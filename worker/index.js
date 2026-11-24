import { DASHBOARD_CLIENT_JS } from './dashboard-client.js';
import { dashboardStyles, themeScript } from './dashboard-style.js';

var VERSION = '3.38.0'; // bump when you change the worker code

/**
 * pageview-logger — Cloudflare Worker analytics dashboard
 * =======================================================
 *
 * Purpose: Record page views and selected site activity for a personal profile
 * (shoaibsprojects.github.io/shoaibAktharProBio) with a private analytics dashboard.
 *
 * ARCHITECTURE
 * ────────────
 * │ Profile Page │ ──beacon──► │ Worker │ ──write──► │ D1 Database │
 * │ (index.html)  │   (fetch)    │ (JS)   │  (SQL)     │ (SQLite)    │
 * │               │ ◄──cookie── │        │             │             │
 *
 * DATA MODEL
 * ──────────
 *   page_views      — one row per page load (immutable once written)
 *   page_engagement — one row per heartbeat/click/hide event
 *   visitor_identity_links — reversible grouping, raw visitor IDs remain intact
 *   visitor_identity_events — audit trail of manual links/separations
 *   visitor_visit_overrides — per-visit corrections for destructive legacy merges
 *   visitor_visit_events — audit trail for historical visit corrections
 *   rate_limits     — atomic UPSERT per (ip, scope, bucket)
 *   sessions        — JTI-based server-side session revocation
 *
 * VISITOR IDENTITY (3-tier)
 * ─────────────────────────
 *   Tier 1 — Cookie (vid2): 1yr, SameSite=None, HttpOnly. Same browser = same device.
 *   Tier 2 — Fingerprint: SHA-256(normalizedUA | lang | ISP | country) → fp-{12hex}.
 *            ISP+country keeps strangers with identical Android UA separated.
 *   Tier 3 — Manual reversible links via dashboard Identity studio.
 *
 * SECURITY MODEL
 * ──────────────
 *   • Anonymous telemetry: exact Origin/CORS allowlist, public client marker,
 *     bounded validation, and per-IP edge/D1 rate limits (not authentication)
 *   • Session auth: HMAC-SHA-256 tokens, server-side JTI stored in D1
 *   • Rate limits: Atomic UPSERT per IP, no race-window
 *   • Bot blocking: 34 patterns filtered before DB write
 *   • CSRF: Identity mutations require same-origin request metadata
 *   • Key comparison: timingSafeEqual (SHA-256) — no timing side-channel
 *   • XSS: All user data rendered via esc()/escH()
 *   • Login: Cloudflare Turnstile challenge + brute-force rate limit
 *
 * ENDPOINTS
 * ─────────
 *   /log-visit         POST  — Page view beacon (CORS, origin+key auth)
 *   /event             POST  — Engagement event (heartbeat/click/pagehide)
 *   /dashboard         GET   — Responsive dashboard HTML (session auth)
 *                      POST  — Login (Turnstile + key auth)
 *   /stats             GET   — Dashboard data as JSON (session auth)
 *   /health            GET   — Public health check (no auth)
 *   /meta              GET   — Worker metadata (session auth)
 *   /api/merge-visitors POST — Link two visitor profiles (session+CSRF auth)
 *   /api/unmerge-visitor POST — Separate one original visitor ID
 *   /api/profile-visits GET — Review a profile's underlying visits
 *   /api/move-visit POST — Move one historical visit into another profile
 *   /api/restore-visit POST — Undo a per-visit correction
 *   /api/reset-engagement POST — Delete all engagement rows
 *   /api/delete        POST  — Delete selected visits / profiles / clicks / everything
 *   /logout            POST  — Revoke session (clears cookie + D1 jti)
 *
 * SCHEDULED JOBS (cron: 0 3 * * * — daily at 3 AM UTC)
 * ─────────────────────────────────────────────────────
 *   • Purge expired rate_limit buckets (older than 2 days)
 *   • Purge expired sessions
 *   • (Optional) Data retention: purge old page_views and engagement rows
 *     when RETAIN_DAYS env var is set
 *
 * FREE-TIER LIMITS (Cloudflare Workers Free Plan)
 * ────────────────────────────────────────────────
 *   100k requests/day, 10ms CPU per request
 *   D1: 5GB storage, 5M rows read/day, 100k rows written/day
 *   Free-plan caps reject excess requests and D1 operations; account plan is set in Cloudflare.
 *   Workers Logs includes 200k events/day on the Free plan.
 *
 * @module pageview-logger
 * @author Shoaib Akthar
 * @version 3.38.0
 */

export default {
  async fetch(request, env, ctx) {
    const start = Date.now();
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      let response;

      if (path === '/log-visit') {
        response = await handleLogVisit(request, env);
      } else if (path === '/dashboard') {
        response = await handleDashboard(request, env);
      } else if (path === '/logout') {
        response = await handleLogout(request, env);
      } else if (path === '/stats') {
        response = await handleStats(request, env);
      } else if (path === '/health') {
        response = handleHealth(request, env);
      } else if (path === '/event') {
        response = await handleEvent(request, env);
      } else if (path === '/api/merge-visitors') {
        response = await handleMergeVisitors(request, env);
      } else if (path === '/api/unmerge-visitor') {
        response = await handleUnmergeVisitor(request, env);
      } else if (path === '/api/profile-visits') {
        response = await handleProfileVisits(request, env);
      } else if (path === '/api/move-visit') {
        response = await handleMoveVisit(request, env);
      } else if (path === '/api/restore-visit') {
        response = await handleRestoreVisit(request, env);
      } else if (path === '/api/reset-engagement') {
        response = await handleResetEngagement(request, env);
      } else if (path === '/api/delete') {
        response = await handleDelete(request, env);
      } else if (path === '/meta') {
        response = await handleMeta(request, env);
      } else {
        response = new Response('Not Found', { status: 404, headers: securityHeaders() });
      }

      const elapsed = Date.now() - start;
      response.headers.set('X-Response-Time', elapsed + 'ms');

      // Structured log — one JSON line per request
      console.log(JSON.stringify({
        l: path,
        s: response.status,
        ms: elapsed,
      }));
      return response;

    } catch (err) {
      const elapsed = Date.now() - start;
      console.error(JSON.stringify({
        l: path,
        error: err instanceof Error ? err.message : String(err),
        ms: elapsed,
      }));
      return new Response('Internal Server Error', { status: 500, headers: securityHeaders() });
    }
  },

  // Daily maintenance: purge expired rate-limit buckets, expired sessions,
  // and optionally old page_views / engagement rows (configurable via RETAIN_DAYS env var).
  async scheduled(event, env) {
    const cutoff = Math.floor(Date.now() / 1000);
    const ops = [
      env.DB.prepare('DELETE FROM rate_limits WHERE bucket < ?').bind(cutoff - 2 * 86400).run(),
      env.DB.prepare('DELETE FROM sessions WHERE exp < ?').bind(cutoff).run(),
    ];

    // Data retention: if RETAIN_DAYS is set, purge old records to stay within
    // D1 free-tier limits. Default: off (no auto-deletion). Recommended: 90 for
    // page_views, 30 for engagement.
    const retainDays = parseInt(env.RETAIN_DAYS, 10) || 0;
    if (retainDays > 0) {
      const viewCutoff = new Date(Date.now() - retainDays * 86400000).toISOString().slice(0, 19).replace('T', ' ');
      ops.push(
        env.DB.prepare('DELETE FROM page_views WHERE created_at < ?').bind(viewCutoff).run(),
        env.DB.prepare('DELETE FROM page_engagement WHERE created_at < ?').bind(viewCutoff).run()
      );
    }

    const results = await Promise.all(ops);
    const counts = results.map(r => (r && r.changes) || 0);
    console.log(JSON.stringify({
      event: 'scheduled',
      rate_limits: counts[0] || 0,
      sessions: counts[1] || 0,
      views: counts[2] || 0,
      engagement: counts[3] || 0,
      retainDays: retainDays || 'off',
    }));
  },
};

// ── Security headers applied to every response ──
function securityHeaders(extra = {}) {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; img-src 'self' data: https:; connect-src 'self' https://challenges.cloudflare.com",
    ...extra,
  };
}

// ── Cross-origin allowlist (only known sites may call the logger) ──
const DEFAULT_ORIGINS = 'https://shoaibsprojects.github.io,https://shoaibakthar.pro,http://localhost';

function originAllowed(origin, env) {
  if (!origin) return true; // non-browser client (curl etc.) — validated by key later
  const list = (env.ALLOWED_ORIGINS || DEFAULT_ORIGINS).split(',').map(s => s.trim()).filter(Boolean);
  return list.includes(origin);
}

// ── D1-backed rate limiter (atomic UPSERT — no race window) ──
// One row per (ip, scope, bucket). Bucket = window start in unix seconds.
async function checkRateLimit(db, ip, scope, windowSec, max) {
  const now = Math.floor(Date.now() / 1000);
  const bucket = Math.floor(now / windowSec) * windowSec;
  const res = await db.prepare(
    `INSERT INTO rate_limits (ip, scope, bucket, count)
     VALUES (?, ?, ?, 1)
     ON CONFLICT (ip, scope, bucket) DO UPDATE SET count = count + 1
     RETURNING count`
  ).bind(ip, scope, bucket).first();
  return (res && res.count) <= max;
}

// ── Constant-time comparison (defeats timing side-channel on the key) ──
async function constantTimeEqual(a, b) {
  const enc = new TextEncoder();
  const [da, db] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(a)),
    crypto.subtle.digest('SHA-256', enc.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(da, db);
}

// ── Referrer sanitization: only real http(s) URLs are stored/rendered ──
function sanitizeReferrer(ref) {
  if (!ref) return null;
  try {
    const u = new URL(ref);
    if (u.protocol === 'http:' || u.protocol === 'https:') return ref;
  } catch (_) { /* not a URL */ }
  return null;
}

// ── Bot / crawler detection (UA heuristics; Cloudflare's own bot mgmt is enterprise-only) ──
const BOT_PATTERNS = [
  /bot\b/i, /crawl/i, /spider/i, /slurp/i, /baiduspider/i, /yandex/i, /bingbot/i,
  /googlebot/i, /duckduckgo/i, /petalbot/i, /bytespider/i, /applebot/i, /gptbot/i,
  /facebookexternalhit/i, /linkedinbot/i, /twitterbot/i, /whatsapp/i, /telegrambot/i,
  /curl/i, /wget/i, /python/i, /go-http-client/i, /node-fetch/i, /axios/i,
  /postman/i, /httpclient/i, /okhttp/i, /headless/i, /phantomjs/i, /scrapy/i,
  /puppeteer/i, /playwright/i, /semrush/i, /ahrefs/i, /mj12bot/i, /dotbot/i,
  /gtmetrix/i, /pingdom/i, /uptimerobot/i, /lighthouse/i, /pagespeed/i, /headlesschrome/i,
  /google-read-aloud/i, /google-lighthouse/i, /chrome-lighthouse/i,
];

function isBot(ua) {
  if (!ua) return false;
  return BOT_PATTERNS.some(p => p.test(ua));
}

// ── Session token helpers ──
// Token is an HMAC-signed payload { jti, exp }. The jti is stored in D1 so
// logout can revoke it server-side before expiry.
async function createSessionToken(env) {
  const jti = crypto.randomUUID();
  const exp = Math.floor(Date.now() / 1000) + 3600; // 1 hour
  await env.DB.prepare('INSERT INTO sessions (jti, exp) VALUES (?, ?)')
    .bind(jti, exp).run();
  const payload = JSON.stringify({ exp, jti });
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(env.DASHBOARD_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  return btoa(JSON.stringify({ p: payload, s: Array.from(new Uint8Array(sig)).map(b => String.fromCharCode(b)).join('') }));
}

async function verifySessionToken(token, env) {
  try {
    const raw = JSON.parse(atob(token));
    const { p, s } = raw;
    const payload = JSON.parse(p);
    if (payload.exp < Math.floor(Date.now() / 1000)) return false;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(env.DASHBOARD_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sig = new Uint8Array(s.split('').map(c => c.charCodeAt(0)));
    const ok = await crypto.subtle.verify('HMAC', key, sig, enc.encode(p));
    if (!ok) return false;
    // Server-side check: the jti must still exist (logout revokes it).
    const row = await env.DB.prepare('SELECT exp FROM sessions WHERE jti = ?')
      .bind(payload.jti).first();
    return !!(row && row.exp === payload.exp);
  } catch (_) {
    return false;
  }
}

// Read the __Host-session cookie value (null if absent).
function sessionTokenFrom(cookie) {
  const m = cookie.match(/__Host-session=([^;]+)/);
  return m ? m[1] : null;
}

// Decode a token's jti (used by logout to revoke). Returns null on any error.
function sessionJti(token) {
  try {
    const raw = JSON.parse(atob(token));
    return JSON.parse(raw.p).jti || null;
  } catch (_) {
    return null;
  }
}

// ── POST /log-visit ──
async function handleLogVisit(request, env) {
  const base = securityHeaders({ 'Vary': 'Origin' });
  const origin = request.headers.get('Origin');
  // Require a valid Origin: browsers always send one on cross-origin POSTs.
  // This stops raw clients from logging fake views even with the public key.
  if (!origin || !originAllowed(origin, env)) {
    return new Response('Forbidden', { status: 403, headers: securityHeaders() });
  }
  base['Access-Control-Allow-Origin'] = origin;
  base['Access-Control-Allow-Methods'] = 'POST, OPTIONS';
  base['Access-Control-Allow-Headers'] = 'Content-Type';
  base['Access-Control-Allow-Credentials'] = 'true';

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: base });
  }

  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405, headers: base });
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  // 1) Block known bots/crawlers before they cost any DB writes
  const ua = request.headers.get('User-Agent') || '';
  if (isBot(ua)) {
    console.log(JSON.stringify({ event: 'bot_blocked' }));
    return Response.json({ ok: false, reason: 'bot' }, { status: 403, headers: base });
  }

  // 2) Hard cap on accepted visits per day (protects D1 write budget across all IPs)
  const withinBudget = await checkRateLimit(env.DB, ip, 'daily-budget', 86400, 5000);
  if (!withinBudget) {
    return Response.json({ ok: false, reason: 'budget' }, { status: 429, headers: base });
  }

  // 3) Per-IP rate limit: max 5 log attempts per 60s
  const allowed = await checkRateLimit(env.DB, ip, 'log-visit', 60, 5);
  if (!allowed) {
    return Response.json({ ok: false, reason: 'rate_limited' }, { status: 429, headers: base });
  }

  // 4) Cap payload size (beacon should be tiny)
  const contentLength = Number(request.headers.get('Content-Length') || 0);
  if (contentLength > 4096) {
    return Response.json({ ok: false, reason: 'payload_too_large' }, { status: 413, headers: base });
  }

  let body = {};
  try {
    body = await request.json();
  } catch (_) {
    return Response.json({ ok: false, reason: 'bad_json' }, { status: 400, headers: base });
  }

  // 5) This browser-visible marker filters accidental/unscripted writes; it is
  // not a secret or an authentication boundary.
  if (!body.key || !(await constantTimeEqual(String(body.key), env.LOG_KEY))) {
    return Response.json({ ok: false, reason: 'unauthorized' }, { status: 401, headers: base });
  }

  // 6) Validate pageUrl to stop junk data
  const allowedHosts = ['shoaibsprojects.github.io', 'shoaibakthar.pro', 'localhost'];
  const pageUrl = body.pageUrl || null;
  if (pageUrl) {
    let ok = false;
    try {
      const u = new URL(pageUrl);
      ok = allowedHosts.includes(u.hostname);
    } catch (_) { ok = false; }
    if (!ok) {
      return Response.json({ ok: false, reason: 'invalid_page_url' }, { status: 400, headers: base });
    }
  }

  const cf = request.cf || {};
  const latitude = geoCoordinate(cf.latitude, -90, 90);
  const longitude = geoCoordinate(cf.longitude, -180, 180);
  const language = (request.headers.get('Accept-Language') || '').split(',')[0]?.trim() || null;
  const uaParsed = parseUADetailed(ua);
  let { id: visitorId, fromCookie } = await getVisitorId(request, ua, language, cf);
  // Modern browsers (Chrome/Safari) block the cross-site Set-Cookie we issue here, so
  // the page also persists the id it gets from this response in localStorage on the
  // profile origin and echoes it back on every call. Prefer that id when the cookie
  // wasn't delivered, so page views + engagement collapse onto one stable visitor.
  const bodyVid = String(body.visitor_id || '');
  if (!fromCookie && (UUID_RE.test(bodyVid) || FP_RE.test(bodyVid))) {
    visitorId = bodyVid;
  }

  // Hash the IP (SHA-256, first 12 hex chars) — privacy-preserving same-device signal.
  // If two visits share the same IP hash, they came from the same subnet/household.
  const ipHash = await sha256Hex(ip);
  const colo = cf.colo || null;

  const stmt = env.DB.prepare(
    `INSERT INTO page_views (country, city, region, timezone, user_agent, referrer, page_url, visitor_id,
     device_type, os, browser, latitude, longitude, postal_code, isp, language, ip_hash, colo)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  await stmt.bind(
    cf.country || null,
    cf.city || null,
    cf.region || null,
    cf.timezone || null,
    ua || null,
    sanitizeReferrer(body.referrer || request.headers.get('Referer')) || null,
    pageUrl,
    visitorId,
    uaParsed.device,
    uaParsed.os,
    uaParsed.browser,
    latitude === null ? null : String(latitude),
    longitude === null ? null : String(longitude),
    cf.postalCode || null,
    cf.asOrganization || null,
    language,
    ipHash.slice(0, 16),
    colo
  ).run();

  console.log(JSON.stringify({ event: 'visit', known: fromCookie }));

  const response = Response.json({ ok: true, visitor_id: visitorId }, { headers: base });

  // Always (re)issue the cookie so it survives cross-origin (Site=other, SameSite=None)
  // and persists for a year. Echo back the SAME id we just stored so future visits
  // from this browser collapse onto this row regardless of IP/network changes.
  // Partitioned (CHIPS) keeps the cookie usable inside the profile page's third-party
  // context even under Chrome/Safari's cross-site cookie blocking.
  response.headers.set(
    'Set-Cookie',
    `${VID_COOKIE}=${visitorId}; Max-Age=31536000; Path=/; SameSite=None; Secure; HttpOnly; Partitioned`
  );

  return response;
}

function eventText(value, max) {
  return typeof value === 'string' ? value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max) : '';
}

function geoCoordinate(value, min, max) {
  if (value === null || value === undefined || String(value).trim() === '') return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= min && number <= max ? number : null;
}

function eventInteger(value, min, max) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isInteger(number) && number >= min && number <= max ? number : null;
}

function eventPageUrl(value, origin) {
  try {
    const url = new URL(value);
    return (url.protocol === 'https:' || url.protocol === 'http:') && url.origin === origin
      ? (url.origin + url.pathname).slice(0, 300) : null;
  } catch (_) { return null; }
}

function eventDestination(value, origin, named) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    const hash = /^#[a-zA-Z0-9_-]{1,64}$/.test(url.hash) ? url.hash : '';
    return (url.origin === origin ? url.origin + url.pathname + hash
      : named ? url.origin + url.pathname : url.origin).slice(0, 200);
  } catch (_) { return null; }
}

// ── POST /event (heartbeat, click, visibility, beforeunload) ──
async function handleEvent(request, env) {
  const base = securityHeaders({ 'Vary': 'Origin' });
  const origin = request.headers.get('Origin');
  if (!origin || !originAllowed(origin, env)) {
    return new Response('Forbidden', { status: 403, headers: securityHeaders() });
  }
  base['Access-Control-Allow-Origin'] = origin;
  base['Access-Control-Allow-Methods'] = 'POST, OPTIONS';
  base['Access-Control-Allow-Headers'] = 'Content-Type';
  base['Access-Control-Allow-Credentials'] = 'true';

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: base });
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405, headers: base });

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  // Bots skip engagement entirely
  const ua = request.headers.get('User-Agent') || '';
  if (isBot(ua)) return Response.json({ ok: false, reason: 'bot' }, { status: 403, headers: base });

  // Enforce an edge-local ceiling before touching D1. The D1 limiter below is
  // still the shared secondary guard, but every D1-backed rate-limit check is
  // itself a write and cannot protect the database from a sustained flood.
  let edgeLimit;
  try {
    if (!env.EVENT_INGEST_LIMITER) throw new Error('event limiter binding is missing');
    edgeLimit = await env.EVENT_INGEST_LIMITER.limit({ key: ip });
  } catch (_) {
    return Response.json({ ok: false, reason: 'rate_limit_unavailable' }, { status: 503, headers: base });
  }
  if (!edgeLimit.success) {
    return Response.json({ ok: false, reason: 'rate_limited' }, { status: 429, headers: base });
  }

  // Shared D1 secondary limit: max 60 events/minute/IP across Worker locations.
  const allowed = await checkRateLimit(env.DB, ip, 'events', 60, 60);
  if (!allowed) return Response.json({ ok: false, reason: 'rate_limited' }, { status: 429, headers: base });

  // Payload must be tiny — reject oversized
  const contentLength = Number(request.headers.get('Content-Length') || 0);
  if (contentLength > 2048) return Response.json({ ok: false, reason: 'payload_too_large' }, { status: 413, headers: base });

  let body = {};
  try { body = await request.json(); } catch (_) {
    return Response.json({ ok: false, reason: 'bad_json' }, { status: 400, headers: base });
  }

  // Same public client marker as /log-visit; event ingestion is anonymous.
  if (!body.key || !(await constantTimeEqual(String(body.key), env.LOG_KEY))) {
    return Response.json({ ok: false, reason: 'unauthorized' }, { status: 401, headers: base });
  }

  // Identity comes from the cookie (validated by regex) — same fence as /log-visit.
  // The cross-site cookie is often blocked (Chrome/Safari), so fall back to the id the
  // page client persisted in localStorage and sent in the payload.
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp(VID_COOKIE + '=([^;]+)'));
  let vid = match ? match[1] : '';
  const bodyVid = String(body.visitor_id || '');
  if (!(UUID_RE.test(vid) || FP_RE.test(vid))) {
    vid = (UUID_RE.test(bodyVid) || FP_RE.test(bodyVid)) ? bodyVid : '';
  }
  if (!vid) {
    return Response.json({ ok: false, reason: 'no_session' }, { status: 403, headers: base });
  }

  const session_id = String(body.session_id || '');
  const event_type = String(body.event_type || '');

  // Whitelist accepted event types — reject anything else (prevents schema abuse)
  const allowedEvents = new Set(['heartbeat', 'click', 'pagehide', 'pageshow', 'focus']);
  if (!allowedEvents.has(event_type)) {
    return Response.json({ ok: false, reason: 'bad_event_type' }, { status: 400, headers: base });
  }

  if (event_type === 'click') {
    const source = ['site', 'site-widget', 'outside'].includes(body.source) ? body.source : null;
    const rawActionId = eventText(body.action_id, 64);
    const actionId = source !== 'outside' && /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/.test(rawActionId) ? rawActionId : null;
    let labelQuality = source && ['named', 'inferred', 'unknown'].includes(body.label_quality) ? body.label_quality : null;
    if (labelQuality === 'named' && !actionId) labelQuality = 'inferred';
    if (source === 'outside') labelQuality = 'unknown';
    const viewportW = eventInteger(body.viewport_w, 1, 16384);
    const viewportH = eventInteger(body.viewport_h, 1, 16384);
    const interaction = ['pointer', 'non-pointer'].includes(body.interaction) ? body.interaction : null;
    const x = interaction === 'non-pointer' ? null : eventInteger(body.x, 0, 16384);
    const y = interaction === 'non-pointer' ? null : eventInteger(body.y, 0, 16384);
    const target = source === 'outside' ? 'Unidentified element outside site content'
      : labelQuality === 'unknown' ? 'Page area (not a control)' : eventText(body.target, 100) || null;
    const extra = eventText(body.extra, 200) || null;
    const section = source === 'outside' ? 'Outside site content' : eventText(body.section, 80) || null;
    const cls = source ? null : eventText(body.cls, 80) || null;
    const href = source === 'outside' ? null : eventDestination(body.href, origin, labelQuality === 'named');
    await env.DB.prepare(
      `INSERT INTO page_engagement (visitor_id, session_id, event_type, page_url, x, y, target, extra, section, cls, href, action_id, label_quality, source, interaction, viewport_w, viewport_h)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(vid, session_id || null, event_type, eventPageUrl(body.pageUrl, origin), x, y, target, extra, section, cls, href, actionId, labelQuality, source, interaction, viewportW, viewportH).run();
  } else {
    // heartbeat / pagehide / pageshow / focus — no x/y
    await env.DB.prepare(
      `INSERT INTO page_engagement (visitor_id, session_id, event_type, page_url)
       VALUES (?, ?, ?, ?)`
    ).bind(vid, session_id || null, event_type, eventPageUrl(body.pageUrl, origin)).run();
  }

  return Response.json({ ok: true }, { headers: base });
}

function sameOriginMutation(request) {
  const origin = request.headers.get('Origin');
  const referer = request.headers.get('Referer');
  const site = request.headers.get('Sec-Fetch-Site');
  const expected = new URL(request.url).origin;
  if (origin) return origin === expected;
  if (site !== 'same-origin' || !referer) return false;
  try { return new URL(referer).origin === expected; } catch (_) { return false; }
}

async function identityMutationRequest(request, env) {
  const h = securityHeaders({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  if (request.method !== 'POST') return { response: Response.json({ error: 'method_not_allowed' }, { status: 405, headers: h }) };
  if (!sameOriginMutation(request)) return { response: Response.json({ error: 'forbidden' }, { status: 403, headers: h }) };
  const session = sessionTokenFrom(request.headers.get('Cookie') || '');
  if (!session || !(await verifySessionToken(session, env))) {
    return { response: Response.json({ error: 'unauthorized' }, { status: 401, headers: h }) };
  }
  let body = {};
  try { body = await request.json(); } catch (_) { return { response: Response.json({ error: 'bad_json' }, { status: 400, headers: h }) }; }
  return { body, headers: h };
}

function validVisitorId(id) { return UUID_RE.test(id) || FP_RE.test(id); }

async function handleMergeVisitors(request, env) {
  const mutation = await identityMutationRequest(request, env);
  if (mutation.response) return mutation.response;
  const { body, headers: h } = mutation;
  const source = String(body.source || '');
  const target = String(body.target || '');
  if (!source || !target || source === target) {
    return Response.json({ error: 'bad_params' }, { status: 400, headers: h });
  }
  if (!validVisitorId(source) || !validVisitorId(target)) {
    return Response.json({ error: 'bad_visitor_id' }, { status: 400, headers: h });
  }
  const [srcExists, tgtExists, srcLink, tgtLink, members] = await Promise.all([
    profileExists(env.DB, source),
    profileExists(env.DB, target),
    env.DB.prepare('SELECT canonical_id FROM visitor_identity_links WHERE visitor_id = ?').bind(source).first(),
    env.DB.prepare('SELECT canonical_id FROM visitor_identity_links WHERE visitor_id = ?').bind(target).first(),
    env.DB.prepare('SELECT visitor_id FROM visitor_identity_links WHERE canonical_id = ? ORDER BY visitor_id LIMIT 100').bind(source).all(),
  ]);
  if (srcLink || tgtLink) return Response.json({ error: 'profile_changed', message: 'Refresh the dashboard and try again.' }, { status: 409, headers: h });
  if (!srcExists && !(members.results || []).length) {
    return Response.json({ error: 'source_not_found' }, { status: 404, headers: h });
  }
  if (!tgtExists) {
    return Response.json({ error: 'target_not_found' }, { status: 404, headers: h });
  }
  if ((members.results || []).length >= 100) return Response.json({ error: 'group_too_large' }, { status: 409, headers: h });
  const affected = [source, ...(members.results || []).map(row => row.visitor_id)];
  const eventId = crypto.randomUUID();
  try {
    await env.DB.batch([
      env.DB.prepare("UPDATE visitor_identity_links SET canonical_id = ?, updated_at = datetime('now') WHERE canonical_id = ?").bind(target, source),
      env.DB.prepare('INSERT INTO visitor_identity_links (visitor_id, canonical_id) VALUES (?, ?)').bind(source, target),
      env.DB.prepare('INSERT INTO visitor_identity_events (id, action, source_id, target_id, affected_ids) VALUES (?, ?, ?, ?, ?)').bind(eventId, 'merge', source, target, JSON.stringify(affected)),
    ]);
  } catch (err) {
    if (/target_not_canonical|UNIQUE constraint/i.test(String(err))) return Response.json({ error: 'profile_changed', message: 'Another identity change was saved. Refresh and try again.' }, { status: 409, headers: h });
    throw err;
  }
  console.log(JSON.stringify({ event: 'visitors_linked', eventId, count: affected.length }));
  return Response.json({ ok: true, source, target, linked: affected.length, eventId }, { headers: h });
}

async function handleUnmergeVisitor(request, env) {
  const mutation = await identityMutationRequest(request, env);
  if (mutation.response) return mutation.response;
  const { body, headers: h } = mutation;
  const visitorId = String(body.visitorId || '');
  const canonicalId = String(body.canonicalId || '');
  if (!validVisitorId(visitorId) || !validVisitorId(canonicalId) || visitorId === canonicalId) {
    return Response.json({ error: 'bad_params' }, { status: 400, headers: h });
  }
  const link = await env.DB.prepare('SELECT canonical_id FROM visitor_identity_links WHERE visitor_id = ?').bind(visitorId).first();
  if (!link || link.canonical_id !== canonicalId) return Response.json({ error: 'profile_changed', message: 'Refresh the dashboard and try again.' }, { status: 409, headers: h });
  const eventId = crypto.randomUUID();
  const results = await env.DB.batch([
    env.DB.prepare('DELETE FROM visitor_identity_links WHERE visitor_id = ? AND canonical_id = ?').bind(visitorId, canonicalId),
    env.DB.prepare("INSERT INTO visitor_identity_events (id, action, source_id, target_id, affected_ids) SELECT ?, ?, ?, ?, ? WHERE changes() > 0").bind(eventId, 'separate', visitorId, canonicalId, JSON.stringify([visitorId])),
  ]);
  if (!results[0]?.meta?.changes) return Response.json({ error: 'profile_changed' }, { status: 409, headers: h });
  console.log(JSON.stringify({ event: 'visitor_separated', eventId }));
  return Response.json({ ok: true, visitorId, canonicalId, eventId }, { headers: h });
}

async function handleProfileVisits(request, env) {
  const h = securityHeaders({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  if (request.method !== 'GET') return Response.json({ error: 'method_not_allowed' }, { status: 405, headers: h });
  const session = sessionTokenFrom(request.headers.get('Cookie') || '');
  if (!session || !(await verifySessionToken(session, env))) return Response.json({ error: 'unauthorized' }, { status: 401, headers: h });
  const profile = new URL(request.url).searchParams.get('profile') || '';
  if (!validVisitorId(profile)) return Response.json({ error: 'bad_profile_id' }, { status: 400, headers: h });
  const { results } = await env.DB.prepare(
    `SELECT v.id, v.created_at, v.visitor_id AS original_id, ov.profile_id AS override_id,
            v.city, v.region, v.country, v.device_type, v.os, v.browser, v.user_agent, v.isp,
            substr(v.ip_hash, 1, 8) AS network_signal
     FROM page_views v
     LEFT JOIN visitor_visit_overrides ov ON ov.page_view_id = v.id
     LEFT JOIN visitor_identity_links il ON il.visitor_id = COALESCE(ov.profile_id, v.visitor_id)
     WHERE COALESCE(il.canonical_id, ov.profile_id, v.visitor_id) = ?
     ORDER BY v.created_at DESC, v.id DESC LIMIT 101`
  ).bind(profile).all();
  return Response.json({ profile, visits: (results || []).slice(0, 100).map(row => {
    const parsed = row.user_agent ? parseUADetailed(row.user_agent) : null;
    const { user_agent, ...visit } = row;
    return { ...visit, os: parsed?.os || row.os, browser: parsed?.browser || row.browser, device_type: parsed?.device || row.device_type };
  }), hasMore: (results || []).length > 100 }, { headers: h });
}

async function currentVisitIdentity(db, viewId) {
  return db.prepare(
    `SELECT v.visitor_id AS original_id, ov.profile_id AS override_id,
            COALESCE(il.canonical_id, ov.profile_id, v.visitor_id) AS profile_id
     FROM page_views v
     LEFT JOIN visitor_visit_overrides ov ON ov.page_view_id = v.id
     LEFT JOIN visitor_identity_links il ON il.visitor_id = COALESCE(ov.profile_id, v.visitor_id)
     WHERE v.id = ?`
  ).bind(viewId).first();
}

async function profileExists(db, profileId) {
  const row = await db.prepare(
    `SELECT 1 AS found FROM page_views v
     LEFT JOIN visitor_visit_overrides ov ON ov.page_view_id = v.id
     LEFT JOIN visitor_identity_links il ON il.visitor_id = COALESCE(ov.profile_id, v.visitor_id)
     WHERE COALESCE(il.canonical_id, ov.profile_id, v.visitor_id) = ? LIMIT 1`
  ).bind(profileId).first();
  return !!row;
}

async function handleMoveVisit(request, env) {
  const mutation = await identityMutationRequest(request, env);
  if (mutation.response) return mutation.response;
  const { body, headers: h } = mutation;
  const viewId = Number(body.viewId);
  const fromProfile = String(body.fromProfile || '');
  const requestedTarget = String(body.targetProfile || '');
  if (!Number.isSafeInteger(viewId) || viewId < 1 || !validVisitorId(fromProfile) ||
      !(requestedTarget === 'new' || validVisitorId(requestedTarget))) {
    return Response.json({ error: 'bad_params' }, { status: 400, headers: h });
  }
  const visit = await currentVisitIdentity(env.DB, viewId);
  if (!visit || visit.profile_id !== fromProfile || visit.override_id) {
    return Response.json({ error: 'visit_changed', message: 'This visit changed. Refresh its details and try again.' }, { status: 409, headers: h });
  }
  const targetProfile = requestedTarget === 'new' ? crypto.randomUUID() : requestedTarget;
  if (targetProfile === fromProfile || (requestedTarget !== 'new' && !(await profileExists(env.DB, targetProfile)))) {
    return Response.json({ error: 'bad_target' }, { status: 400, headers: h });
  }
  const eventId = crypto.randomUUID();
  const results = await env.DB.batch([
    env.DB.prepare(
      'INSERT INTO visitor_visit_overrides (page_view_id, profile_id) SELECT id, ? FROM page_views WHERE id = ? AND visitor_id = ? AND NOT EXISTS (SELECT 1 FROM visitor_visit_overrides WHERE page_view_id = ?)'
    ).bind(targetProfile, viewId, visit.original_id, viewId),
    env.DB.prepare(
      "INSERT INTO visitor_visit_events (id, action, page_view_id, original_id, profile_id) SELECT ?, 'move', ?, ?, ? WHERE changes() > 0"
    ).bind(eventId, viewId, visit.original_id, targetProfile),
  ]);
  if (!results[0]?.meta?.changes) return Response.json({ error: 'visit_changed' }, { status: 409, headers: h });
  return Response.json({ ok: true, viewId, profileId: targetProfile, eventId }, { headers: h });
}

async function handleRestoreVisit(request, env) {
  const mutation = await identityMutationRequest(request, env);
  if (mutation.response) return mutation.response;
  const { body, headers: h } = mutation;
  const viewId = Number(body.viewId);
  const expectedProfile = String(body.profileId || '');
  if (!Number.isSafeInteger(viewId) || viewId < 1 || !validVisitorId(expectedProfile)) {
    return Response.json({ error: 'bad_params' }, { status: 400, headers: h });
  }
  const visit = await currentVisitIdentity(env.DB, viewId);
  if (!visit || !visit.override_id || visit.profile_id !== expectedProfile) {
    return Response.json({ error: 'visit_changed', message: 'This visit changed. Refresh its details and try again.' }, { status: 409, headers: h });
  }
  const eventId = crypto.randomUUID();
  const results = await env.DB.batch([
    env.DB.prepare('DELETE FROM visitor_visit_overrides WHERE page_view_id = ? AND profile_id = ?').bind(viewId, visit.override_id),
    env.DB.prepare(
      "INSERT INTO visitor_visit_events (id, action, page_view_id, original_id, profile_id) SELECT ?, 'restore', ?, ?, ? WHERE changes() > 0"
    ).bind(eventId, viewId, visit.original_id, visit.override_id),
  ]);
  if (!results[0]?.meta?.changes) return Response.json({ error: 'visit_changed' }, { status: 409, headers: h });
  return Response.json({ ok: true, viewId, eventId }, { headers: h });
}

// Reset all engagement data (clicks, heartbeats, pagehides, sessions). Session-authenticated.
async function handleResetEngagement(request, env) {
  const mutation = await identityMutationRequest(request, env);
  if (mutation.response) return mutation.response;
  const h = mutation.headers;

  const r = await env.DB.prepare('DELETE FROM page_engagement').run();
  const deleted = (r && r.changes) || 0;
  console.log(JSON.stringify({ event: 'engagement_reset', deleted }));
  return Response.json({ ok: true, deleted }, { headers: h });
}

// ── POST /api/delete (session + same-origin; atomic via D1 batch) ──
// Deletion scopes:
//   visitor        ids=[profile ids]     → every visit, click and identity row for those profiles
//   visit          ids=[page_view ids]   → those visits (+ engagement inside each visit's window)
//   engagement     ids=[engagement ids]  → those click/heartbeat rows
//   all_visits                           → all visits + identity corrections (keeps engagement)
//   all_engagement                       → all engagement rows (keeps visits)
//   all                                  → everything above
// Each mutation is logged with per-table row counts for auditing.
async function handleDelete(request, env) {
  const mutation = await identityMutationRequest(request, env);
  if (mutation.response) return mutation.response;
  const { body, headers: h } = mutation;

  // Destructive operations are rate-limited per IP (20 / minute) as a safety net.
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const allowed = await checkRateLimit(env.DB, ip, 'delete', 60, 20);
  if (!allowed) return Response.json({ error: 'rate_limited' }, { status: 429, headers: h });

  const scope = String(body.scope || '');
  const db = env.DB;

  try {
    if (scope === 'all' || scope === 'all_visits' || scope === 'all_engagement') {
      const ops = [];
      if (scope !== 'all_engagement') {
        // Identity corrections are derived from visits, so they clear alongside them.
        ops.push(
          ['visitor_visit_events', db.prepare('DELETE FROM visitor_visit_events')],
          ['visitor_visit_overrides', db.prepare('DELETE FROM visitor_visit_overrides')],
          ['visitor_identity_events', db.prepare('DELETE FROM visitor_identity_events')],
          ['visitor_identity_links', db.prepare('DELETE FROM visitor_identity_links')],
          ['page_views', db.prepare('DELETE FROM page_views')],
        );
      }
      if (scope !== 'all_visits') {
        ops.push(['page_engagement', db.prepare('DELETE FROM page_engagement')]);
      }
      const results = await db.batch(ops.map(o => o[1]));
      const deleted = {};
      ops.forEach((o, i) => { deleted[o[0]] = chg(results[i]); });
      console.log(JSON.stringify({ event: 'data_deleted', scope, deleted }));
      return Response.json({ ok: true, scope, deleted }, { headers: h });
    }

    if (scope === 'visitor') {
      const ids = dedupeIds(body.ids).filter(validVisitorId).slice(0, 50);
      if (!ids.length) return Response.json({ error: 'bad_ids' }, { status: 400, headers: h });

      // Resolve each profile's raw member IDs and page_view IDs. Identity links and
      // per-visit overrides can move visits under a canonical profile, so a profile
      // delete must reach all three: raw visitors, canonical profile, and view IDs.
      const ph = ids.map(() => '?').join(',');
      const [membersRes, linksRes, viewsRes] = await Promise.all([
        db.prepare(
          `SELECT DISTINCT v.visitor_id AS original_id
           FROM page_views v
           LEFT JOIN visitor_visit_overrides ov ON ov.page_view_id = v.id
           LEFT JOIN visitor_identity_links il ON il.visitor_id = COALESCE(ov.profile_id, v.visitor_id)
           WHERE COALESCE(il.canonical_id, ov.profile_id, v.visitor_id) IN (${ph})`
        ).bind(...ids).all(),
        db.prepare(`SELECT visitor_id FROM visitor_identity_links WHERE canonical_id IN (${ph})`).bind(...ids).all(),
        db.prepare(
          `SELECT v.id
           FROM page_views v
           LEFT JOIN visitor_visit_overrides ov ON ov.page_view_id = v.id
           LEFT JOIN visitor_identity_links il ON il.visitor_id = COALESCE(ov.profile_id, v.visitor_id)
           WHERE COALESCE(il.canonical_id, ov.profile_id, v.visitor_id) IN (${ph})`
        ).bind(...ids).all(),
      ]);
      const memberIds = dedupeIds([...ids, ...(linksRes.results || []).map(r => r.visitor_id), ...(membersRes.results || []).map(r => r.original_id)]).slice(0, 500);
      const profileIds = dedupeIds([...ids, ...(linksRes.results || []).map(r => r.visitor_id)]).slice(0, 500);
      const viewIds = dedupeIds((viewsRes.results || []).map(r => r.id)).slice(0, 1000);

      const sets = [['m', memberIds], ['p', profileIds], ['v', viewIds]];
      const ctes = cteValues(sets);
      const bindAll = memberIds.concat(profileIds, viewIds);
      const results = await db.batch([
        db.prepare(`${ctes} DELETE FROM visitor_visit_events WHERE original_id IN (SELECT id FROM m) OR profile_id IN (SELECT id FROM p) OR page_view_id IN (SELECT id FROM v)`).bind(...bindAll),
        db.prepare(`${ctes} DELETE FROM visitor_visit_overrides WHERE profile_id IN (SELECT id FROM p) OR page_view_id IN (SELECT id FROM v)`).bind(...bindAll),
        db.prepare(`${ctes} DELETE FROM visitor_identity_links WHERE visitor_id IN (SELECT id FROM m) OR canonical_id IN (SELECT id FROM p)`).bind(...bindAll),
        db.prepare(`${ctes} DELETE FROM visitor_identity_events WHERE source_id IN (SELECT id FROM p) OR target_id IN (SELECT id FROM p)`).bind(...bindAll),
        db.prepare(`${ctes} DELETE FROM page_engagement WHERE visitor_id IN (SELECT id FROM m)`).bind(...bindAll),
        db.prepare(`${ctes} DELETE FROM page_views WHERE id IN (SELECT id FROM v)`).bind(...bindAll),
      ]);
      const deleted = {
        visit_events: chg(results[0]),
        visit_overrides: chg(results[1]),
        identity_links: chg(results[2]),
        identity_events: chg(results[3]),
        engagement: chg(results[4]),
        page_views: chg(results[5]),
      };
      console.log(JSON.stringify({ event: 'data_deleted', scope, profiles: ids.length, deleted }));
      return Response.json({ ok: true, scope, deleted }, { headers: h });
    }

    if (scope === 'engagement') {
      const ids = dedupeIds(body.ids).map(n => parseInt(n, 10)).filter(n => Number.isInteger(n) && n > 0).slice(0, 200);
      if (!ids.length) return Response.json({ error: 'bad_ids' }, { status: 400, headers: h });
      const ph = ids.map(() => '?').join(',');
      const r = await db.prepare(`DELETE FROM page_engagement WHERE id IN (${ph})`).bind(...ids).run();
      const deleted = { engagement: chg(r) };
      console.log(JSON.stringify({ event: 'data_deleted', scope, deleted }));
      return Response.json({ ok: true, scope, deleted }, { headers: h });
    }

    if (scope === 'visit') {
      const ids = dedupeIds(body.ids).map(n => parseInt(n, 10)).filter(n => Number.isInteger(n) && n > 0).slice(0, 100);
      if (!ids.length) return Response.json({ error: 'bad_ids' }, { status: 400, headers: h });
      const ph = ids.map(() => '?').join(',');
      const { results: rows } = await db.prepare(
        `SELECT id, visitor_id, created_at FROM page_views WHERE id IN (${ph})`
      ).bind(...ids).all();
      if (!rows || !rows.length) {
        return Response.json({ ok: true, scope, deleted: { page_views: 0, engagement: 0 } }, { headers: h });
      }

      // Engagement has no FK to page_views, so attribute each click/heartbeat to the
      // visit it followed: [this visit, next visit) per raw visitor ID. Deleting
      // consecutive visits tiles the windows, removing exactly their engagement.
      const originalIds = [...new Set(rows.map(r => r.visitor_id))];
      const oph = originalIds.map(() => '?').join(',');
      const { results: allVisits } = await db.prepare(
        `SELECT visitor_id, created_at FROM page_views WHERE visitor_id IN (${oph}) ORDER BY visitor_id ASC, created_at ASC`
      ).bind(...originalIds).all();
      const timesByVisitor = {};
      for (const v of (allVisits || [])) (timesByVisitor[v.visitor_id] = timesByVisitor[v.visitor_id] || []).push(v.created_at);
      const windows = [];
      for (const r of rows) {
        const arr = timesByVisitor[r.visitor_id] || [];
        let next = null;
        for (const t of arr) { if (t > r.created_at) { next = t; break; } }
        windows.push({ vid: r.visitor_id, start: r.created_at, end: next || '9999-12-31 23:59:59' });
      }

      const stmts = [
        db.prepare(`DELETE FROM visitor_visit_overrides WHERE page_view_id IN (${ph})`).bind(...ids),
        db.prepare(`DELETE FROM visitor_visit_events WHERE page_view_id IN (${ph})`).bind(...ids),
      ];
      for (let i = 0; i < windows.length; i += 30) {
        const chunk = windows.slice(i, i + 30);
        const clause = chunk.map(() => '(visitor_id = ? AND created_at >= ? AND created_at < ?)').join(' OR ');
        const params = [];
        chunk.forEach(w => params.push(w.vid, w.start, w.end));
        stmts.push(db.prepare(`DELETE FROM page_engagement WHERE ${clause}`).bind(...params));
      }
      stmts.push(db.prepare(`DELETE FROM page_views WHERE id IN (${ph})`).bind(...ids));

      const results = await db.batch(stmts);
      const last = results.length - 1;
      const engagement = results.slice(2, last).reduce((a, r) => a + chg(r), 0);
      const deleted = {
        visit_overrides: chg(results[0]),
        visit_events: chg(results[1]),
        engagement,
        page_views: chg(results[last]),
      };
      console.log(JSON.stringify({ event: 'data_deleted', scope, deleted }));
      return Response.json({ ok: true, scope, deleted }, { headers: h });
    }

    return Response.json({ error: 'bad_scope' }, { status: 400, headers: h });
  } catch (err) {
    console.error(JSON.stringify({ event: 'delete_error', scope, error: err instanceof Error ? err.message : String(err) }));
    return Response.json({ error: 'delete_failed' }, { status: 500, headers: h });
  }
}

function chg(r) { return (r && r.changes) || 0; }

function dedupeIds(arr) {
  return [...new Set((Array.isArray(arr) ? arr : []).map(String).filter(Boolean))];
}

// Build a `WITH name(id) AS (VALUES (?),...)` prefix for each [name, values] pair.
// Empty sets become `(SELECT NULL WHERE 0)` so the CTE stays valid and matches nothing.
function cteValues(pairs) {
  return 'WITH ' + pairs.map(function (p) {
    const name = p[0], values = p[1] || [];
    if (!values.length) return name + '(id) AS (SELECT NULL WHERE 0)';
    return name + '(id) AS (VALUES ' + values.map(function () { return '(?)'; }).join(',') + ')';
  }).join(', ');
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FP_RE = /^fp-[0-9a-f]{12}$/;
const VID_COOKIE = 'vid2';

// Stable, server-side visitor identity. Priority:
//   1) vid2 cookie (persists 1yr across IP/network/region changes) — the browser
//      only sends it cross-origin once we set SameSite=None + the site calls
//      fetch with credentials:'include'. We bumped the cookie name from
//      'visitor_id' -> 'vid2' so that any cookies minted under the previous,
//      over-coarse fingerprint scheme are simply ignored (browsers send the
//      stale one, we don't recognise it, we re-fingerprint cleanly). This also
//      stops an attacker from pinning an arbitrary id: the regex below only
//      accepts a real UUID or one of our 12-hex 'fp-...' ids — never a free-
//      form value they drafted.
//   2) fingerprint hash of (normalized UA + Accept-Language + ISP + country) —
//      collapses the same device across cookieless visits (incognito,
//      cookie-blocked, first hit) and across IP changes within the same
//      carrier, WITHOUT merging two strangers who share a generic Android
//      webview UA. ISP+country keep Chennai-Airtel-en-IN separate from
//      Sacramento-T-Mobile-en-US even when the UA string is byte-identical.
//   3) fresh random UUID — only if both above fail (shouldn't happen in practice).
// Returns { id, fromCookie }.
async function getVisitorId(request, ua, language, cf = {}) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp(VID_COOKIE + '=([^;]+)'));
  const candidate = match ? match[1] : '';
  if (candidate && (UUID_RE.test(candidate) || FP_RE.test(candidate))) {
    return { id: candidate, fromCookie: true };
  }
  const isp = (cf.asOrganization || '').toLowerCase();
  const country = (cf.country || '').toLowerCase();
  const fp = await sha256Hex(`${normalizeUA(ua)}|${(language || '').toLowerCase()}|${isp}|${country}`);
  return { id: 'fp-' + fp.slice(0, 12), fromCookie: false };
}

function normalizeUA(ua) {
  // Strip build/version noise that changes frequently for the same device
  // (Chrome patch versions etc.), so a browser update doesn't split one
  // person into two visitor ids.
  return (ua || '')
    .replace(/Chrome\/[\d.]+/g, 'Chrome')
    .replace(/CriOS\/[\d.]+/g, 'CriOS')
    .replace(/Version\/[\d.]+/g, 'Version')
    .replace(/Mobile\/[\dA-Z]+/g, 'Mobile')
    .toLowerCase();
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  const bytes = new Uint8Array(buf);
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

// Short, safe-to-log preview of a visitor id (first 8 chars after any prefix).
function visitor_id_preview(id) {
  if (!id) return null;
  return String(id).replace(/^fp-/, '').slice(0, 8);
}

// Human-readable duration helper for the dashboard stat cards.
function fmtDur(sec) {
  sec = Math.max(0, Math.round(sec || 0));
  if (sec < 60) return sec + 's';
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  if (m < 60) return m + 'm' + (s ? ' ' + s + 's' : '');
  const h = Math.floor(m / 60);
  return h + 'h' + (m % 60 ? ' ' + (m % 60) + 'm' : '');
}

// ── POST /logout ──
async function handleLogout(request, env) {
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405, headers: securityHeaders() });
  }
  // Revoke the session server-side so the token dies even if the cookie leaks.
  const session = sessionTokenFrom(request.headers.get('Cookie') || '');
  if (session) {
    const jti = sessionJti(session);
    if (jti) {
      await env.DB.prepare('DELETE FROM sessions WHERE jti = ?').bind(jti).run();
    }
  }
  const headers = securityHeaders({
    'Location': '/dashboard',
    'Cache-Control': 'no-store',
    'Set-Cookie': '__Host-session=; Max-Age=0; Path=/; SameSite=Lax; Secure; HttpOnly',
  });
  return new Response(null, { status: 302, headers });
}

// ── GET/POST /dashboard ──
async function handleDashboard(request, env) {
  const htmlHeaders = securityHeaders({
    'Content-Type': 'text/html;charset=UTF-8',
    'Cache-Control': 'no-store',
    'X-Robots-Tag': 'noindex, nofollow',
  });
  const session = sessionTokenFrom(request.headers.get('Cookie') || '');

  // POST: authenticate and set session cookie
  if (request.method === 'POST') {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    // Brute-force protection: max 5 login attempts per 10 min per IP
    const allowed = await checkRateLimit(env.DB, ip, 'dashboard-login', 600, 5);
    if (!allowed) {
      return new Response(loginPage('Too many attempts. Try again in 10 minutes.', env), {
        status: 429,
        headers: htmlHeaders,
      });
    }

    // Optional Cloudflare Turnstile (human verification) if configured
    let body;
    try {
      body = await request.formData();
    } catch (_) {
      try { body = await request.json(); } catch (__) { body = null; }
    }
    if (env.TURNSTILE_SECRET) {
      const token = (body && typeof body.get === 'function' ? (body.get('turnstile') || body.get('cf-turnstile-response') || '') : '') || '';
      // Best-effort Turnstile: the client intentionally submits WITHOUT a token when the widget
      // fails to initialize (e.g. Safari iOS / mobile / Private Relay), so only reject a PRESENT
      // but invalid token. The brute-force rate limit above still guards this endpoint.
      if (token && !(await verifyTurnstile(env, token))) {
        return new Response(loginPage('Verification failed. Please try again.', env), {
          status: 401,
          headers: htmlHeaders,
        });
      }
    }

    const key = body?.get?.('key') || body?.key || '';
    if (!(await constantTimeEqual(String(key), env.DASHBOARD_KEY))) {
      console.warn(JSON.stringify({ event: 'login_fail' }));
      return new Response(loginPage('Invalid key', env), {
        status: 401,
        headers: htmlHeaders,
      });
    }
    console.log(JSON.stringify({ event: 'login_ok' }));
    const token = await createSessionToken(env);
    // Safari/ITP deliberately drops Set-Cookie when it rides on a 303/302 redirect
    // (known WebKit behavior — works in Chrome/Brave). So we store the session cookie
    // on a 200 response instead, then navigate client-side to /dashboard.
    const redirectPage =
      '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">' +
      '<title>Redirecting…</title><meta http-equiv="refresh" content="0;url=/dashboard">' +
      '</head><body><script>window.location.replace("/dashboard")</script></body></html>';
    const res = new Response(redirectPage, {
      status: 200,
      headers: {
        ...htmlHeaders,
        'Set-Cookie': `__Host-session=${token}; Max-Age=3600; Path=/; SameSite=Lax; Secure; HttpOnly`,
      },
    });
    return res;
  }

  if (request.method !== 'GET') {
    return new Response('Method Not Allowed', { status: 405, headers: htmlHeaders });
  }

  // GET: verify session cookie
  const sessionValid = !!(session && await verifySessionToken(session, env));
  console.log(JSON.stringify({ event: 'dashboard_session_check', cookiePresent: !!session, valid: sessionValid }));
  if (sessionValid) {
    const html = await renderDashboard(env.DB);
    return new Response(html, { headers: htmlHeaders });
  }

  return new Response(loginPage('', env), {
    status: 401,
    headers: htmlHeaders,
  });
}

// Optional Turnstile verification (only called when TURNSTILE_SECRET is configured)
async function verifyTurnstile(env, token) {
  try {
    const params = new URLSearchParams();
    params.set('secret', env.TURNSTILE_SECRET);
    params.set('response', token);
    // Note: no `remoteip` — on iOS Private Relay / mobile IP rotation the IP at token-mint
    // time can differ from the IP at siteverify time, which makes Cloudflare reject valid
    // tokens. remoteip is optional; omitting it avoids those false rejections.
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    if (!res.ok) return false;
    const data = await res.json();
    return data.success === true;
  } catch (_) {
    return false;
  }
}

async function renderDashboard(db) {
  const [totals, topCountries, recentVisits, trend, referrers, engagement, profiles, identityEvents] = await Promise.all([
    queryStats(db),
    queryTopCountries(db),
    queryRecent(db),
    queryTrend(db, 30),
    queryTopReferrers(db),
    queryEngagement(db),
    queryVisitorProfiles(db),
    queryIdentityEvents(db),
  ]);
  return dashboardHtml(totals, topCountries, recentVisits, trend, referrers, engagement, profiles, identityEvents);
}

// ── GET /stats (JSON) ──
async function handleStats(request, env) {
  const jsonHeaders = securityHeaders({
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'X-Robots-Tag': 'noindex, nofollow',
  });

  if (request.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'method_not_allowed' }), { status: 405, headers: jsonHeaders });
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const allowed = await checkRateLimit(env.DB, ip, 'stats', 60, 30);
  if (!allowed) {
    return new Response(JSON.stringify({ error: 'rate_limited' }), { status: 429, headers: jsonHeaders });
  }

  const session = sessionTokenFrom(request.headers.get('Cookie') || '');

  if (!session || !(await verifySessionToken(session, env))) {
    return new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401, headers: jsonHeaders });
  }

  const [totals, topCountries, trend, referrers, recent, engagement, profiles, identityEvents] = await Promise.all([
    queryStats(env.DB),
    queryTopCountries(env.DB),
    queryTrend(env.DB, 30),
    queryTopReferrers(env.DB),
    queryRecent(env.DB),
    queryEngagement(env.DB),
    queryVisitorProfiles(env.DB),
    queryIdentityEvents(env.DB),
  ]);

  return Response.json({ totals, topCountries, trend, referrers, recent, engagement, profiles, identityEvents }, { headers: jsonHeaders });
}

// ── GET /health ──
function handleHealth(request, env) {
  const h = securityHeaders({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  return Response.json({
    status: 'ok',
    ts: new Date().toISOString(),
    bindings: { d1: 'DB' in env, dashKey: 'DASHBOARD_KEY' in env, turnstile: 'TURNSTILE_SECRET' in env, logKey: 'LOG_KEY' in env, eventLimiter: 'EVENT_INGEST_LIMITER' in env },
  }, { headers: h });
}

// ── GET /meta (session-gated, internal only) ──
async function handleMeta(request, env) {
  const h = securityHeaders({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  if (request.method !== 'GET') {
    return Response.json({ error: 'method_not_allowed' }, { status: 405, headers: h });
  }
  const session = sessionTokenFrom(request.headers.get('Cookie') || '');
  if (!session || !(await verifySessionToken(session, env))) {
    return Response.json({ error: 'unauthorized' }, { status: 401, headers: h });
  }
  const [oldest, newest, pvCount, engCount] = await Promise.all([
    env.DB.prepare('SELECT created_at FROM page_views ORDER BY created_at ASC LIMIT 1').first(),
    env.DB.prepare('SELECT created_at FROM page_views ORDER BY created_at DESC LIMIT 1').first(),
    env.DB.prepare('SELECT COUNT(*) AS c FROM page_views').first(),
    env.DB.prepare('SELECT COUNT(*) AS c FROM page_engagement').first(),
  ]);
  const retainDays = parseInt(env.RETAIN_DAYS, 10) || 0;
  return Response.json({
    version: VERSION,
    compat: '2026-08-02',
    runtime: 'workers',
    data_range: {
      first: oldest?.created_at || null,
      last: newest?.created_at || null,
    },
    counts: {
      page_views: pvCount?.c || 0,
      engagement: engCount?.c || 0,
    },
    retention: retainDays > 0 ? retainDays + 'd' : 'off',
    uptime: process.uptime ? Math.floor(process.uptime()) + 's' : 'n/a',
  }, { headers: h });
}

// ── DB queries ──
async function queryStats(db) {
  const row = await db.prepare(
    `SELECT
       (SELECT COUNT(*) FROM page_views) AS total,
       (SELECT COUNT(DISTINCT COALESCE(l.canonical_id, ov.profile_id, v.visitor_id))
        FROM page_views v LEFT JOIN visitor_visit_overrides ov ON ov.page_view_id = v.id
        LEFT JOIN visitor_identity_links l ON l.visitor_id = COALESCE(ov.profile_id, v.visitor_id)) AS uniq,
       (SELECT COUNT(*) FROM page_views WHERE date(created_at) = date('now')) AS today,
       (SELECT COUNT(*) FROM page_views WHERE created_at >= datetime('now', '-1 day')) AS last24h`
  ).first();
  return {
    total: row?.total || 0,
    unique: row?.uniq || 0,
    today: row?.today || 0,
    last24h: row?.last24h || 0,
  };
}

async function queryEngagement(db) {
  // Sessions with at least one heartbeat: duration = last heartbeat − first pageview-ish event
  // We approximate session start from the earliest engagement row and end from the latest.
  const { results: sessions } = await db.prepare(
    `SELECT session_id,
            MIN(created_at) AS started,
            MAX(created_at) AS ended,
            COUNT(*) AS events
     FROM page_engagement
     WHERE session_id IS NOT NULL AND session_id != ''
     GROUP BY session_id
     ORDER BY started DESC
     LIMIT 50`
  ).all();

  const perSession = (sessions || []).map(s => {
    const secs = Math.max(0, Math.round((new Date(s.ended) - new Date(s.started)) / 1000));
    return {
      session: (s.session_id || '').slice(0, 12),
      started: s.started,
      ended: s.ended,
      durationSec: secs,
      events: s.events || 0,
    };
  });

  const totalSessions = perSession.length;
  const totalSec = perSession.reduce((a, b) => a + b.durationSec, 0);
  const avgSec = totalSessions ? Math.round(totalSec / totalSessions) : 0;
  const totalClicks = await db.prepare("SELECT COUNT(*) AS count FROM page_engagement WHERE event_type = 'click'").first();

  // Top clicked targets
  const { results: clicks } = await db.prepare(
    `SELECT target, MAX(label_quality) AS label_quality, COUNT(*) AS count
     FROM page_engagement
     WHERE event_type = 'click' AND target IS NOT NULL AND target != ''
     GROUP BY target
     ORDER BY count DESC
     LIMIT 8`
  ).all();

  // Per-click log — newest first, with the visitor's latest known location
  const { results: clickDetails } = await db.prepare(
    `SELECT pe.id AS id, pe.created_at, pe.visitor_id, COALESCE(il.canonical_id, pe.visitor_id) AS profile_id, pe.target, pe.section, pe.cls, pe.href, pe.x, pe.y,
            pe.action_id, pe.label_quality, pe.source, pe.interaction, pe.viewport_w, pe.viewport_h,
            (SELECT v.city    FROM page_views v WHERE v.visitor_id = pe.visitor_id ORDER BY v.created_at DESC LIMIT 1) AS city,
            (SELECT v.region  FROM page_views v WHERE v.visitor_id = pe.visitor_id ORDER BY v.created_at DESC LIMIT 1) AS region,
            (SELECT v.country FROM page_views v WHERE v.visitor_id = pe.visitor_id ORDER BY v.created_at DESC LIMIT 1) AS country,
            (SELECT v.latitude FROM page_views v WHERE v.visitor_id = pe.visitor_id ORDER BY v.created_at DESC LIMIT 1) AS latitude,
            (SELECT v.longitude FROM page_views v WHERE v.visitor_id = pe.visitor_id ORDER BY v.created_at DESC LIMIT 1) AS longitude
     FROM page_engagement pe
     LEFT JOIN visitor_identity_links il ON il.visitor_id = pe.visitor_id
     WHERE pe.event_type = 'click' AND pe.target IS NOT NULL AND pe.target != ''
     ORDER BY pe.created_at DESC
     LIMIT 60`
  ).all();

  return {
    sessions: totalSessions,
    avgDurationSec: avgSec,
    totalClicks: totalClicks?.count || 0,
    recent: perSession.slice(0, 10),
    topClicks: clicks || [],
    clickDetails: clickDetails || [],
  };
}

async function queryTopCountries(db) {
  const { results } = await db.prepare(
    `SELECT country, COUNT(*) as count
     FROM page_views
     WHERE country IS NOT NULL
     GROUP BY country
     ORDER BY count DESC
     LIMIT 10`
  ).all();
  return results || [];
}

async function queryRecent(db) {
  const { results } = await db.prepare(
    `SELECT v.id, v.created_at, v.country, v.city, v.region, v.referrer, v.page_url, v.visitor_id, v.user_agent,
            COALESCE(il.canonical_id, ov.profile_id, v.visitor_id) AS profile_id,
            v.device_type, v.os, v.browser, v.latitude, v.longitude, v.postal_code, v.isp, v.language
     FROM page_views v
     LEFT JOIN visitor_visit_overrides ov ON ov.page_view_id = v.id
     LEFT JOIN visitor_identity_links il ON il.visitor_id = COALESCE(ov.profile_id, v.visitor_id)
     ORDER BY v.created_at DESC
     LIMIT 100`
  ).all();
  return (results || []).map(row => {
    const parsed = row.user_agent ? parseUADetailed(row.user_agent) : null;
    const { user_agent, ...visit } = row;
    return { ...visit, os: parsed?.os || row.os, browser: parsed?.browser || row.browser, device_type: parsed?.device || row.device_type };
  });
}

// ── 30-day daily trend ──
async function queryTrend(db, days) {
  const { results } = await db.prepare(
    `SELECT date(created_at) as date, COUNT(*) as count
     FROM page_views
     WHERE created_at >= datetime('now', 'start of day', ?)
     GROUP BY date(created_at)
     ORDER BY date ASC`
  ).bind(`-${days - 1} days`).all();
  return results || [];
}

// ── Top referrers ──
async function queryTopReferrers(db) {
  const { results } = await db.prepare(
    `SELECT referrer
     FROM page_views
     ORDER BY created_at DESC
     LIMIT 200`
  ).all();

  const counts = {};
  for (const r of results || []) {
    let host;
    try {
      host = r.referrer ? new URL(r.referrer).hostname.replace(/^www\./, '') : null;
    } catch (_) {
      host = r.referrer ? String(r.referrer) : null;
    }
    const key = host || 'Direct';
    counts[key] = (counts[key] || 0) + 1;
  }

  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([source, count]) => ({ source, count }));
}

// ── Grouped visitor profiles (one box per device/person) ──
async function queryVisitorProfiles(db) {
  const { results } = await db.prepare(
    `SELECT COALESCE(il.canonical_id, ov.profile_id, v.visitor_id) AS profile_id,
            COUNT(*) as visits,
            MIN(v.created_at) as first_seen,
            MAX(v.created_at) as last_seen,
            GROUP_CONCAT(DISTINCT COALESCE(ov.profile_id, v.visitor_id)) as member_ids,
            GROUP_CONCAT(DISTINCT v.city) as cities,
            GROUP_CONCAT(DISTINCT v.region) as regions,
            GROUP_CONCAT(DISTINCT v.country) as countries,
            GROUP_CONCAT(DISTINCT v.isp) as isps,
            GROUP_CONCAT(DISTINCT v.user_agent) as uas,
            GROUP_CONCAT(DISTINCT v.device_type) as devices,
            GROUP_CONCAT(DISTINCT v.os) as oss,
            GROUP_CONCAT(DISTINCT v.browser) as browsers,
            GROUP_CONCAT(DISTINCT v.language) as langs,
            GROUP_CONCAT(DISTINCT v.timezone) as timezones,
            GROUP_CONCAT(DISTINCT v.ip_hash) as ip_hashes,
            GROUP_CONCAT(DISTINCT v.colo) as colos
     FROM page_views v
     LEFT JOIN visitor_visit_overrides ov ON ov.page_view_id = v.id
     LEFT JOIN visitor_identity_links il ON il.visitor_id = COALESCE(ov.profile_id, v.visitor_id)
     GROUP BY COALESCE(il.canonical_id, ov.profile_id, v.visitor_id)
     ORDER BY visits DESC`
  ).all();

  return (results || []).map(r => {
    const uas = [...new Set((r.uas || '').split(',').filter(Boolean))];
    const parsed = uas.map(parseUADetailed);
    return ({
    id: r.profile_id,
    members: [...new Set((r.member_ids || '').split(',').filter(Boolean))].sort((a, b) => a === r.profile_id ? -1 : b === r.profile_id ? 1 : a.localeCompare(b)),
    visits: r.visits || 0,
    firstSeen: r.first_seen,
    lastSeen: r.last_seen,
    cities: [...new Set((r.cities || '').split(',').filter(Boolean))],
    regions: [...new Set((r.regions || '').split(',').filter(Boolean))],
    countries: [...new Set((r.countries || '').split(',').filter(Boolean))],
    isps: [...new Set((r.isps || '').split(',').filter(Boolean))],
    uas,
    devices: parsed.length ? [...new Set(parsed.map(p => p.device))] : [...new Set((r.devices || '').split(',').filter(Boolean))],
    oss: parsed.length ? [...new Set(parsed.map(p => p.os))] : [...new Set((r.oss || '').split(',').filter(Boolean))],
    browsers: parsed.length ? [...new Set(parsed.map(p => p.browser))] : [...new Set((r.browsers || '').split(',').filter(Boolean))],
    langs: [...new Set((r.langs || '').split(',').filter(Boolean))],
    timezones: [...new Set((r.timezones || '').split(',').filter(Boolean))],
    ipHashes: [...new Set((r.ip_hashes || '').split(',').filter(Boolean))],
    colos: [...new Set((r.colos || '').split(',').filter(Boolean))],
  });
  });
}

async function queryIdentityEvents(db) {
  const [{ results }, { results: visitResults }] = await Promise.all([db.prepare(
    'SELECT id, action, source_id, target_id, affected_ids, created_at FROM visitor_identity_events ORDER BY created_at DESC, rowid DESC LIMIT 12'
  ).all(), db.prepare(
    'SELECT id, action, page_view_id, original_id, profile_id, created_at FROM visitor_visit_events ORDER BY created_at DESC, rowid DESC LIMIT 12'
  ).all()]);
  const links = (results || []).map(row => ({
    id: row.id,
    action: row.action,
    source: row.source_id,
    target: row.target_id,
    affected: JSON.parse(row.affected_ids || '[]'),
    createdAt: row.created_at,
  }));
  const visits = (visitResults || []).map(row => ({
    id: row.id,
    action: row.action,
    source: row.original_id,
    target: row.profile_id,
    viewId: row.page_view_id,
    affected: [row.page_view_id],
    createdAt: row.created_at,
  }));
  return [...links, ...visits].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 12);
}

// ── HTML pages ──
const BRAND = '<span class="brand"><span class="brand-mark" aria-hidden="true"><i></i><i></i><i></i></span>Site Activity</span>';
const THEME_TOGGLE = '<button type="button" id="themeToggle" aria-label="Dark mode" aria-pressed="false" title="Dark mode"><span class="theme-icon" aria-hidden="true">◐</span></button>';

function pageHead(title, csp) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<title>${title} | Site Activity</title>
<script>${themeScript}</script>
<style>${dashboardStyles}</style>
</head>`;
}

function loginPage(msg, env) {
  const error = msg ? `<p class="login-error" role="alert">${esc(msg)}</p>` : '';
  const hasTurnstile = !!env?.TURNSTILE_SECRET;
  const host = 'https://challenges.cloudflare.com';
  const siteKey = env?.TURNSTILE_SITE_KEY || '0x4AAAAAAEEnNXNege0uqc_0';
  const csp = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    + (hasTurnstile ? ` ${host}; frame-src ${host}; connect-src ${host}` : '')
    + "; img-src 'self' data: https:";
  const turnstile = hasTurnstile ? `
    <div id="dashboardChallenge" class="cf-turnstile" data-sitekey="${esc(siteKey)}" data-action="turnstile-spin-v2" data-theme="auto" data-size="compact"></div>
    <script>
      var challenge = document.getElementById('dashboardChallenge');
      if (challenge.clientWidth >= 300) challenge.dataset.size = 'flexible';
    </script>
    <script src="${host}/turnstile/v0/api.js" async defer></script>` : '';
  return `${pageHead('Sign in', csp)}
<body>
<header class="masthead"><div class="masthead-inner shell">${BRAND}${THEME_TOGGLE}</div></header>
<main class="login-shell shell">
  <div class="card login-card">
    <p class="eyebrow">shoaibakthar.pro</p>
    <h1>Sign in to analytics</h1>
    ${error}
    <form method="POST" action="/dashboard">
      <label for="keyInput">Access key</label>
      <div class="login-field">
        <input type="password" name="key" id="keyInput" autocomplete="off" required>
        <button type="button" id="eyeBtn" aria-controls="keyInput" aria-label="Show access key">Show</button>
      </div>
      ${turnstile}
      <button class="primary" type="submit">Sign in</button>
    </form>
  </div>
</main>
<script>
  document.getElementById('eyeBtn').addEventListener('click', function () {
    var input = document.getElementById('keyInput');
    var show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    this.textContent = show ? 'Hide' : 'Show';
    this.setAttribute('aria-label', show ? 'Hide access key' : 'Show access key');
  });
</script>
</body>
</html>`;
}


function metric(id, label, value, detail = '') {
  return `<div class="metric"><dt>${label}</dt><dd class="metric-value" id="${id}">${value}</dd>${detail ? `<dd class="muted">${detail}</dd>` : ''}</div>`;
}

function logTable(kind, columns, rows) {
  const visits = kind === 'recent';
  const label = visits ? 'visits' : 'interactions';
  return `<div class="log-tools">
    <button type="button" class="manage-log" aria-pressed="false">Manage records</button>
    <label class="select-all"><input type="checkbox" class="chk" id="${kind}All"> Select all shown</label>
    <div class="bulkbar" id="${kind}Bulk" hidden>
      <span><strong id="${kind}SelCount">0</strong> selected</span>
      <button type="button" id="${kind}ClearSel">Clear</button>
      <button type="button" class="danger-btn" id="${kind}BulkDelete">Delete selected ${label}</button>
    </div>
  </div>
  <div class="table-scroll-x">
    <table class="log-table" role="table" aria-label="${visits ? 'Recent visits' : 'Recent interactions'}">
      <thead role="rowgroup"><tr role="row"><th scope="col" class="sel-col"><span class="sr-only">Select</span></th>
        ${columns.map(column => `<th scope="col">${column}</th>`).join('')}<th scope="col" class="act-col"><span class="sr-only">Actions</span></th>
      </tr></thead>
      <tbody role="rowgroup" id="${visits ? 'recentTbody' : 'clickTbody'}">${rows}</tbody>
    </table>
  </div>`;
}

function dashboardHtml(totals, countries, visits, trend, referrers, engagement, profiles, identityEvents) {
  const dashSeed = JSON.stringify({totals, topCountries: countries, recent: visits, trend, referrers, engagement,
    profiles: profiles.map(({ id, visits, members, cities, countries, devices, oss, browsers, firstSeen, lastSeen, isps, ipHashes, timezones }) =>
      ({ id, visits, members, cities, countries, devices, oss, browsers, firstSeen, lastSeen, isps, ipHashes, timezones })),
    identityEvents
  }).replace(/</g, '\u003c').replace(/\u2028/g, '\u2028').replace(/\u2029/g, '\u2029');
  const number = new Intl.NumberFormat('en-US');
  const recentRows = visits.length ? visits.map(v => {
    const place = [v.city, v.region, v.country].filter(Boolean).join(', ');
    const device = [v.device_type, v.os, v.browser].filter(Boolean).join(' · ');
    return `<tr role="row">
      <td role="cell" class="sel-col"></td>
      <td role="cell" class="time-cell" data-label="Time (Central)">${formatTime(v.created_at)}</td>
      <td role="cell" class="main-cell" data-label="Approx. area">${esc(place || (v.latitude != null || v.longitude != null ? 'Approximate area' : '—'))}${coordH(v)}</td>
      <td role="cell" data-label="Device">${esc(device || '—')}</td>
      <td role="cell" data-label="Source">${esc(v.referrer || 'Direct')}</td>
      <td role="cell" data-label="Profile">${esc((v.profile_id || v.visitor_id || '').slice(0, 8))}</td>
      <td role="cell" class="act-col"></td>
    </tr>`;
  }).join('') : '<tr role="row"><td role="cell" colspan="7" class="empty-state">No visits recorded yet.</td></tr>';

  return `${pageHead('Dashboard', "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'")}
<body>
<a class="sr-only skip-link button" href="#dashboardMain">Skip to content</a>
<header class="masthead"><div class="masthead-inner shell">
  ${BRAND}
  <div class="top-actions">${THEME_TOGGLE}<form method="POST" action="/logout"><button type="submit">Sign out</button></form></div>
</div></header>
<div class="nav-shell"><nav class="navigation shell" aria-label="Dashboard" id="dashboardNav">
  <a href="#overview" aria-current="page">Overview</a>
  <a href="#visits">Visits</a>
  <a href="#interactions">Interactions</a>
  <a href="#profiles">Profiles</a>
  <a href="#settings">Settings</a>
</nav></div>
<main class="shell" id="dashboardMain" tabindex="-1">
  <noscript><style>#visits[hidden]{display:block!important}.overview-grid,.nav-shell,.log-tools,.search-wrap,.refresh-group{display:none!important}</style><p class="card">Enable JavaScript to use the dashboard filters, activity charts and profile tools.</p></noscript>
  <section id="overview" data-view aria-labelledby="overviewTitle">
    <header class="section-head">
      <div><p class="eyebrow">shoaibakthar.pro</p><h1 id="overviewTitle" tabindex="-1">Traffic overview</h1></div>
      <div class="refresh-group"><span class="refresh-status" id="refreshStatus" role="status">Updates every minute</span><button type="button" id="refreshButton">Refresh</button></div>
    </header>
    <div class="favorite-alert" id="favoriteAlert" hidden></div>
    <dl class="metrics">
      ${metric('statToday', 'Views today', number.format(totals.today), 'Since midnight UTC')}
      ${metric('stat24h', 'Views in 24 hours', number.format(totals.last24h), 'Rolling window')}
      ${metric('statTotal', 'Total views', number.format(totals.total), 'All recorded visits')}
      ${metric('statUnique', 'Visitor profiles', number.format(totals.unique), 'Distinct profiles')}
    </dl>
    <div class="overview-grid">
      <section class="card plot-card" aria-labelledby="chartTitle">
        <header class="card-head">
          <div><p class="eyebrow">Daily views · UTC</p><h2 id="chartTitle">Traffic over time</h2></div>
          <div class="periods" role="group" aria-label="Chart date range">
            <button type="button" data-days="7" aria-label="Last 7 days" aria-pressed="false">7D</button>
            <button type="button" data-days="30" aria-label="Last 30 days" aria-pressed="true">30D</button>
          </div>
        </header>
        <div class="plot-summary"><strong class="plot-total" id="plotTotal">0</strong><span id="plotSummary">views in 30 days</span></div>
        <div class="plot-chart">
          <div class="plot-axis" id="plotAxis" aria-hidden="true"></div>
          <div class="plot-bars" id="plotBars" role="group" aria-label="Daily views. Use the arrow keys to browse dates."></div>
          <div class="plot-dates" id="plotDates" aria-hidden="true"></div>
        </div>
        <p class="plot-detail" id="plotDetail"></p>
      </section>
      <section class="card" aria-labelledby="sourcesTitle">
        <header class="card-head"><div><h2 id="sourcesTitle">Traffic sources</h2><p class="muted">From the latest 200 visits</p></div></header>
        <ol class="rank-list" role="list" id="refList"></ol>
      </section>
    </div>
    <div class="overview-grid">
      <section class="card" aria-labelledby="latestTitle">
        <header class="card-head"><h2 id="latestTitle">Latest visits</h2><a class="button" href="#visits">All visits <span aria-hidden="true">↗</span></a></header>
        <ul class="compact-visits" role="list" id="latestVisits"></ul>
      </section>
      <section class="card overview-country" aria-labelledby="countriesTitle">
        <header class="card-head"><div><h2 id="countriesTitle">Top countries</h2><p class="muted">Estimated from IP addresses</p></div></header>
        <ol class="rank-list" role="list" id="countryList"></ol>
      </section>
    </div>
  </section>

  <section id="visits" data-view aria-labelledby="visitsTitle" hidden>
    <header class="section-head"><div><h1 id="visitsTitle" tabindex="-1">Visits</h1><p class="muted">The latest 100 visits, newest first</p></div></header>
    <section class="card table-card" aria-labelledby="visitLogTitle">
      <header class="card-head"><h2 id="visitLogTitle">Recent visits</h2>
        <div class="search-wrap"><input type="search" id="recentSearch" placeholder="Search visits…" aria-label="Search visits" autocomplete="off"></div>
      </header>
      ${logTable('recent', ['Time (Central)', 'Approx. area', 'Device', 'Source', 'Profile'], recentRows)}
    </section>
  </section>

  <section id="interactions" data-view aria-labelledby="interactionsTitle" hidden>
    <header class="section-head"><div><h1 id="interactionsTitle" tabindex="-1">Interactions</h1><p class="muted">How visitors use your site</p></div></header>
    <dl class="engagement-summary">
      ${metric('statClicks', 'Total clicks', number.format(engagement.totalClicks))}
      ${metric('statSessions', 'Recent sessions', number.format(engagement.sessions), 'Up to 50 with recorded activity')}
      ${metric('statAvg', 'Avg. activity span', fmtDur(engagement.avgDurationSec), 'First to last recorded event')}
    </dl>
    <section class="card top-clicks" aria-labelledby="topClickTitle">
      <header class="card-head"><h2 id="topClickTitle">Most clicked</h2></header>
      <ol id="topClickList" role="list"></ol>
    </section>
    <section class="card table-card" aria-labelledby="clickLogTitle">
      <header class="card-head"><div><h2 id="clickLogTitle">Interaction log</h2><p class="muted">The latest 60 click records</p></div>
        <div class="search-wrap"><input type="search" id="clickSearch" placeholder="Search interactions…" aria-label="Search interactions" autocomplete="off"></div>
      </header>
      <details class="identity-note"><summary>About interaction labels</summary><p>Named controls are identified by the site. Inferred controls use browser semantics. Positions are coordinates within the viewport.</p></details>
      ${logTable('click', ['Time (Central)', 'Interaction', 'Approx. area', 'Section', 'Destination', 'Profile', 'Position'], '<tr><td colspan="9" class="empty-state">Loading interactions…</td></tr>')}
    </section>
  </section>

  <section id="profiles" data-view aria-labelledby="profilesTitle" hidden>
    <header class="section-head"><div><p class="eyebrow">Identity studio</p><h1 id="profilesTitle" tabindex="-1">Visitor profiles</h1></div></header>
    <div class="log-tools">
      <div class="search-wrap"><input type="search" id="profileSearch" placeholder="Search profiles…" aria-label="Search profiles" autocomplete="off"></div>
      <label><input type="checkbox" class="chk" id="savedProfiles"> Saved only</label>
    </div>
    <div id="profileGrid" class="profile-grid"></div>
    <details class="card identity-history"><summary>Identity activity</summary><div id="identityHistory"></div></details>
  </section>

  <section id="settings" data-view aria-labelledby="settingsTitle" hidden>
    <header class="section-head"><div><h1 id="settingsTitle" tabindex="-1">Settings</h1></div></header>
    <section class="card danger-zone" aria-labelledby="dangerTitle">
      <h2 id="dangerTitle">Delete analytics data</h2>
      <p>Deleting data is permanent. Choose the records you want to clear.</p>
      <div class="danger-actions">
        <button type="button" class="danger-btn" data-danger="all_visits">Delete all visits</button>
        <button type="button" class="danger-btn" data-danger="all_engagement">Delete clicks and sessions</button>
        <button type="button" class="danger-btn" data-danger="all">Delete all analytics</button>
      </div>
    </section>
  </section>
</main>
<footer class="shell">Visit and interaction times use US Central time.</footer>
  <dialog class="identity-dialog" id="identityDialog" aria-labelledby="identityDialogTitle">
    <h2 id="identityDialogTitle">Are these the same person?</h2>
    <p id="identityDialogDescription">The card you opened stays. Choose another profile to add to it.</p>
    <div id="identityTargetWrap"><label for="identityTarget">Choose a second profile to add</label><select id="identityTarget"></select></div>
    <div class="identity-review"><div><strong id="identityFromLabel">Keep this profile</strong><span id="identityFrom"></span></div><div><strong id="identityToLabel">Add this profile</strong><span id="identityTo"></span></div></div>
    <div class="identity-signal" id="identitySignals"></div>
    <p class="identity-note" id="identityOutcome"></p>
    <label class="identity-check" id="identityApprovalWrap"><input type="checkbox" id="identityApproval"><span>I know these profiles belong to the same person.</span></label>
    <p class="identity-error" id="identityError" role="alert" hidden></p>
    <div class="identity-dialog-actions"><button type="button" id="identityCancel">Cancel</button><button type="button" class="identity-confirm" id="identityConfirm" disabled>Combine into this profile</button></div>
  </dialog>

  <dialog class="identity-dialog" id="visitDialog" aria-labelledby="visitDialogTitle">
    <h2 id="visitDialogTitle">Review visits</h2>
    <p>Each line is an individual visit. Choose one only if you know it belongs to another person. The original record stays intact; this historical correction can be undone. Future visits still use the browser’s own ID.</p>
    <div class="visit-list" id="visitList"></div>
    <div class="visit-editor" id="visitEditor" hidden>
      <p id="visitSelected"></p>
      <label for="visitDestination">Where should this visit appear?</label><select id="visitDestination"></select>
      <p class="identity-note">Visits only. Click/session events cannot be attributed to a particular visit and will stay with their original ID.</p>
      <div class="identity-dialog-actions"><button type="button" id="visitCancelMove">Cancel</button><button type="button" class="identity-confirm" id="visitConfirmMove">Move visit</button></div>
    </div>
    <p class="identity-error" id="visitError" role="alert" hidden></p>
    <div class="identity-dialog-actions"><button type="button" id="visitClose">Close</button></div>
  </dialog>

<script>window.__DASH=${dashSeed};</script>
<script>${DASHBOARD_CLIENT_JS}</script>
</body>
</html>`;
}

function formatTime(t) {
  if (!t) return '';
  const d = new Date(t + 'Z');
  return d.toLocaleString('en-US', { month:'short', day:'numeric', hour:'numeric', minute:'2-digit', hour12:true, timeZone:'America/Chicago' });
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Cloudflare's city and coordinates are IP geolocation estimates, not device GPS.
function coordH(v) {
  let place = [v.city, v.region, v.country].filter(Boolean).join(', ');
  const latitude = geoCoordinate(v.latitude, -90, 90);
  const longitude = geoCoordinate(v.longitude, -180, 180);
  if (!place && latitude === null && longitude === null) return '';
  place = place || 'Approximate area';
  const hasPlace = [v.city, v.region, v.country].some(Boolean);
  const map = hasPlace
    ? '<a class="area-map-link" href="https://maps.apple.com/?q=' + encodeURIComponent(place)
      + '" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" aria-label="Open the approximate area in Apple Maps">Apple Maps ↗</a>'
    : '<span class="map-unavailable">Place name unavailable</span>';
  return '<div class="location-meta"><span>IP-based estimate</span>' + map + '</div>';
}

// User‑agent parser — returns structured fields for DB storage
function parseUADetailed(ua) {
  if (!ua) return { device: 'Unknown', os: 'Unknown', browser: 'Unknown' };
  let browser = 'Unknown';
  if (/Brave/i.test(ua)) browser = 'Brave';
  else if (/Edg\//.test(ua)) browser = 'Edge';
  else if (/SamsungBrowser\//.test(ua)) browser = 'Samsung';
  else if (/Chrome\//.test(ua) && !/Chromium\//.test(ua)) browser = 'Chrome';
  else if (/Firefox\//.test(ua)) browser = 'Firefox';
  else if (/Safari\//.test(ua) && !/Chrome\//.test(ua) && !/Chromium\//.test(ua)) browser = 'Safari';
  let os = 'Unknown';
  if (/Windows NT 10/.test(ua)) os = 'Windows';
  else if (/iPhone/.test(ua)) os = 'iOS';
  else if (/iPad/.test(ua)) os = 'iPadOS';
  else if (/Android/.test(ua)) os = 'Android';
  else if (/Mac OS X/.test(ua)) os = 'macOS';
  else if (/Linux/.test(ua)) os = 'Linux';
  let device = 'Desktop';
  if (/Tablet|iPad/.test(ua)) device = 'Tablet';
  else if (/Mobi|Android|iPhone/.test(ua)) device = 'Mobile';
  return { device, os, browser };
}
