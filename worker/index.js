var VERSION = '3.33.0'; // bump when you change the worker code

/**
 * pageview-logger — Cloudflare Worker analytics dashboard
 * =======================================================
 *
 * Purpose: Track page views and engagement on a personal profile site
 * (shoaibsprojects.github.io/shoaibAktharProBio) with a liquid-glass dashboard.
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
 *   • All writes: Origin whitelist + shared-secret key (LOG_KEY)
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
 *   /dashboard         GET   — Liquid-glass dashboard HTML (session auth)
 *                      POST  — Login (Turnstile + key auth)
 *   /stats             GET   — Dashboard data as JSON (session auth)
 *   /health            GET   — Public health check (no auth)
 *   /meta              GET   — Worker metadata (session auth)
 *   /api/merge-visitors POST — Link two visitor profiles (session+CSRF auth)
 *   /api/unmerge-visitor POST — Separate one original visitor ID
 *   /api/profile-visits GET — Review a profile's underlying visits
 *   /api/move-visit POST — Move one historical visit into another profile
 *   /api/restore-visit POST — Undo a per-visit correction
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
 *   This project uses ~0.1% of free-tier capacity at current traffic.
 *
 * @module pageview-logger
 * @author Shoaib Akthar
 * @version 3.33.0
 */

export default {
  async fetch(request, env, ctx) {
    const start = Date.now();
    const url = new URL(request.url);
    const path = url.pathname;
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const ua = request.headers.get('User-Agent') || '';

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
        ip,
        ua: ua.slice(0, 128),
      }));
      return response;

    } catch (err) {
      const elapsed = Date.now() - start;
      console.error(JSON.stringify({
        l: path,
        error: err instanceof Error ? err.message : String(err),
        ms: elapsed,
        ip,
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
    console.log(JSON.stringify({ event: 'bot_blocked', ip, ua: ua.slice(0, 100) }));
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

  // 5) Shared-secret check prevents unauthenticated writes
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
  const language = (request.headers.get('Accept-Language') || '').split(',')[0]?.trim() || null;
  const uaParsed = parseUADetailed(ua);
  let { id: visitorId, fromCookie } = await getVisitorId(request, ua, language, cf);
  // Modern browsers (Chrome/Safari) block the cross-site Set-Cookie we issue here, so
  // the tracker also persists the id it gets from this response in localStorage on the
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
    cf.latitude ? String(cf.latitude) : null,
    cf.longitude ? String(cf.longitude) : null,
    cf.postalCode || null,
    cf.asOrganization || null,
    language,
    ipHash.slice(0, 16),
    colo
  ).run();

  console.log(JSON.stringify({ event: 'visit', ip, city: cf.city || null, country: cf.country || null, known: fromCookie, vid: visitor_id_preview(visitorId) }));

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

  // Rate limit: max 60 events per 60s per IP (covers heartbeats at 30s + clicks)
  const allowed = await checkRateLimit(env.DB, ip, 'events', 60, 60);
  if (!allowed) return Response.json({ ok: false, reason: 'rate_limited' }, { status: 429, headers: base });

  // Payload must be tiny — reject oversized
  const contentLength = Number(request.headers.get('Content-Length') || 0);
  if (contentLength > 2048) return Response.json({ ok: false, reason: 'payload_too_large' }, { status: 413, headers: base });

  let body = {};
  try { body = await request.json(); } catch (_) {
    return Response.json({ ok: false, reason: 'bad_json' }, { status: 400, headers: base });
  }

  // Same shared-secret gate as /log-visit
  if (!body.key || !(await constantTimeEqual(String(body.key), env.LOG_KEY))) {
    return Response.json({ ok: false, reason: 'unauthorized' }, { status: 401, headers: base });
  }

  // Identity comes from the cookie (validated by regex) — same fence as /log-visit.
  // The cross-site cookie is often blocked (Chrome/Safari), so fall back to the id the
  // tracker persisted in localStorage and sent in the payload.
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
    const x = Number.isFinite(Number(body.x)) ? Math.round(Number(body.x)) : null;
    const y = Number.isFinite(Number(body.y)) ? Math.round(Number(body.y)) : null;
    const target = typeof body.target === 'string' ? body.target.slice(0, 200) : null;
    const extra = typeof body.extra === 'string' ? body.extra.slice(0, 200) : null;
    const section = typeof body.section === 'string' ? body.section.slice(0, 80) : null;
    const cls = typeof body.cls === 'string' ? body.cls.slice(0, 80) : null;
    const href = typeof body.href === 'string' ? body.href.slice(0, 200) : null;
    await env.DB.prepare(
      `INSERT INTO page_engagement (visitor_id, session_id, event_type, page_url, x, y, target, extra, section, cls, href)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(vid, session_id || null, event_type, body.pageUrl || null, x, y, target, extra, section, cls, href).run();
  } else {
    // heartbeat / pagehide / pageshow / focus — no x/y
    await env.DB.prepare(
      `INSERT INTO page_engagement (visitor_id, session_id, event_type, page_url)
       VALUES (?, ?, ?, ?)`
    ).bind(vid, session_id || null, event_type, body.pageUrl || null).run();
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
  const h = securityHeaders({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: h });
  if (request.method !== 'POST') return Response.json({ error: 'method_not_allowed' }, { status: 405, headers: h });

  // CSRF: only accept requests originated from our own dashboard
  const origin = request.headers.get('Origin') || '';
  const host = request.headers.get('Host') || '';
  if (origin && !origin.includes('pageview-logger') && !host.includes('pageview-logger')) {
    return Response.json({ error: 'forbidden' }, { status: 403, headers: h });
  }

  const session = sessionTokenFrom(request.headers.get('Cookie') || '');
  if (!session || !(await verifySessionToken(session, env))) {
    return Response.json({ error: 'unauthorized' }, { status: 401, headers: h });
  }

  const r = await env.DB.prepare('DELETE FROM page_engagement').run();
  const deleted = (r && r.changes) || 0;
  console.log(JSON.stringify({ event: 'engagement_reset', deleted }));
  return Response.json({ ok: true, deleted }, { headers: h });
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
      console.warn(JSON.stringify({ event: 'login_fail', ip }));
      return new Response(loginPage('Invalid key', env), {
        status: 401,
        headers: htmlHeaders,
      });
    }
    console.log(JSON.stringify({ event: 'login_ok', ip }));
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
  try {
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
  } catch (err) {
    console.error('renderDashboard error:', err.stack || err.message);
    return '<html><body><h1>500</h1><pre>' + (err.stack || err.message) + '</pre></body></html>';
  }
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
    bindings: { d1: 'DB' in env, dashKey: 'DASHBOARD_KEY' in env, turnstile: 'TURNSTILE_SECRET' in env, logKey: 'LOG_KEY' in env },
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

  // Top clicked targets
  const { results: clicks } = await db.prepare(
    `SELECT target, COUNT(*) AS count
     FROM page_engagement
     WHERE event_type = 'click' AND target IS NOT NULL AND target != ''
     GROUP BY target
     ORDER BY count DESC
     LIMIT 8`
  ).all();

  // Per-click log — newest first, with the visitor's latest known location
  const { results: clickDetails } = await db.prepare(
    `SELECT pe.created_at, pe.visitor_id, COALESCE(il.canonical_id, pe.visitor_id) AS profile_id, pe.target, pe.section, pe.cls, pe.href, pe.x, pe.y,
            (SELECT v.city    FROM page_views v WHERE v.visitor_id = pe.visitor_id ORDER BY v.created_at DESC LIMIT 1) AS city,
            (SELECT v.region  FROM page_views v WHERE v.visitor_id = pe.visitor_id ORDER BY v.created_at DESC LIMIT 1) AS region,
            (SELECT v.country FROM page_views v WHERE v.visitor_id = pe.visitor_id ORDER BY v.created_at DESC LIMIT 1) AS country
     FROM page_engagement pe
     LEFT JOIN visitor_identity_links il ON il.visitor_id = pe.visitor_id
     WHERE pe.event_type = 'click' AND pe.target IS NOT NULL AND pe.target != ''
     ORDER BY pe.created_at DESC
     LIMIT 60`
  ).all();

  return {
    sessions: totalSessions,
    avgDurationSec: avgSec,
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
    `SELECT v.created_at, v.country, v.city, v.region, v.referrer, v.page_url, v.visitor_id, v.user_agent,
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
     WHERE created_at >= datetime('now', ?)
     GROUP BY date(created_at)
     ORDER BY date ASC`
  ).bind(`-${days} days`).all();
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
function loginPage(msg, env) {
  const errorHtml = msg ? `<p style="color:#d32f2f;margin-bottom:1rem;font-size:0.85rem">${esc(msg)}</p>` : '';
  const hasTurnstile = !!(env && env.TURNSTILE_SECRET);
  const turnstileSiteKey = (env && env.TURNSTILE_SITE_KEY) || '0x4AAAAAAEEnNXNege0uqc_0';
  const csp = hasTurnstile
    ? "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; img-src 'self' data: https:; connect-src https://challenges.cloudflare.com"
    : "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:";
  const turnstileHtml = hasTurnstile ? `
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <div class="cf-turnstile" data-sitekey="${esc(turnstileSiteKey)}" data-action="turnstile-spin-v2" data-theme="auto" data-size="flexible"></div>` : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Page View Dashboard</title>
<meta name="robots" content="noindex, nofollow">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='80' font-size='80' text-anchor='middle' x='50'%3E📊%3C/text%3E%3C/svg%3E">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<style>
  *,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
  :root{--bg:#eef0f6;--surface:rgba(255,255,255,0.6);--text:#1d1d1f;--muted:#86868b;--accent:#0071e3;
    --border:rgba(255,255,255,0.5);--border-soft:rgba(20,24,32,0.08);--accent-soft:rgba(0,113,227,0.10);
    --glass:linear-gradient(150deg,rgba(255,255,255,0.8) 0%,rgba(255,255,255,0.4) 50%,rgba(255,255,255,0.15) 100%);
    --card-shadow:0 20px 60px -10px rgba(0,80,180,0.18),inset 0 1px 0 rgba(255,255,255,0.85),inset 0 -1px 0 rgba(255,255,255,0.25);
    --sheen:linear-gradient(115deg,rgba(255,255,255,0.7) 0%,rgba(255,255,255,0.12) 18%,transparent 40%,rgba(255,255,255,0.0) 60%,rgba(255,255,255,0.2) 82%,transparent 100%)}
  html[data-theme="dark"]{--bg:#0e1015;--surface:rgba(28,31,38,0.6);--text:#f5f5f7;--muted:#a1a1a6;--accent:#2997ff;
    --border:rgba(255,255,255,0.14);--border-soft:rgba(255,255,255,0.09);--accent-soft:rgba(41,151,255,0.16);
    --glass:linear-gradient(150deg,rgba(70,80,110,0.5) 0%,rgba(30,34,44,0.3) 50%,rgba(20,22,30,0.18) 100%);
    --card-shadow:0 20px 60px -10px rgba(0,0,0,0.55),inset 0 1px 0 rgba(255,255,255,0.16),inset 0 -1px 0 rgba(0,0,0,0.4);
    --sheen:linear-gradient(115deg,rgba(255,255,255,0.22) 0%,rgba(255,255,255,0.04) 18%,transparent 40%,transparent 60%,rgba(255,255,255,0.06) 82%,transparent 100%)}
  @media (prefers-color-scheme: dark){
    :root{--bg:#0e1015;--surface:rgba(28,31,38,0.6);--text:#f5f5f7;--muted:#a1a1a6;--accent:#2997ff;
      --border:rgba(255,255,255,0.14);--border-soft:rgba(255,255,255,0.09);--accent-soft:rgba(41,151,255,0.16);
      --glass:linear-gradient(135deg,rgba(58,68,92,0.44),rgba(28,31,38,0.28));
      --card-shadow:0 14px 44px rgba(0,0,0,0.55),inset 0 1px 0 rgba(255,255,255,0.14),inset 0 0 24px rgba(41,151,255,0.05);
      --sheen:linear-gradient(115deg,rgba(255,255,255,0.16) 0%,rgba(255,255,255,0.03) 28%,transparent 55%,rgba(255,255,255,0.04) 78%,transparent 100%)}
  }
  body{font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text','SF Pro Display','Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);display:flex;align-items:center;justify-content:center;min-height:100vh;padding:1rem;transition:background 0.4s,color 0.4s;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;overflow-x:hidden}
  body::before,body::after{content:'';position:fixed;inset:-30%;z-index:-2;pointer-events:none}
  body::before{
    background:
      radial-gradient(700px 500px at 10% 0%,#d0e4ff 0%,transparent 50%),
      radial-gradient(800px 550px at 92% 5%,#ecd9ff 0%,transparent 48%),
      radial-gradient(900px 600px at 50% 95%,#d0f5e0 0%,transparent 50%),
      linear-gradient(160deg,#eef2fb 0%,#e8ecf6 100%);
    animation:none}
  body::after{background:radial-gradient(50% 35% at 50% 0%,rgba(255,255,255,0.7) 0%,transparent 70%);animation:none;mix-blend-mode:overlay}
  html[data-theme="dark"] body::before{
    background:
      radial-gradient(700px 500px at 10% 0%,rgba(25,80,170,0.3) 0%,transparent 50%),
      radial-gradient(800px 550px at 92% 5%,rgba(80,40,170,0.32) 0%,transparent 48%),
      radial-gradient(900px 600px at 50% 95%,rgba(15,110,60,0.22) 0%,transparent 50%),
      linear-gradient(160deg,#0c0f18 0%,#0e111a 100%)}
  html[data-theme="dark"] body::after{background:radial-gradient(50% 35% at 50% 0%,rgba(120,160,255,0.14) 0%,transparent 70%);mix-blend-mode:screen}
  @keyframes aurora{0%{transform:translate3d(0,0,0) scale(1)}100%{transform:translate3d(-3%,2%,0) scale(1.04)}}
  @keyframes aurora-glow{0%{opacity:0.5}100%{opacity:0.95}}
  @keyframes fadeInUp{0%{opacity:0;transform:translateY(12px) scale(0.998)}50%{opacity:1}100%{opacity:1;transform:translateY(0) scale(1)}}
  h1{background:linear-gradient(115deg,var(--text) 35%,var(--muted));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
  .box{background:var(--glass);padding:3rem 2.5rem;border-radius:28px;box-shadow:var(--card-shadow);text-align:center;max-width:420px;width:92vw;position:relative;border:1px solid var(--border);backdrop-filter:blur(28px) saturate(180%);-webkit-backdrop-filter:blur(28px) saturate(180%);animation:fadeInUp 0.3s cubic-bezier(.22,.61,.36,1) both}
  .box::before{content:'';position:absolute;inset:0;border-radius:inherit;pointer-events:none;background:radial-gradient(120% 80% at 0% 0%,rgba(255,255,255,0.8) 0%,rgba(255,255,255,0.0) 50%);opacity:0.7}
  .box::after{content:'';position:absolute;inset:0;border-radius:inherit;pointer-events:none;background:var(--sheen);mix-blend-mode:screen;z-index:0}
  .box>*{position:relative;z-index:1}
  .box-content{position:relative;z-index:1}
  .theme-toggle{position:absolute;top:1rem;right:1rem;z-index:2;background:var(--glass);color:var(--muted);border:1px solid var(--border);padding:0.35rem 0.7rem;border-radius:980px;font-size:0.75rem;cursor:pointer;font-family:inherit;font-weight:600;backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);box-shadow:inset 0 1px 0 rgba(255,255,255,0.7),0 2px 8px rgba(20,24,32,0.05);transition:color 0.2s,border-color 0.2s,box-shadow 0.2s}
  .theme-toggle:hover{color:var(--accent);border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft),inset 0 1px 0 rgba(255,255,255,0.8)}
  input{width:100%;padding:12px 16px;border:1px solid var(--border);border-radius:16px;font-size:16px;margin:1rem 0;font-family:inherit;background:rgba(255,255,255,0.5);color:var(--text);font-weight:500;transition:border-color 0.2s,box-shadow 0.2s;outline:none;backdrop-filter:blur(30px) saturate(200%);-webkit-backdrop-filter:blur(30px) saturate(200%);box-shadow:inset 0 1px 0 rgba(255,255,255,0.7),0 2px 8px rgba(20,24,32,0.05)}
  html[data-theme="dark"] input{background:rgba(40,44,55,0.5)}
  input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft),inset 0 1px 0 rgba(255,255,255,0.7)}
  button{background:linear-gradient(180deg,#0a84ff,var(--accent));color:#fff;border:none;padding:12px 32px;border-radius:980px;font-size:16px;cursor:pointer;font-family:inherit;font-weight:600;letter-spacing:0.01em;transition:transform 0.25s cubic-bezier(.22,.61,.36,1),box-shadow 0.25s,opacity 0.2s;box-shadow:0 8px 24px rgba(0,113,227,0.4),inset 0 1px 0 rgba(255,255,255,0.45),inset 0 -1px 0 rgba(0,0,0,0.15)}
  button:hover{transform:translateY(-1px);box-shadow:0 12px 32px rgba(0,113,227,0.5),inset 0 1px 0 rgba(255,255,255,0.55),inset 0 -1px 0 rgba(0,0,0,0.15)}
  html[data-theme="dark"] button{background:linear-gradient(180deg,#3aa0ff,#2997ff);box-shadow:0 8px 24px rgba(41,151,255,0.45),inset 0 1px 0 rgba(255,255,255,0.35),inset 0 -1px 0 rgba(0,0,0,0.2)}
  html[data-theme="dark"] button:hover{box-shadow:0 12px 32px rgba(41,151,255,0.55),inset 0 1px 0 rgba(255,255,255,0.45)}
  .pw-wrap{position:relative;margin:1rem 0}
  .pw-wrap input{margin:0;padding-right:48px}
  .eye-btn{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;border:none;padding:8px;cursor:pointer;color:var(--muted);display:flex;align-items:center;justify-content:center}
  .eye-btn:hover{color:var(--accent)}
  .eye-btn svg{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
  .cf-turnstile{display:flex;justify-content:center;margin:1rem 0}
  @media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<div class="box">
  <button type="button" class="theme-toggle" id="themeToggle" onclick="toggleTheme()" aria-label="Toggle dark mode">Dark</button>
  <h1 style="font-size:1.5rem;margin-bottom:0.5rem">Dashboard Access</h1>
  <p style="color:var(--muted);margin-bottom:1rem">Enter access key to continue</p>
  ${errorHtml}
  <form method="POST" action="/dashboard" id="loginForm">
    <div class="pw-wrap">
      <input type="password" name="key" id="keyInput" placeholder="Access Key" autofocus autocomplete="off">
      <button type="button" class="eye-btn" id="eyeBtn" aria-label="Show or hide key" title="Show/hide">
        <svg viewBox="0 0 24 24" id="eyeOpen"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>
        <svg viewBox="0 0 24 24" id="eyeClosed" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
      </button>
    </div>
    ${turnstileHtml}
    <button type="submit">View Dashboard</button>
  </form>
  <script>
    document.getElementById('eyeBtn').addEventListener('click', function(){
      var input = document.getElementById('keyInput');
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      document.getElementById('eyeOpen').style.display = show ? 'none' : 'block';
      document.getElementById('eyeClosed').style.display = show ? 'block' : 'none';
      input.focus();
    });
  </script>
</div>
<script>
  function readTheme(){
    var t=null;
    try{t=localStorage.getItem('dash-theme');}catch(e){}
    if(!t){var m=document.cookie.match(/(?:^|;\\s*)dash-theme=([^;]*)/);if(m)t=m[1];}
    return t;
  }
  function writeTheme(t){
    try{localStorage.setItem('dash-theme',t);}catch(e){}
    document.cookie='dash-theme='+t+'; Max-Age=31536000; Path=/; SameSite=Lax';
  }
  function applyTheme(){
    var m=window.matchMedia('(prefers-color-scheme: dark)');
    var t=readTheme()||(m.matches?'dark':'light');
    document.documentElement.setAttribute('data-theme',t);
    document.getElementById('themeToggle').textContent=(t==='dark')?'Light':'Dark';
  }
  function toggleTheme(){
    var m=window.matchMedia('(prefers-color-scheme: dark)');
    var cur=readTheme()||(m.matches?'dark':'light');
    var next=cur==='dark'?'light':'dark';
    document.documentElement.setAttribute('data-theme',next);
    document.getElementById('themeToggle').textContent=next==='dark'?'Light':'Dark';
    writeTheme(next);
  }
  applyTheme();
</script>
</body>
</html>`;
}

const DASHBOARD_CLIENT_JS = String.raw`
  // ── Theme (localStorage with cookie fallback — mobile/private browsing blocks localStorage) ──
  function readTheme(){
    var t=null;
    try{t=localStorage.getItem('dash-theme');}catch(e){}
    if(!t){var m=document.cookie.match(/(?:^|;\s*)dash-theme=([^;]*)/);if(m)t=m[1];}
    return t;
  }
  function writeTheme(t){
    try{localStorage.setItem('dash-theme',t);}catch(e){}
    document.cookie='dash-theme='+t+'; Max-Age=31536000; Path=/; SameSite=Lax';
  }
  function applyTheme(){
    var m=window.matchMedia('(prefers-color-scheme: dark)');
    var t=readTheme()||(m.matches?'dark':'light');
    document.documentElement.setAttribute('data-theme',t);
    document.getElementById('themeToggle').textContent=(t==='dark')?'Light':'Dark';
    return t;
  }
  function toggleTheme(){
    var next=applyTheme()==='dark'?'light':'dark';
    document.documentElement.setAttribute('data-theme',next);
    document.getElementById('themeToggle').textContent=next==='dark'?'Light':'Dark';
    writeTheme(next);
  }
  // ── In-place data refresh (no page reloads — reloads were logging users out) ──
  function escH(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
  function truncH(s,n){s=String(s);return s.length>n?s.slice(0,n)+'...':s;}
  function fmtH(t){if(!t)return'';var d=new Date(t+'Z');return d.toLocaleString('en-US',{month:'short',day:'numeric',hour:'numeric',minute:'2-digit',hour12:true,timeZone:'America/Chicago'});}
  function uaH(ua){
    if(!ua)return'Unknown';
    var b='Other',u=ua;
    if(u.indexOf('Edg/')>=0)b='Edge';else if(u.indexOf('Chrome/')>=0&&u.indexOf('Chromium')<0)b='Chrome';
    else if(u.indexOf('Firefox/')>=0)b='Firefox';else if(u.indexOf('Safari/')>=0&&u.indexOf('Chrome')<0)b='Safari';
    var os='Unknown';
    if(u.indexOf('Windows NT 10')>=0)os='Windows';else if(u.indexOf('Mac OS X')>=0)os='macOS';
    else if(u.indexOf('Android')>=0)os='Android';else if(u.indexOf('iPhone')>=0||u.indexOf('iPad')>=0)os='iOS';
    else if(u.indexOf('Linux')>=0)os='Linux';
    return b+' \u00b7 '+os+' \u00b7 '+((u.indexOf('Mobi')>=0||u.indexOf('Android')>=0||u.indexOf('iPhone')>=0||u.indexOf('iPad')>=0)?'Mobile':'Desktop');
  }
  function flagH(c){if(!c||c.length!==2)return'';var a=0x1F1E6-65+c.toUpperCase().charCodeAt(0),b=0x1F1E6-65+c.toUpperCase().charCodeAt(1);return String.fromCodePoint(a,b);}
  function refLinkH(r,n){return r?'<a href="'+escH(r)+'" rel="noreferrer" style="color:var(--accent);text-decoration:none">'+truncH(escH(r),n)+'</a>':'Direct';}
  function agoH(t){if(!t)return'';var diff=Math.floor((Date.now()-new Date(t+'Z').getTime())/1000);if(diff<0)return'just now';if(diff<60)return diff+'s ago';if(diff<3600)return Math.floor(diff/60)+'m ago';if(diff<86400)return Math.floor(diff/3600)+'h ago';return Math.floor(diff/86400)+'d ago';}
  function devH(v){var d=v.device_type||'Unknown';var o=v.os||'';var b=v.browser||'';var line=[o,b].filter(Boolean).join(' · ');return '<span class="badge">'+escH(d)+'</span>'+(line?' '+escH(line):(v.user_agent?(' '+escH(uaH(v.user_agent))):''));}
  function locH(v){var place=[v.city,v.region,v.country].filter(Boolean).join(', ');if(!place)return '—';return escH(place)+'<div class="identity-note">IP-based estimate · <a href="https://www.google.com/maps/search/?api=1&query='+encodeURIComponent(place)+'" target="_blank" rel="noreferrer">Area map</a></div>';}
  function ispH(v){return v.isp?' <span style="font-size:0.68rem;color:var(--muted)">'+escH(v.isp)+'</span>':'';}
  // ── Search filter state ──
  var _allRecent=[];
  var _allClicks=[];
  function rowHtml(v){
    var vid=v.profile_id||v.visitor_id||'';
    var isNew=(Date.now()-new Date(v.created_at+'Z').getTime())<3600000;
    return '<tr data-vid="'+escH(vid)+'"'+(isNew?' class="new-visit"':'')+'><td><div>'+fmtH(v.created_at)+'</div><div style="font-size:0.7rem;color:var(--muted)">'+agoH(v.created_at)+(isNew?' <span class="badge-new">NEW</span>':'')+'</div></td><td>'+locH(v)+'</td><td style="font-size:0.78rem">'+devH(v)+'</td><td>'+refLinkH(v.referrer,30)+'</td><td><span class="badge" title="Original ID: '+escH(v.visitor_id||'')+'">'+escH(vid.slice(0,8))+'</span></td></tr>';
  }
  function renderRecent(){
    var rt=document.getElementById('recentTbody');
    if(!rt)return;
    var q=(document.getElementById('recentSearch')||{}).value||'';
    q=q.trim().toLowerCase();
    var rv=_allRecent;
    if(q){rv=rv.filter(function(v){
      var hay=[v.city,v.region,v.country,v.device_type,v.os,v.browser,v.isp,v.postal_code,v.visitor_id,v.profile_id,v.referrer].filter(Boolean).join(' ').toLowerCase();
      return hay.indexOf(q)!==-1;
    });}
    rt.innerHTML=rv.length?rv.map(rowHtml).join(''):'<tr><td colspan="5" class="empty-state">No visits match your filter</td></tr>';
  }
  // ── Click detail rows (filled from /stats engagement.clickDetails) ──
  function clickRowHtml(c){
    var vid=c.profile_id||c.visitor_id||'';
    var sec=c.section?escH(truncH(c.section,28)):'—';
    var tgt=c.target?escH(truncH(c.target,40)):'—';
    var link='—';
    if(c.href)link='<a href="'+escH(c.href)+'" target="_blank" rel="noreferrer" style="color:var(--accent);text-decoration:none;font-size:0.72rem">'+truncH(escH(String(c.href).replace(/^https?:\/\//,'')),24)+'</a>';
    var pos=(c.x!=null&&c.y!=null)?c.x+','+c.y:'—';
    return '<tr data-vid="'+escH(vid)+'"><td><div>'+fmtH(c.created_at)+'</div><div style="font-size:0.7rem;color:var(--muted)">'+agoH(c.created_at)+'</div></td><td><span class="badge" title="Original ID: '+escH(c.visitor_id||'')+'">'+escH(vid.slice(0,8))+'</span></td><td>'+locH(c)+'</td><td style="font-size:0.78rem">'+sec+'</td><td style="font-size:0.78rem">'+tgt+'</td><td>'+link+'</td><td style="font-size:0.72rem;color:var(--muted)">'+pos+'</td></tr>';
  }
  function renderClicks(){
    var tb=document.getElementById('clickTbody');
    if(!tb)return;
    tb.innerHTML=_allClicks.length?_allClicks.map(clickRowHtml).join(''):'<tr><td colspan="7" class="empty-state">No click data yet — appears as visitors interact</td></tr>';
  }
  var _dashSig='';
  function refresh(){
    fetch('/stats',{headers:{'Accept':'application/json'}})
      .then(function(r){if(r.status===401){location.href='/dashboard';return null;}return r.json();})
      .then(function(d){
        if(!d)return;
        var g=function(id,v){var el=document.getElementById(id);if(el)el.textContent=v;};
        g('statToday',d.totals.today);g('stat24h',d.totals.last24h);g('statTotal',d.totals.total);g('statUnique',d.totals.unique);
        if(_sd&&d.identityEvents&&((d.identityEvents[0]&&d.identityEvents[0].id)||'')!==_sd.identityRevision){location.reload();return;}
        var rec=d.recent||[],ck=(d.engagement&&d.engagement.clickDetails)||[];
        var refs=d.referrers||[],cc=d.topCountries||[];
        var sig=(rec[0]?rec[0].created_at:'')+'|'+rec.length+'|'+(ck[0]?ck[0].created_at:'')+'|'+ck.length
          +'|'+(refs[0]?refs[0].count:0)+'|'+refs.length+'|'+(cc[0]?cc[0].count:0)+'|'+cc.length;
        if(sig!==_dashSig){
          _dashSig=sig;
          var tr=d.trend||[];
          if(tr.length){
            var mx=Math.max.apply(null,tr.map(function(t){return t.count;}))||1;
            var pts=tr.map(function(t,i){var x=tr.length===1?50:(i/(tr.length-1))*100;return x+','+(40-(t.count/mx)*38);}).join(' ');
            var poly=document.getElementById('trendPoly');if(poly)poly.setAttribute('points','0,40 '+pts+' 100,40');
            var dl=document.getElementById('trendDate');
            if(dl)dl.innerHTML='<span>'+tr[0].date+'</span><span>Peak: '+mx+'</span><span>'+tr[tr.length-1].date+'</span>';
          }
          var ref=document.getElementById('refList');
          if(ref){
            var rx=refs,rmax=Math.max(1,rx.length?rx[0].count:1);
            ref.innerHTML=rx.length?rx.map(function(r){var pct=(r.count/rmax)*100;return '<div class="ref-item"><span class="ref-name">'+escH(r.source)+'</span><div class="ref-bar"><div class="ref-fill" style="width:'+pct+'%"></div></div><span class="ref-count">'+r.count+'</span></div>';}).join(''):'<p class="empty-state">No referrer data</p>';
          }
          var cl=document.getElementById('countryList');
          if(cl){
            cl.innerHTML=cc.map(function(c){return '<span class="country-chip"><strong>'+c.count+'</strong> '+flagH(c.country)+' '+escH(c.country)+'</span>';}).join('');
          }
          _allRecent=rec;
          renderRecent();
          _allClicks=ck;
          renderClicks();
          applyTracked();
          showTrackedAlert();
        }
      })
      .catch(function(){});
  }
  applyTheme();
  var _sd=window.__DASH;
  if(_sd){_allRecent=_sd.recent||[];_allClicks=_sd.clicks||[];renderClicks();
    _dashSig=((_sd.recent&&_sd.recent[0])?_sd.recent[0].created_at:'')+'|'+(_sd.recent?_sd.recent.length:0)
      +'|'+((_sd.clicks&&_sd.clicks[0])?_sd.clicks[0].created_at:'')+'|'+(_sd.clicks?_sd.clicks.length:0)
      +'|'+(_sd.refSig||'0|0')+'|'+(_sd.ccSig||'0|0');
  }
  else{refresh();}
  setInterval(refresh,60000);
  var si=document.getElementById('recentSearch');
  if(si)si.addEventListener('input',renderRecent);

  var identityDialog=document.getElementById('identityDialog');
  var identityState=null;
  function identityProfile(id){return ((_sd&&_sd.profiles)||[]).find(function(p){return p.id===id;});}
  function identitySummary(p){return p?((p.oss||[]).concat(p.browsers||[]).concat(p.cities||[]).filter(Boolean).slice(0,3).join(' · ')||'Unknown device')+' · '+p.visits+' visits · '+p.members.length+' ID'+(p.members.length===1?'':'s'):'No visits';}
  function sharedSignal(a,b,key){return (a[key]||[]).some(function(x){return (b[key]||[]).indexOf(x)>=0;});}
  function identityReview(){
    if(!identityState)return;
    var keep=identityState.source,add=identityState.action==='merge'?document.getElementById('identityTarget').value:identityState.target;
    var left=identityProfile(keep),right=identityProfile(add);
    document.getElementById('identityFrom').textContent=identityState.action==='merge'?keep+'\n'+identitySummary(left):keep;
    document.getElementById('identityTo').textContent=add?add+'\n'+identitySummary(right):'Choose a second profile above';
    if(identityState.action==='merge'){
      var differentCountry=left&&right&&left.countries.length&&right.countries.length&&!sharedSignal(left,right,'countries');
      var differentDevice=left&&right&&left.oss.length&&right.oss.length&&!sharedSignal(left,right,'oss');
      var signal=document.getElementById('identitySignals');
      signal.textContent=!add?'Choose a second profile to compare.':differentCountry&&differentDevice?'Caution: these profiles show different countries and devices. Review visits before combining.':differentCountry?'Caution: the countries differ. Location alone is not proof they are different people.':differentDevice?'Caution: the devices differ. A person may use more than one device.':'Device and location clues can help, but they do not prove two profiles are the same person.';
      signal.classList.toggle('identity-warning',!!(differentCountry||differentDevice));
      document.getElementById('identityOutcome').textContent=left&&right?'After combining: one profile with '+(left.visits+right.visits)+' visits. The visitor count drops by one; original visits and clicks are unchanged. '+(right.members.length>1?'This adds '+right.members.length+' IDs; undo by unlinking each added ID.':'You can undo by clicking Unlink on the added ID.') :'';
      document.getElementById('identityApproval').disabled=!add;
      if(!add)document.getElementById('identityApproval').checked=false;
      document.getElementById('identityConfirm').disabled=!add||!document.getElementById('identityApproval').checked;
    }else document.getElementById('identityConfirm').disabled=false;
  }
  function identityOpen(action,source,target){
    if(!identityDialog)return;
    identityState={action:action,source:source,target:target||''};
    var select=document.getElementById('identityTarget');
    var wrap=document.getElementById('identityTargetWrap');
    var confirm=document.getElementById('identityConfirm');
    var err=document.getElementById('identityError');
    err.hidden=true;err.textContent='';
    document.getElementById('identityApproval').checked=false;
    select.innerHTML='';
    if(action==='merge'){
      wrap.hidden=false;
      var placeholder=document.createElement('option');placeholder.value='';placeholder.textContent='Select a profile to add…';placeholder.disabled=true;placeholder.selected=true;select.appendChild(placeholder);
      ((_sd&&_sd.profiles)||[]).filter(function(p){return p.id!==source;}).forEach(function(p){var o=document.createElement('option');o.value=p.id;o.textContent=p.id.slice(0,10)+' · '+identitySummary(p);select.appendChild(o);});
      document.getElementById('identityDialogTitle').textContent='Are these the same person?';
      document.getElementById('identityDialogDescription').textContent='This profile stays as the main card. Choose a second profile to add only when you recognize both as the same person. To separate people already mixed in one card, use Review visits instead.';
      document.getElementById('identityFromLabel').textContent='Keep this profile';
      document.getElementById('identityToLabel').textContent='Add this profile';
      document.getElementById('identitySignals').hidden=false;
      document.getElementById('identityOutcome').hidden=false;
      document.getElementById('identityApprovalWrap').hidden=false;
      confirm.textContent='Combine into this profile';confirm.disabled=true;
      if(select.options.length===1){err.textContent='There are no other profiles to combine.';err.hidden=false;}
    }else{
      wrap.hidden=true;
      document.getElementById('identityDialogTitle').textContent='Unlink visitor ID';
      document.getElementById('identityDialogDescription').textContent='This only removes a recent profile link. It cannot split older visits that were stored with the same ID; use Review visits for those.';
      document.getElementById('identityFromLabel').textContent='ID to unlink';
      document.getElementById('identityToLabel').textContent='Current profile';
      document.getElementById('identitySignals').hidden=true;
      document.getElementById('identityOutcome').hidden=true;
      document.getElementById('identityApprovalWrap').hidden=true;
      confirm.textContent='Unlink ID';confirm.disabled=false;
    }
    identityReview();identityDialog.showModal();
  }
  if(identityDialog){
    document.getElementById('identityTarget').addEventListener('change',function(){document.getElementById('identityApproval').checked=false;identityReview();});
    document.getElementById('identityApproval').addEventListener('change',identityReview);
    document.getElementById('identityCancel').addEventListener('click',function(){identityDialog.close();});
    document.getElementById('identityConfirm').addEventListener('click',function(){
      if(!identityState)return;
      var confirm=this,err=document.getElementById('identityError');
      var action=identityState.action,keepProfile=identityState.source,addProfile=action==='merge'?document.getElementById('identityTarget').value:identityState.target;
      var url=action==='merge'?'/api/merge-visitors':'/api/unmerge-visitor';
      var payload=action==='merge'?{source:addProfile,target:keepProfile}:{visitorId:keepProfile,canonicalId:addProfile};
      if(action==='merge'&&!document.getElementById('identityApproval').checked)return;
      confirm.disabled=true;confirm.textContent='Saving…';err.hidden=true;
      fetch(url,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
        .then(function(r){return r.json().then(function(d){return{status:r.status,data:d};});})
        .then(function(result){if(result.data&&result.data.ok){location.reload();return;}err.textContent=(result.data&&result.data.message)||('Could not save ('+((result.data&&result.data.error)||result.status)+'). Refresh and try again.');err.hidden=false;confirm.textContent=action==='merge'?'Combine into this profile':'Unlink ID';identityReview();})
        .catch(function(){err.textContent='Network error. Please try again.';err.hidden=false;confirm.textContent=action==='merge'?'Combine into this profile':'Unlink ID';identityReview();});
    });
  }
  document.addEventListener('click',function(e){
    var merge=e.target.closest('.profile-merge');
    if(merge){e.preventDefault();identityOpen('merge',merge.getAttribute('data-vid'));return;}
    var separate=e.target.closest('.profile-separate');
    if(separate){e.preventDefault();identityOpen('separate',separate.getAttribute('data-member'),separate.getAttribute('data-canonical'));}
  });

  var visitDialog=document.getElementById('visitDialog'),visitProfile='',visitRows=[],selectedVisit=null;
  function visitError(message){var el=document.getElementById('visitError');el.textContent=message;el.hidden=false;}
  function visitRowLabel(v){return (v.city||v.region||v.country||'Unknown area')+' · '+(v.os||v.device_type||'Unknown device')+' · '+(v.browser||'Unknown browser');}
  function renderVisitList(){
    var list=document.getElementById('visitList');
    list.innerHTML=visitRows.length?visitRows.map(function(v){return '<div class="visit-item"><div><strong>'+escH(visitRowLabel(v))+'</strong><small>'+escH(fmtH(v.created_at))+' · '+escH(v.isp||'Unknown network')+(v.network_signal?' · network '+escH(v.network_signal):'')+'</small><small>Visit #'+v.id+(v.override_id?' · moved from original ID '+escH(v.original_id.slice(0,10)):'')+'</small></div><button type="button" class="'+(v.override_id?'visit-restore':'visit-select')+'" data-view-id="'+v.id+'">'+(v.override_id?'Undo move':'Move visit')+'</button></div>';}).join(''):'<p class="identity-note">No visits found in this profile.</p>';
  }
  function openVisitDialog(profile){
    if(!visitDialog)return;
    visitProfile=profile;visitRows=[];selectedVisit=null;
    document.getElementById('visitDialogTitle').textContent='Review visits · '+profile.slice(0,10);
    document.getElementById('visitList').innerHTML='<p class="identity-note">Loading visits…</p>';
    document.getElementById('visitEditor').hidden=true;
    document.getElementById('visitError').hidden=true;
    visitDialog.showModal();
    fetch('/api/profile-visits?profile='+encodeURIComponent(profile),{credentials:'same-origin'})
      .then(function(r){if(!r.ok)throw Error('Could not load visits ('+r.status+').');return r.json();})
      .then(function(d){visitRows=d.visits||[];renderVisitList();if(d.hasMore)visitError('Showing the latest 100 visits only.');})
      .catch(function(err){visitError(err.message||'Could not load visits.');document.getElementById('visitList').innerHTML='';});
  }
  if(visitDialog){
    document.getElementById('visitClose').addEventListener('click',function(){visitDialog.close();});
    document.getElementById('visitCancelMove').addEventListener('click',function(){document.getElementById('visitEditor').hidden=true;selectedVisit=null;});
    document.getElementById('visitList').addEventListener('click',function(e){
      var button=e.target.closest('button[data-view-id]');if(!button)return;
      var id=Number(button.getAttribute('data-view-id'));
      var visit=visitRows.find(function(v){return v.id===id;});if(!visit)return;
      var err=document.getElementById('visitError');err.hidden=true;
      if(button.classList.contains('visit-restore')){
        button.disabled=true;button.textContent='Restoring…';
        fetch('/api/restore-visit',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({viewId:id,profileId:visitProfile})})
          .then(function(r){return r.json();}).then(function(d){if(d.ok){location.reload();return;}visitError(d.message||'Could not undo the move. Refresh and try again.');button.disabled=false;button.textContent='Undo move';})
          .catch(function(){visitError('Network error. Please try again.');button.disabled=false;button.textContent='Undo move';});
        return;
      }
      selectedVisit=visit;
      document.getElementById('visitSelected').textContent='Move visit #'+id+' · '+visitRowLabel(visit)+' · '+fmtH(visit.created_at);
      var select=document.getElementById('visitDestination');select.innerHTML='';
      var fresh=document.createElement('option');fresh.value='new';fresh.textContent='Create a new separate profile';select.appendChild(fresh);
      ((_sd&&_sd.profiles)||[]).filter(function(p){return p.id!==visitProfile;}).forEach(function(p){var o=document.createElement('option');o.value=p.id;o.textContent='Existing: '+p.id.slice(0,10)+' · '+identitySummary(p);select.appendChild(o);});
      document.getElementById('visitEditor').hidden=false;
    });
    document.getElementById('visitConfirmMove').addEventListener('click',function(){
      if(!selectedVisit)return;
      var button=this;button.disabled=true;button.textContent='Moving…';
      fetch('/api/move-visit',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({viewId:selectedVisit.id,fromProfile:visitProfile,targetProfile:document.getElementById('visitDestination').value})})
        .then(function(r){return r.json();}).then(function(d){if(d.ok){location.reload();return;}visitError(d.message||'Could not move this visit. Refresh and try again.');button.disabled=false;button.textContent='Move visit';})
        .catch(function(){visitError('Network error. Please try again.');button.disabled=false;button.textContent='Move visit';});
    });
  }
  document.addEventListener('click',function(e){var button=e.target.closest('.profile-review');if(button){e.preventDefault();openVisitDialog(button.getAttribute('data-vid'));}});

  // ── Reset engagement data (clicks, heartbeats, sessions) ──
  document.addEventListener('click',function(e){
    var btn=e.target.closest('.reset-eng');
    if(!btn)return;
    e.preventDefault();e.stopPropagation();
    if(!confirm('Delete ALL click and session tracking data? This cannot be undone.'))return;
    btn.disabled=true;btn.textContent='Resetting…';
    fetch('/api/reset-engagement',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'}})
      .then(function(r){return r.json().catch(function(){return{ok:false}});})
      .then(function(d){
        if(d&&d.ok){location.reload();}
        else{alert('Reset failed: '+(d&&d.error||'unknown'));btn.disabled=false;btn.textContent='Reset';}
      })
      .catch(function(){alert('Network error');btn.disabled=false;btn.textContent='Reset';});
  });

  // ── Visitor tracking (localStorage, no backend) ──
  var TRACK_KEY='dash-tracked';
  function getTracked(){try{var v=localStorage.getItem(TRACK_KEY);return v?JSON.parse(v):[];}catch(e){return[];}}
  function saveTracked(arr){try{localStorage.setItem(TRACK_KEY,JSON.stringify(arr));}catch(e){}}

  // Apply tracked styles to profile cards and recent visit rows
  function applyTracked(){
    var t=getTracked();
    // Profile cards
    document.querySelectorAll('.profile-card').forEach(function(c){
      var vid=c.getAttribute('data-vid');
      var btn=c.querySelector('.track-btn');
      if(t.indexOf(vid)>=0){c.classList.add('tracked');if(btn)btn.textContent='★ Tracked';}
      else{if(btn)btn.textContent='☆ Track';}
    });
    // Recent visit rows
    document.querySelectorAll('tr[data-vid]').forEach(function(r){
      if(t.indexOf(r.getAttribute('data-vid'))>=0)r.classList.add('tracked-visit');
    });
  }

  // Pin tracked cards to the top of the grid
  function pinTracked(){
    var grid=document.getElementById('profileGrid');
    if(!grid)return;
    var t=getTracked();
    var cards=Array.from(grid.querySelectorAll('.profile-card'));
    cards.sort(function(a,b){
      var aT=t.indexOf(a.getAttribute('data-vid'))>=0?0:1;
      var bT=t.indexOf(b.getAttribute('data-vid'))>=0?0:1;
      return aT-bT;
    });
    cards.forEach(function(c){grid.appendChild(c);});
  }

  // Golden alert banner when a tracked visitor has been active in the last 24h
  function showTrackedAlert(){
    var el=document.getElementById('trackedAlert');
    if(!el)return;
    var t=getTracked();
    if(!t.length){el.hidden=true;return;}
    var now=Date.now(),WIN=24*3600000,best=null;
    document.querySelectorAll('.profile-card[data-vid][data-lastseen]').forEach(function(c){
      var vid=c.getAttribute('data-vid');
      if(t.indexOf(vid)<0)return;
      var ls=new Date(c.getAttribute('data-lastseen')+'Z').getTime();
      if(isNaN(ls))return;
      var age=now-ls;
      if(age>=0&&age<WIN&&(!best||ls>best.ls)){
        best={ls:ls,vid:vid,name:(c.querySelector('.profile-name')||{}).textContent||vid.slice(0,8)};
      }
    });
    if(best){
      var mins=Math.floor((now-best.ls)/60000);
      var when=mins<1?'just now':mins<60?mins+'m ago':Math.floor(mins/60)+'h ago';
      el.innerHTML='<span style="font-size:1.15rem;line-height:1">★</span> <span><strong>'+escH(best.name)+'</strong> visited '+when+'</span><button type="button" onclick="this.parentNode.hidden=true" title="Dismiss" style="margin-left:auto;background:none;border:none;color:inherit;font-size:1.1rem;cursor:pointer;line-height:1">&times;</button>';
      el.hidden=false;
    }else{el.hidden=true;}
  }

  // Click handler for track buttons
  document.addEventListener('click',function(e){
    var btn=e.target.closest('.track-btn');
    if(!btn)return;
    var vid=btn.getAttribute('data-vid');
    if(!vid)return;
    var t=getTracked();
    var idx=t.indexOf(vid);
    if(idx>=0){t.splice(idx,1);btn.textContent='☆ Track';}else{t.push(vid);btn.textContent='★ Tracked';}
    saveTracked(t);
    applyTracked();
    pinTracked();
    showTrackedAlert();
  });

  // On load: apply tracking, pin tracked cards to top, show any recent-visit alert
  applyTracked();
  pinTracked();
  showTrackedAlert();

`;

function dashboardHtml(totals, countries, visits, trend, referrers, engagement, profiles, identityEvents) {
  const trendMax = Math.max(1, ...trend.map(t => t.count));
  const trendPoints = trend.length ? trend.map((t, i) => {
    const x = (trend.length === 1) ? 50 : (i / (trend.length - 1)) * 100;
    const y = 40 - (t.count / trendMax) * 38;
    return x + ',' + y;
  }).join(' ') : '';
  const trendPoly = trendPoints ? '0,40 ' + trendPoints + ' 100,40' : '';
  const refMax = Math.max(1, ...referrers.map(r => r.count));
  const trendEmpty = trend.length === 0;
  const referrerRows = referrers.length ? referrers.map(r => {
    const pct = (r.count / refMax) * 100;
    return '<div class="ref-item"><span class="ref-name">' + esc(r.source) + '</span>'
      + '<div class="ref-bar"><div class="ref-fill" style="width:' + pct + '%"></div></div>'
      + '<span class="ref-count">' + r.count + '</span></div>';
  }).join('') : '<p class="empty-state">No referrer data</p>';

  // Engagement stat cards — always visible (show zeros when there's no data yet)
  var eng = engagement || {};
  var topClicks = eng.topClicks || [];
  var engagementHtml = '<div class="stats" style="margin-bottom:1.5rem">'
    + '<div class="stat-card"><div class="stat-icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div><div class="stat-value" id="statSessions">' + (eng.sessions || 0) + '</div><div class="stat-label">Sessions Tracked</div></div>'
    + '<div class="stat-card"><div class="stat-icon"><svg viewBox="0 0 24 24"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg></div><div class="stat-value" id="statAvg">' + fmtDur(eng.avgDurationSec || 0) + '</div><div class="stat-label">Avg. Time on Page</div></div>'
    + '<div class="stat-card"><div class="stat-icon"><svg viewBox="0 0 24 24"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg></div><div class="stat-value" id="statClicks">' + topClicks.length + '</div><div class="stat-label">Most-Clicked</div></div>'
    + '<div class="stat-card" style="display:flex;flex-direction:column;justify-content:center"><div class="stat-label" style="margin-bottom:0.4rem">Recent clicks</div><div style="font-size:0.8rem;color:var(--muted);line-height:1.5">' + (topClicks.slice(0, 3).map(function(c){ return esc(c.target) + ' <strong>' + c.count + '</strong>'; }).join(' &middot; ') || '—') + '</div><button class="reset-eng" type="button" title="Delete all click &amp; session tracking data">Reset</button></div>'
    + '</div>';

  // Server-known data seeded inline (slim) so the client can skip the on-load /stats re-fetch
  const refSig = ((referrers && referrers[0] && referrers[0].count) || 0) + '|' + (referrers ? referrers.length : 0);
  const ccSig = ((countries && countries[0] && countries[0].count) || 0) + '|' + (countries ? countries.length : 0);
  const dashSeed = JSON.stringify({
    recent: visits.map(v => ({ created_at: v.created_at, city: v.city, region: v.region, country: v.country,
      referrer: v.referrer, visitor_id: v.visitor_id, profile_id: v.profile_id, device_type: v.device_type, os: v.os, browser: v.browser,
      isp: v.isp, postal_code: v.postal_code, latitude: v.latitude, longitude: v.longitude })),
    clicks: (engagement && engagement.clickDetails) || [],
    profiles: profiles.map(p => ({ id: p.id, visits: p.visits, members: p.members, cities: p.cities, countries: p.countries, devices: p.devices, oss: p.oss, browsers: p.browsers })),
    identityRevision: identityEvents?.[0]?.id || '',
    refSig: refSig, ccSig: ccSig
  }).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');

  const recentRows = visits.map(v => {
    const ago = timeAgo(v.created_at);
    const recent = (Date.now() - new Date(v.created_at + 'Z').getTime()) < 3600000; // within last hour
    const loc = [v.city, v.region, v.country].filter(Boolean).join(', ') || 'Unknown';
    const os = esc(v.os || '');
    const browser = esc(v.browser || '');
    const dev = esc(v.device_type || '');
    const vid = v.profile_id || v.visitor_id || '';
    return '<tr data-vid="' + esc(vid) + '"' + (recent ? ' class="new-visit"' : '') + '>'
      + '<td><div>' + formatTime(v.created_at) + '</div><div style="font-size:0.7rem;color:var(--muted)">' + ago + (recent ? ' <span class="badge-new">NEW</span>' : '') + '</div></td>'
      + '<td>' + esc(loc) + coordH(v) + '</td>'
      + '<td style="font-size:0.78rem">' + (dev ? '<span class="badge">' + dev + '</span> ' : '') + ' ' + esc([os, browser].filter(Boolean).join(' · ') || '—') + '</td>'
      + '<td>' + (v.referrer
        ? '<a href="' + esc(v.referrer) + '" rel="noreferrer" style="color:var(--accent);text-decoration:none">' + truncate(esc(v.referrer), 30) + '</a>'
        : 'Direct') + '</td>'
      + '<td><span class="badge" title="Original ID: ' + esc(v.visitor_id || '') + '">' + esc(vid.slice(0, 8)) + '</span></td></tr>';
  }).join('');
  const countryChips = countries.length ? countries.map(c =>
    '<span class="country-chip"><strong>' + c.count + '</strong> ' + flag(c.country) + ' ' + esc(c.country) + '</span>'
  ).join('') : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Page View Dashboard</title>
<meta name="robots" content="noindex, nofollow">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='80' font-size='80' text-anchor='middle' x='50'%3E📊%3C/text%3E%3C/svg%3E">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'">
<style>
  *,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
  :root{--bg:#eef0f6;--text:#1d1d1f;--muted:#6e6e73;--dim:#1d1d1f;
    --border:rgba(255,255,255,0.55);--border-soft:rgba(20,24,32,0.07);
    --accent:#0071e3;--accent-soft:rgba(0,113,227,0.10);
    --glass-bg:linear-gradient(150deg,rgba(255,255,255,0.85) 0%,rgba(255,255,255,0.45) 45%,rgba(255,255,255,0.18) 100%);
    --glass-edge:linear-gradient(160deg,rgba(255,255,255,0.95) 0%,rgba(255,255,255,0.0) 30%,rgba(255,255,255,0.0) 75%,rgba(255,255,255,0.55) 100%);
    --glass-inner:radial-gradient(120% 80% at 0% 0%,rgba(255,255,255,0.8) 0%,rgba(255,255,255,0.0) 50%);
    --glass-shadow:0 22px 70px -10px rgba(0,80,180,0.18),0 4px 16px -4px rgba(20,24,32,0.08),inset 0 1px 0 rgba(255,255,255,0.85),inset 0 -1px 0 rgba(255,255,255,0.25),inset 0 0 1px 1px rgba(255,255,255,0.4);
    --pill-shadow:0 2px 8px rgba(20,24,32,0.06),inset 0 1px 0 rgba(255,255,255,0.8),inset 0 -1px 0 rgba(0,0,0,0.04);
    --specular:linear-gradient(115deg,rgba(255,255,255,0.7) 0%,rgba(255,255,255,0.12) 18%,transparent 40%,rgba(255,255,255,0.0) 60%,rgba(255,255,255,0.18) 82%,rgba(255,255,255,0.0) 100%);
    --accent-shadow:0 8px 24px rgba(0,113,227,0.20);
    --radius:28px;--radius-md:22px;--radius-sm:16px}
  html[data-theme="dark"]{--bg:#0c0e14;--text:#f5f5f7;--muted:#a1a1a6;--dim:#e5e5ea;
    --border:rgba(255,255,255,0.16);--border-soft:rgba(255,255,255,0.08);--accent:#2997ff;--accent-soft:rgba(41,151,255,0.18);
    --glass-bg:linear-gradient(150deg,rgba(70,80,110,0.5) 0%,rgba(30,34,44,0.35) 50%,rgba(20,22,30,0.2) 100%);
    --glass-edge:linear-gradient(160deg,rgba(180,200,255,0.25) 0%,rgba(255,255,255,0.0) 35%,rgba(255,255,255,0.0) 70%,rgba(180,200,255,0.18) 100%);
    --glass-inner:radial-gradient(120% 80% at 0% 0%,rgba(160,180,255,0.25) 0%,rgba(255,255,255,0.0) 55%);
    --glass-shadow:0 22px 70px -10px rgba(0,0,0,0.55),0 4px 16px -4px rgba(0,0,0,0.3),inset 0 1px 0 rgba(255,255,255,0.16),inset 0 -1px 0 rgba(0,0,0,0.4),inset 0 0 1px 1px rgba(255,255,255,0.08);
    --pill-shadow:0 2px 8px rgba(0,0,0,0.4),inset 0 1px 0 rgba(255,255,255,0.16),inset 0 -1px 0 rgba(0,0,0,0.4);
    --specular:linear-gradient(115deg,rgba(255,255,255,0.22) 0%,rgba(255,255,255,0.04) 18%,transparent 40%,transparent 60%,rgba(255,255,255,0.06) 82%,transparent 100%);
    --accent-shadow:0 8px 24px rgba(41,151,255,0.25)}
  body{font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text','SF Pro Display','Segoe UI',system-ui,sans-serif;
    background:var(--bg);color:var(--text);padding:2rem 1.25rem;min-height:100vh;
    transition:background 0.4s,color 0.4s;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
  body::before,body::after,body>.aurora-layer{content:'';position:fixed;inset:-30%;z-index:-2;pointer-events:none}
  body::before{
    background:
      radial-gradient(750px 550px at 10% 5%,rgba(99,157,255,0.55) 0%,rgba(99,157,255,0.18) 30%,transparent 55%),
      radial-gradient(850px 600px at 88% 8%,rgba(167,119,255,0.5) 0%,rgba(167,119,255,0.15) 30%,transparent 52%),
      radial-gradient(950px 650px at 45% 92%,rgba(56,217,169,0.45) 0%,rgba(56,217,169,0.12) 30%,transparent 50%),
      radial-gradient(650px 480px at 25% 55%,rgba(255,138,199,0.4) 0%,rgba(255,138,199,0.1) 30%,transparent 48%),
      linear-gradient(160deg,#f0f4ff 0%,#eef0fa 100%);
    animation:none;filter:blur(30px)}
  body::after{
    background:radial-gradient(55% 35% at 50% 0%,rgba(255,255,255,0.7) 0%,transparent 65%);
    animation:none;mix-blend-mode:overlay;filter:none}
  body>.aurora-layer{
    background:
      radial-gradient(500px 400px at 70% 30%,rgba(120,180,255,0.35) 0%,transparent 60%),
      radial-gradient(450px 380px at 15% 75%,rgba(180,140,255,0.3) 0%,transparent 55%);
    animation:none;mix-blend-mode:screen;filter:blur(40px)}
  html[data-theme="dark"] body>.aurora-layer{
    background:
      radial-gradient(500px 400px at 70% 30%,rgba(60,120,220,0.3) 0%,transparent 60%),
      radial-gradient(450px 380px at 15% 75%,rgba(120,80,200,0.25) 0%,transparent 55%);
    mix-blend-mode:screen}
  html[data-theme="dark"] body::before{
    background:
      radial-gradient(750px 550px at 10% 5%,rgba(40,100,220,0.4) 0%,rgba(40,100,220,0.12) 30%,transparent 55%),
      radial-gradient(850px 600px at 88% 8%,rgba(110,60,220,0.38) 0%,rgba(110,60,220,0.1) 30%,transparent 52%),
      radial-gradient(950px 650px at 45% 92%,rgba(20,160,100,0.32) 0%,rgba(20,160,100,0.08) 30%,transparent 50%),
      radial-gradient(650px 480px at 25% 55%,rgba(200,50,120,0.28) 0%,rgba(200,50,120,0.08) 30%,transparent 48%),
      linear-gradient(160deg,#0a0d16 0%,#0c0f1a 100%)}
  html[data-theme="dark"] body::after{background:radial-gradient(55% 35% at 50% 0%,rgba(100,150,255,0.18) 0%,transparent 65%);mix-blend-mode:screen}
  @keyframes aurora{0%{transform:translate3d(0,0,0) scale(1)}100%{transform:translate3d(-3%,2%,0) scale(1.04)}}
  @keyframes aurora-glow{0%{opacity:0.5;transform:translate3d(0,0,0)}100%{opacity:0.9;transform:translate3d(2%,-2%,0)}}
  @keyframes aurora-2{0%{transform:translate3d(0,0,0) scale(1)}100%{transform:translate3d(2%,-3%,0) scale(1.06)}}
  @keyframes glass-morph{0%{border-radius:var(--radius)}50%{border-radius:calc(var(--radius) + 4px)}100%{border-radius:var(--radius)}}
  @keyframes fadeInUp{0%{opacity:0;transform:translateY(8px) scale(0.998)}50%{opacity:1}100%{opacity:1;transform:translateY(0) scale(1)}}
  .stat-card>*,.card>*,.top-bar>*{position:relative;z-index:1}
  .stat-card::after,.card::after,.top-bar::after{z-index:0}
  .container{max-width:1000px;margin:0 auto}
  .top-bar{position:sticky;top:0.75rem;z-index:20;display:flex;justify-content:space-between;align-items:center;
    flex-wrap:wrap;gap:1rem;padding:1.15rem 1.5rem;margin-bottom:1.75rem;border-radius:var(--radius);overflow:hidden;
    background:var(--glass-bg);backdrop-filter:blur(28px) saturate(180%);-webkit-backdrop-filter:blur(28px) saturate(180%);
    border:1px solid var(--border);box-shadow:var(--glass-shadow)}
  .top-bar::after{content:'';position:absolute;inset:0;border-radius:inherit;pointer-events:none;background:var(--specular);mix-blend-mode:screen}
  .top-bar::before{content:'';position:absolute;inset:0;border-radius:inherit;pointer-events:none;background:var(--glass-inner);opacity:0.6}
  h1{font-size:2rem;font-weight:700;letter-spacing:-0.025em;line-height:1.1;
    background:linear-gradient(115deg,var(--text) 35%,var(--muted));
    -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
  .subtitle{color:var(--muted);margin-top:0.3rem;font-size:0.9rem}
  .top-actions{display:flex;align-items:center;gap:0.5rem}
  .theme-toggle,.logout{background:var(--glass-bg);color:var(--text);font-size:0.8rem;text-decoration:none;
    padding:0.45rem 1.1rem;border-radius:980px;border:1px solid var(--border);cursor:pointer;font-family:inherit;
    font-weight:600;letter-spacing:0.01em;transition:transform 0.25s cubic-bezier(.22,.61,.36,1),color 0.2s,border-color 0.2s,box-shadow 0.2s;
    box-shadow:var(--pill-shadow);backdrop-filter:blur(16px) saturate(180%);-webkit-backdrop-filter:blur(16px) saturate(180%)}
  .theme-toggle:hover,.logout:hover{color:var(--accent);border-color:var(--accent);transform:translateY(-1px);box-shadow:0 0 0 3px var(--accent-soft),inset 0 1px 0 rgba(255,255,255,0.9)}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:1.5rem}
  .stat-card{position:relative;overflow:hidden;background:var(--glass-bg);padding:1.4rem 1.5rem;border-radius:var(--radius);
    box-shadow:var(--glass-shadow);border:1px solid var(--border);
    backdrop-filter:blur(28px) saturate(180%);-webkit-backdrop-filter:blur(28px) saturate(180%);
    transition:transform 0.3s cubic-bezier(.22,.61,.36,1),box-shadow 0.3s;    animation:fadeInUp 0.3s cubic-bezier(.22,.61,.36,1) both}
  .stat-card::before{content:'';position:absolute;inset:0;border-radius:inherit;pointer-events:none;background:var(--glass-inner);opacity:0.7}
  .stat-card::after{content:'';position:absolute;inset:0;border-radius:inherit;pointer-events:none;background:var(--specular);mix-blend-mode:screen}
  .stat-card:hover{transform:translateY(-4px);box-shadow:0 28px 70px -12px rgba(0,80,180,0.22),0 6px 20px -6px rgba(20,24,32,0.1),inset 0 1px 0 rgba(255,255,255,0.9)}
  html[data-theme="dark"] .stat-card:hover{box-shadow:0 28px 70px -10px rgba(0,0,0,0.6),inset 0 0 20px rgba(41,151,255,0.08),inset 0 1px 0 rgba(255,255,255,0.18)}
  .stat-icon{width:34px;height:34px;border-radius:10px;display:flex;align-items:center;justify-content:center;
    background:var(--accent-soft);color:var(--accent);margin-bottom:0.9rem}
  .stat-icon svg{width:17px;height:17px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
  .stat-value{font-size:2.2rem;font-weight:700;letter-spacing:-0.03em;color:var(--text);font-variant-numeric:tabular-nums}
  .stat-label{font-size:0.7rem;color:var(--dim);text-transform:uppercase;letter-spacing:0.08em;margin-top:0.3rem;font-weight:700}
  .grid-2{display:grid;grid-template-columns:1.4fr 1fr;gap:1rem;margin-bottom:1.5rem}
  @media(max-width:768px){.grid-2{grid-template-columns:1fr}}
  .card{position:relative;overflow:hidden;background:var(--glass-bg);border-radius:var(--radius);padding:1.5rem;box-shadow:var(--glass-shadow);
    margin-bottom:1.5rem;border:1px solid var(--border);
    backdrop-filter:blur(28px) saturate(180%);-webkit-backdrop-filter:blur(28px) saturate(180%)}
  .card, .profile-card{content-visibility:auto;contain-intrinsic-size:auto 320px}
  .card::before{content:'';position:absolute;inset:0;border-radius:inherit;pointer-events:none;background:var(--glass-inner);opacity:0.7}
  .card::after{content:'';position:absolute;inset:0;border-radius:inherit;pointer-events:none;background:var(--specular);mix-blend-mode:screen}
  html[data-theme="dark"] .card{background:var(--glass-bg)}
  h2{font-size:1.05rem;font-weight:700;margin-bottom:1rem;letter-spacing:-0.012em}
  .card-head{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin-bottom:1rem;flex-wrap:wrap}
  .card-head h2{margin-bottom:0}
  .trend-wrap{position:relative;padding-top:0.5rem}
  svg.trend{width:100%;height:60px;display:block}
  .trend-poly{fill:rgba(0,113,227,0.10);stroke:var(--accent);stroke-width:2.5;stroke-linejoin:round;stroke-linecap:round}
  html[data-theme="dark"] .trend-poly{fill:rgba(41,151,255,0.12)}
  .trend-date{font-size:0.7rem;color:var(--muted);display:flex;justify-content:space-between;margin-top:0.5rem}
  .ref-item{display:flex;justify-content:space-between;align-items:center;padding:0.6rem 0;border-bottom:1px solid var(--border-soft)}
  .ref-item:last-child{border-bottom:none}
  .ref-name{font-size:0.85rem;font-weight:500;max-width:40%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;letter-spacing:0.01em}
  .ref-bar{flex:1;margin:0 1rem;height:6px;background:rgba(0,0,0,0.06);border-radius:3px;overflow:hidden}
  html[data-theme="dark"] .ref-bar{background:rgba(255,255,255,0.08)}
  .ref-fill{height:100%;background:linear-gradient(90deg,var(--accent),#5ac8fa);border-radius:3px;transition:width 0.4s ease}
  .ref-count{font-size:0.8rem;color:var(--muted);font-weight:700;min-width:2.5rem;text-align:right;font-variant-numeric:tabular-nums}
  .country-list{display:flex;flex-wrap:wrap;gap:0.5rem}
  .country-chip{background:var(--glass-bg);padding:0.5rem 1rem;border-radius:20px;font-size:0.85rem;box-shadow:var(--pill-shadow);
    border:1px solid var(--border);backdrop-filter:blur(12px) saturate(180%);-webkit-backdrop-filter:blur(12px) saturate(180%);font-weight:500}
  .country-chip strong{color:var(--accent);font-weight:700}
  .table-wrap{background:var(--glass-bg);border-radius:var(--radius);overflow:hidden;box-shadow:var(--glass-shadow);border:1px solid var(--border);
    backdrop-filter:blur(28px) saturate(180%);-webkit-backdrop-filter:blur(28px) saturate(180%)}
  table{width:100%;border-collapse:collapse;border-radius:var(--radius)}
  th,td{padding:11px 14px;text-align:left;font-size:0.82rem;white-space:nowrap;letter-spacing:0.01em}
  th{background:rgba(0,113,227,0.06);font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:0.05em;font-size:0.68rem}
  html[data-theme="dark"] th{background:rgba(41,151,255,0.10)}
  td{border-bottom:1px solid var(--border-soft);font-weight:500;font-variant-numeric:tabular-nums}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:rgba(0,113,227,0.05)}
  html[data-theme="dark"] tr:hover td{background:rgba(41,151,255,0.08)}
  .badge{display:inline-block;padding:3px 9px;border-radius:8px;font-size:0.68rem;font-weight:700;letter-spacing:0.02em;background:rgba(46,125,50,0.12);color:#2e7d32}
  html[data-theme="dark"] .badge{background:rgba(129,199,132,0.16);color:#81c784}
  .badge-new{display:inline-block;padding:2px 6px;border-radius:6px;font-size:0.6rem;font-weight:700;letter-spacing:0.04em;text-transform:uppercase;background:rgba(46,125,50,0.18);color:#2e7d32;margin-left:6px;animation:pulse-new 2s ease-in-out infinite}
  @keyframes pulse-new{0%,100%{opacity:1}50%{opacity:0.5}}
  .new-visit td{background:rgba(46,125,50,0.04)}
  html[data-theme="dark"] .new-visit td{background:rgba(76,175,80,0.06)}
  .profile-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:1rem;margin-top:0.5rem}
  .profile-card{position:relative;background:linear-gradient(150deg,rgba(255,255,255,0.6),rgba(255,255,255,0.25));border:1px solid var(--border);border-radius:var(--radius-md);padding:1.1rem;box-shadow:inset 0 1px 0 rgba(255,255,255,0.6);transition:transform 0.2s,box-shadow 0.2s}
  .profile-card:hover{transform:translateY(-2px);box-shadow:inset 0 1px 0 rgba(255,255,255,0.7),0 8px 24px rgba(0,80,180,0.12)}
  .profile-head{display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem}
  .profile-icon{font-size:1.3rem;flex-shrink:0}
  .profile-name{font-size:0.82rem;font-weight:700;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .prob{font-size:0.6rem;padding:2px 6px;border-radius:8px;font-weight:600;text-transform:uppercase;letter-spacing:0.03em}
  .prob-high{background:rgba(46,125,50,0.15);color:#2e7d32}
  .prob-med{background:rgba(245,124,0,0.15);color:#e65100}
  .prob-low{background:rgba(117,117,117,0.15);color:#616161}
  .profile-visits{font-size:1.4rem;font-weight:700;color:var(--text);margin-bottom:0.3rem}
  .profile-visits strong{font-variant-numeric:tabular-nums}
  .profile-loc{font-size:0.78rem;color:var(--accent);margin-bottom:0.4rem}
  .profile-meta{font-size:0.68rem;color:var(--muted);line-height:1.5;word-break:break-word}
  .profile-meta br{content:'';display:block;margin-top:2px}
  .profile-actions{display:flex;flex-wrap:wrap;gap:0.4rem;margin-top:0.7rem}
  .profile-merge{font-size:0.68rem;padding:3px 10px;border-radius:8px;border:1px solid var(--border);background:rgba(255,255,255,0.5);cursor:pointer;font-weight:500;transition:all 0.15s;color:var(--text)}
  .profile-merge:hover{border-color:var(--accent);color:var(--accent);background:rgba(0,113,227,0.08)}
  .profile-review{font-size:0.68rem;padding:3px 10px;border-radius:8px;border:1px solid var(--accent);background:var(--accent-soft);cursor:pointer;font-weight:700;color:var(--accent)}
  .profile-review:hover{filter:brightness(.9)}
  .prob-review{background:rgba(245,158,11,.16);color:#995000}
  html[data-theme="dark"] .prob-review{color:#ffd18a}
  html[data-theme="dark"] .profile-card{background:linear-gradient(150deg,rgba(50,58,78,0.5),rgba(28,31,38,0.35))}
  html[data-theme="dark"] .profile-merge{background:rgba(255,255,255,0.06)}
  .track-btn{font-size:0.68rem;padding:3px 10px;border-radius:8px;border:1px solid var(--border);background:rgba(255,255,255,0.5);cursor:pointer;font-weight:500;transition:all 0.15s;color:var(--text)}
  .track-btn:hover{border-color:#f59e0b;color:#b45309;background:rgba(245,158,11,0.1)}
  .reset-eng{align-self:flex-start;margin-top:0.5rem;font-size:0.66rem;padding:3px 10px;border-radius:8px;border:1px solid rgba(211,47,47,0.4);background:rgba(211,47,47,0.06);cursor:pointer;font-weight:600;letter-spacing:0.03em;color:#c62828;transition:all 0.15s}
  .reset-eng:hover{background:rgba(211,47,47,0.12);border-color:#c62828}
  html[data-theme="dark"] .reset-eng{color:#ef9a9a;border-color:rgba(239,154,154,0.4);background:rgba(211,47,47,0.15)}
  html[data-theme="dark"] .reset-eng:hover{background:rgba(211,47,47,0.25)}
  .profile-card.tracked{border:2px solid #f59e0b;box-shadow:inset 0 1px 0 rgba(255,255,255,0.7),0 0 24px rgba(245,158,11,0.15),0 8px 32px rgba(0,0,0,0.08)}
  .profile-card.tracked .track-btn{background:rgba(245,158,11,0.15);color:#b45309;border-color:#f59e0b}
  html[data-theme="dark"] .profile-card.tracked{border-color:#fbbf24;box-shadow:inset 0 1px 0 rgba(255,255,255,0.12),0 0 24px rgba(251,191,36,0.18)}
  html[data-theme="dark"] .profile-card.tracked .track-btn{background:rgba(251,191,36,0.2);color:#fde68a;border-color:#fbbf24}
  .tracked-alert{display:flex;align-items:center;gap:0.6rem;margin:0 0 1rem;padding:0.75rem 1rem;border-radius:var(--radius-sm);
    background:linear-gradient(150deg,rgba(245,158,11,0.16),rgba(251,191,36,0.08));border:1px solid rgba(245,158,11,0.5);
    box-shadow:0 0 24px rgba(245,158,11,0.18),inset 0 1px 0 rgba(255,255,255,0.4);
    backdrop-filter:blur(30px) saturate(200%);-webkit-backdrop-filter:blur(30px) saturate(200%);
    font-size:0.85rem;font-weight:600;color:#92400e;animation:pulse-new 3s ease-in-out infinite}
  html[data-theme="dark"] .tracked-alert{color:#fde68a;background:linear-gradient(150deg,rgba(251,191,36,0.18),rgba(251,191,36,0.06))}
  .tracked-alert[hidden]{display:none}
  tr.tracked-visit td{background:rgba(245,158,11,0.06)}
  html[data-theme="dark"] tr.tracked-visit td{background:rgba(251,191,36,0.08)}
  .tracked-section h2::after{content:' ⚡ Tracked';font-size:0.7rem;color:#f59e0b;font-weight:600;vertical-align:middle}
  html[data-theme="dark"] .tracked-section h2::after{color:#fbbf24}
  html[data-theme="dark"] .prob-high{background:rgba(76,175,80,0.2);color:#81c784}
  html[data-theme="dark"] .prob-med{background:rgba(255,152,0,0.2);color:#ffb74d}
  html[data-theme="dark"] .prob-low{background:rgba(158,158,158,0.2);color:#bdbdbd}
  .table-scroll-x{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;border-radius:var(--radius)}
  .table-scroll-y{max-height:520px;width:100%;overflow-y:auto;-webkit-overflow-scrolling:touch}
  .table-scroll-y table{box-shadow:none;border-radius:0}
  .table-scroll-y thead th{position:sticky;top:0;z-index:1}
  .empty-state{color:var(--muted);font-size:0.85rem;text-align:center;padding:2rem 0}
  .auto-refresh{display:flex;align-items:center;gap:0.4rem;font-size:0.75rem;color:var(--muted);margin-top:1.5rem;text-align:center;justify-content:center}
  .dot{width:8px;height:8px;border-radius:50%;background:#34c759;display:inline-block;animation:pulse 2s infinite;box-shadow:0 0 0 4px rgba(52,199,89,0.15)}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
  .search-wrap{position:relative;min-width:220px}
  .search-wrap input{width:100%;padding:0.5rem 0.9rem 0.5rem 2rem;border:1px solid var(--border);border-radius:var(--radius-sm);
    background:var(--glass-bg);color:var(--text);font-size:0.82rem;font-family:inherit;font-weight:500;outline:none;
    transition:border-color 0.2s,box-shadow 0.2s;
    backdrop-filter:blur(30px) saturate(200%);-webkit-backdrop-filter:blur(30px) saturate(200%);
    box-shadow:inset 0 1px 0 rgba(255,255,255,0.7),0 2px 8px rgba(20,24,32,0.05)}
  html[data-theme="dark"] .search-wrap input{background:var(--glass-bg)}
  .search-wrap input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft),inset 0 1px 0 rgba(255,255,255,0.7)}
  .search-wrap input::placeholder{color:var(--muted)}
  .search-icon{position:absolute;left:0.65rem;top:50%;transform:translateY(-50%);width:14px;height:14px;
    stroke:var(--muted);fill:none;stroke-width:2;stroke-linecap:round;pointer-events:none}
  .identity-intro{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;margin-bottom:1.2rem}
  .identity-intro p,.identity-note{font-size:0.78rem;color:var(--muted);line-height:1.5}
  .identity-kicker{font-size:0.68rem;font-weight:800;letter-spacing:0.14em;text-transform:uppercase;color:var(--accent);margin-bottom:0.25rem}
  .identity-members{display:flex;flex-wrap:wrap;align-items:center;gap:0.35rem;margin-top:0.75rem}
  .identity-chip{display:inline-flex;align-items:center;gap:0.25rem;padding:0.22rem 0.4rem;border:1px solid var(--border-soft);border-radius:8px;background:var(--accent-soft);font-size:0.68rem;font-family:ui-monospace,SFMono-Regular,monospace;color:var(--text)}
  .identity-chip button{border:0;background:none;color:var(--accent);cursor:pointer;font:inherit;font-weight:800;padding:0 0.1rem}
  .identity-chip button:hover{text-decoration:underline}
  .identity-history{margin-top:1.2rem;padding-top:1rem;border-top:1px solid var(--border-soft)}
  .identity-history h3{font-size:0.85rem;margin-bottom:0.55rem}
  .identity-history ul{list-style:none;display:grid;gap:0.4rem}
  .identity-history li{font-size:0.73rem;color:var(--muted);line-height:1.45}
  .identity-dialog{width:min(92vw,530px);max-height:85vh;overflow:auto;margin:auto;padding:1.4rem;border:1px solid var(--border);border-radius:22px;background:var(--bg);color:var(--text);box-shadow:0 30px 90px rgba(0,0,0,.35);font-family:inherit}
  .identity-dialog::backdrop{background:rgba(10,15,30,.65);backdrop-filter:blur(4px)}
  .identity-dialog h2{font-size:1.2rem;margin-bottom:0.5rem}
  .identity-dialog p{font-size:0.8rem;line-height:1.55;color:var(--muted)}
  .identity-dialog label{display:block;font-size:0.77rem;font-weight:700;margin:1rem 0 0.35rem}
  .identity-dialog select{width:100%;padding:0.75rem;border:1px solid var(--border-soft);border-radius:11px;background:var(--glass-bg);color:var(--text);font:inherit}
  .identity-review{display:grid;grid-template-columns:1fr 1fr;gap:0.7rem;margin-top:1rem}
  .identity-review>div{padding:0.8rem;border:1px solid var(--border-soft);border-radius:12px;background:var(--accent-soft);min-width:0}
  .identity-review>div:first-child{border-color:rgba(52,199,89,.45);background:rgba(52,199,89,.10)}
  .identity-review strong{display:block;font-size:0.7rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:.4rem}
  .identity-review span{font-size:.78rem;line-height:1.5;overflow-wrap:anywhere}
  .identity-dialog-actions{display:flex;justify-content:flex-end;gap:.5rem;margin-top:1.2rem}
  .identity-dialog-actions button{border:1px solid var(--border-soft);border-radius:10px;padding:.65rem 1rem;font:inherit;font-size:.8rem;font-weight:700;cursor:pointer;background:var(--glass-bg);color:var(--text)}
  .identity-dialog-actions .identity-confirm{background:var(--accent);border-color:var(--accent);color:white}
  .identity-dialog-actions button:disabled{opacity:.55;cursor:wait}
  .identity-error{color:#c62828!important;margin-top:.65rem}
  .identity-error[hidden]{display:none}
  html[data-theme="dark"] .identity-error{color:#ff9c9c!important}
  .identity-review span{display:block;white-space:pre-line}
  .identity-signal{margin-top:.85rem;padding:.7rem .85rem;border:1px solid var(--border-soft);border-radius:10px;background:var(--accent-soft);font-size:.78rem;line-height:1.5}
  .identity-signal.identity-warning{border-color:rgba(245,158,11,.55);background:rgba(245,158,11,.12);color:#8a4b00}
  html[data-theme="dark"] .identity-signal.identity-warning{color:#ffd18a}
  #identityOutcome{margin-top:.7rem}
  .identity-check{display:flex;align-items:flex-start;gap:.55rem;margin-top:1rem;font-size:.8rem;line-height:1.4;cursor:pointer}
  .identity-check input{width:1rem;height:1rem;margin-top:.08rem;accent-color:var(--accent);flex:none}
  .identity-signal[hidden],.identity-note[hidden],.identity-check[hidden]{display:none}
  .visit-list{display:grid;gap:.55rem;max-height:45vh;overflow:auto;margin-top:1rem}
  .visit-item{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:.8rem;border:1px solid var(--border-soft);border-radius:12px;background:var(--accent-soft)}
  .visit-item strong{display:block;font-size:.8rem}
  .visit-item small{display:block;font-size:.7rem;color:var(--muted);line-height:1.5}
  .visit-item button{flex:none;border:1px solid var(--accent);border-radius:9px;background:var(--bg);color:var(--accent);padding:.4rem .6rem;cursor:pointer;font-size:.72rem;font-weight:700}
  .visit-editor{margin-top:1rem;padding:1rem;border:1px solid var(--accent);border-radius:14px;background:var(--accent-soft)}
  .visit-editor[hidden]{display:none}
  .visit-editor .identity-dialog-actions{margin-top:.75rem}
  @media(max-width:600px){body{padding:1rem}.top-bar{top:0.5rem}.stats{grid-template-columns:repeat(2,1fr)}.card{padding:1rem}.identity-review{grid-template-columns:1fr}}
  @media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<div class="aurora-layer" aria-hidden="true"></div>
<div class="container">
  <div class="tracked-alert" id="trackedAlert" hidden></div>
  <div class="top-bar">
    <div>
      <h1>Page View Dashboard</h1>
      <p class="subtitle">Real-time visit tracking for your profile page</p>
    </div>
    <div class="top-actions">
      <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()" type="button">Dark</button>
      <form method="POST" action="/logout" style="display:inline;margin:0"><button type="submit" class="logout" title="Session expires after 1 hour">Logout</button></form>
    </div>
  </div>
  <div class="stats">
    <div class="stat-card"><div class="stat-icon"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg></div><div class="stat-value" id="statToday">${totals.today}</div><div class="stat-label">Today</div></div>
    <div class="stat-card"><div class="stat-icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div><div class="stat-value" id="stat24h">${totals.last24h}</div><div class="stat-label">Last 24 Hours</div></div>
    <div class="stat-card"><div class="stat-icon"><svg viewBox="0 0 24 24"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg></div><div class="stat-value" id="statTotal">${totals.total}</div><div class="stat-label">Total Views</div></div>
    <div class="stat-card"><div class="stat-icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-6 8-6s8 2 8 6"/></svg></div><div class="stat-value" id="statUnique">${totals.unique}</div><div class="stat-label">Unique Visitors</div></div>
  </div>
  ${engagementHtml}

  <div class="card" style="margin-bottom:1.5rem">
    <div class="card-head">
      <h2>Click Details</h2>
      <span style="font-size:0.72rem;color:var(--muted)">Last 60 clicks &middot; tracked visitors glow gold</span>
    </div>
    <div class="table-scroll-x">
      <table>
        <thead><tr><th>Time (CST)</th><th>Visitor</th><th>Location</th><th>Section</th><th>Target</th><th>Link</th><th>Pos</th></tr></thead>
        <tbody id="clickTbody"><tr><td colspan="7" class="empty-state">Loading…</td></tr></tbody>
      </table>
    </div>
  </div>

  ${profiles && profiles.length ? '<div class="card" style="margin-bottom:1.5rem" id="identityStudio"><div class="identity-intro"><div><div class="identity-kicker">Identity studio</div><h2>Visitor Profiles</h2><p>Review the visits inside a profile to correct an old mix-up. Combine profiles only when they belong to the same person; linked IDs can be unlinked later.</p></div></div><div class="profile-grid tracked-section" id="profileGrid">' + profiles.map(function(p,i){
    var os = (p.oss && p.oss[0]) || '';
    var browser = (p.browsers && p.browsers[0]) || '';
    var rawUA = (p.uas && p.uas[0]) || '';
    // Fallback: extract from raw UA if parsed fields are empty (old data)
    if (!os && rawUA){
      if (/iPhone|iPad/i.test(rawUA)) os='iOS';
      else if (/Android/i.test(rawUA)) os='Android';
      else if (/Mac OS X/i.test(rawUA)) os='macOS';
      else if (/Windows/i.test(rawUA)) os='Windows';
    }
    if (!browser && rawUA){
      if (/Edg\//i.test(rawUA)) browser='Edge';
      else if (/Chrome\//i.test(rawUA)) browser='Chrome';
      else if (/Firefox\//i.test(rawUA)) browser='Firefox';
      else if (/Safari\//i.test(rawUA)) browser='Safari';
    }
    var devIcon = os && /macos|windows/i.test(os) ? '💻' : '📱';
    // Friendly name: "Android · Chrome · Seattle"
    var label=[];
    if (os) label.push(os);
    if (browser) label.push(browser);
    var primaryCity = p.cities[0] || '';
    if (primaryCity) label.push(primaryCity);
    var mixed = p.oss.length > 1 && p.countries.length > 1;
    var visitorName = mixed ? 'Mixed device signals' : label.length>0 ? label.join(' · ') : 'Device '+(i+1);
    if (visitorName.length>35) visitorName=visitorName.slice(0,33)+'…';
    var span = p.firstSeen && p.lastSeen ? (new Date(p.lastSeen+'Z').getTime()-new Date(p.firstSeen+'Z').getTime())/(86400000) : 0;
    var prob = mixed ? 'Review' : p.visits>=6 ? 'Regular' : p.visits>=3 ? (span>7 ? 'Frequent' : 'Returning') : 'New';
    var probClass = mixed ? 'review' : p.visits>=6 ? 'high' : p.visits>=3 ? 'med' : 'low';
    var ispList = p.isps && p.isps.filter(Boolean).join(', ') || '';
    var ipList = p.ipHashes && p.ipHashes.filter(Boolean).map(function(h){return h.slice(0,8)}).join(', ') || '';
    var citiesStr = p.cities.slice(0,3).join(', ') + (p.cities.length>3 ? ' +'+(p.cities.length-3) : '');
    var times = p.timezones && p.timezones.filter(Boolean).join(', ') || '';
    var members = p.members.length > 1 ? '<div class="identity-members"><span class="identity-note">Linked IDs</span>' + p.members.map(function(id){return '<span class="identity-chip" title="'+esc(id)+'">'+esc(id.slice(0,10))+(id!==p.id?' <button type="button" class="profile-separate" data-member="'+esc(id)+'" data-canonical="'+esc(p.id)+'" aria-label="Unlink '+esc(id)+'">Unlink</button>':'')+'</span>';}).join('') + '</div>' : '';
    return '<div class="profile-card" data-vid="'+esc(p.id)+'"'+(p.lastSeen?' data-lastseen="'+esc(p.lastSeen)+'"':'')+'><div class="profile-head"><span class="profile-icon">'+devIcon+'</span><span class="profile-name" title="'+esc(p.id)+'">'+esc(visitorName)+'</span><span class="prob prob-'+probClass+'">'+prob+'</span></div><div class="profile-visits"><strong>'+p.visits+'</strong> visits '+(p.lastSeen?'<span style="font-size:0.7rem;color:var(--muted)">since '+formatTime(p.firstSeen).split(',')[0].trim()+'</span>':'')+'</div><div class="profile-loc">📍 '+esc(citiesStr)+'</div><div class="profile-meta">'+esc(os||'')+(browser?' · '+esc(browser):'')+(ispList?'<br>📡 '+esc(ispList):'')+(ipList?'<br>🔑 '+ipList:'')+(times?'<br>🕐 '+esc(times):'')+(p.lastSeen?'<br>⚠️ <strong>Last seen '+timeAgo(p.lastSeen)+'</strong>':'')+'</div>'+members+'<div class="profile-actions"><button class="track-btn" data-vid="'+esc(p.id)+'" title="Star this visitor to track them">★ Track</button><button class="profile-review" data-vid="'+esc(p.id)+'" title="Inspect and correct individual visits">Review visits</button><button class="profile-merge" data-vid="'+esc(p.id)+'" title="Keep this card and add another profile to it">Combine with another…</button></div></div>';
  }).join('') + '</div><div class="identity-history"><h3>Identity activity</h3>' + (identityEvents.length ? '<ul>' + identityEvents.map(function(ev){var summary=ev.action==='merge'?'Combined '+ev.affected.length+' ID'+(ev.affected.length===1?'':'s'):ev.action==='separate'?'Unlinked an ID':ev.action==='move'?'Moved visit #'+ev.viewId:'Restored visit #'+ev.viewId;return '<li>'+formatTime(ev.createdAt)+' · '+summary+(ev.target?' → '+esc(ev.target.slice(0,10)):'')+'</li>';}).join('')+'</ul>' : '<p class="identity-note">No identity changes yet.</p>') + '</div></div>' : ''}

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

  <div class="grid-2">
    <div class="card">
      <h2>Views — last 30 days</h2>
      <div class="trend-wrap" id="trendWrap">
        <svg class="trend" viewBox="0 0 100 40" preserveAspectRatio="none">
          <polyline class="trend-poly" id="trendPoly" points="${trendPoly}"/>
        </svg>
        ${trendEmpty ? '<p class="empty-state">No data yet</p>' : '<div class="trend-date" id="trendDate"><span>' + trend[0].date + '</span><span>Peak: ' + trendMax + '</span><span>' + trend[trend.length-1].date + '</span></div>'}
      </div>
    </div>
    <div class="card">
      <h2>Top Sources</h2>
      <div id="refList">${referrerRows}</div>
    </div>
  </div>

  ${countries.length ? '<div class="card"><h2>Top Countries</h2><div class="country-list" id="countryList">' + countryChips + '</div></div>' : ''}

  <div class="card">
    <div class="card-head">
      <h2>Recent Visits</h2>
      <div class="search-wrap">
        <svg class="search-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input type="text" id="recentSearch" placeholder="Filter visits…" autocomplete="off" aria-label="Filter visits">
      </div>
    </div>
    <div class="table-scroll-x">
      <table>
        <thead><tr><th>Time (CST)</th><th>Approx. area</th><th>Device · OS</th><th>Source</th><th>Profile</th></tr></thead>
        <tbody id="recentTbody">${recentRows}</tbody>
      </table>
    </div>
  </div>
  <div class="auto-refresh"><span class="dot"></span> Auto-refreshes every 60s &middot; All times in CST</div>
</div>
<script>window.__DASH=${dashSeed};</script>
<script>
${DASHBOARD_CLIENT_JS}
</script>
</body>
</html>`;
}

function flag(code) {
  if (!code || code.length !== 2) return '';
  const a = 0x1F1E6 - 65 + code.toUpperCase().charCodeAt(0);
  const b = 0x1F1E6 - 65 + code.toUpperCase().charCodeAt(1);
  return String.fromCodePoint(a, b);
}

function formatTime(t) {
  if (!t) return '';
  const d = new Date(t + 'Z');
  return d.toLocaleString('en-US', { month:'short', day:'numeric', hour:'numeric', minute:'2-digit', hour12:true, timeZone:'America/Chicago' });
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n) + '...' : s;
}

// City/region from IP geolocation is approximate, not a visitor's GPS position.
function coordH(v) {
  const place = [v.city, v.region, v.country].filter(Boolean).join(', ');
  if (!place) return '';
  return '<div class="identity-note">IP-based estimate · <a href="https://www.google.com/maps/search/?api=1&query='
    + encodeURIComponent(place) + '" target="_blank" rel="noreferrer">Area map</a></div>';
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

function timeAgo(t) {
  if (!t) return '';
  const diff = Math.floor((Date.now() - new Date(t + 'Z').getTime()) / 1000);
  if (diff < 0) return 'just now';
  if (diff < 60) return diff + 's ago';
  const mins = Math.floor(diff / 60);
  if (mins < 60) return mins + 'm ago';
  const hours = Math.floor(mins / 60);
  if (hours < 24) return hours + 'h ago';
  const days = Math.floor(hours / 24);
  if (days < 30) return days + 'd ago';
  return Math.floor(days / 30) + 'mo ago';
}
