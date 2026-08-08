var VERSION = '3.16.4'; // bump when you change the worker code

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

  // Daily maintenance: purge expired rate-limit buckets and expired sessions.
  async scheduled(event, env) {
    const cutoff = Math.floor(Date.now() / 1000);
    await Promise.all([
      env.DB.prepare('DELETE FROM rate_limits WHERE bucket < ?').bind(cutoff - 2 * 86400).run(),
      env.DB.prepare('DELETE FROM sessions WHERE exp < ?').bind(cutoff).run(),
    ]);
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
  const { id: visitorId, fromCookie } = await getVisitorId(request, ua, language, cf);

  const stmt = env.DB.prepare(
    `INSERT INTO page_views (country, city, region, timezone, user_agent, referrer, page_url, visitor_id,
     device_type, os, browser, latitude, longitude, postal_code, isp, language)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
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
    language
  ).run();

  console.log(JSON.stringify({ event: 'visit', ip, city: cf.city || null, country: cf.country || null, known: fromCookie, vid: visitor_id_preview(visitorId) }));

  const response = Response.json({ ok: true }, { headers: base });

  // Always (re)issue the cookie so it survives cross-origin (Site=other, SameSite=None)
  // and persists for a year. Echo back the SAME id we just stored so future visits
  // from this browser collapse onto this row regardless of IP/network changes.
  response.headers.set(
    'Set-Cookie',
    `${VID_COOKIE}=${visitorId}; Max-Age=31536000; Path=/; SameSite=None; Secure; HttpOnly`
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

  // Identity comes from the cookie (validated by regex) — same fence as /log-visit
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp(VID_COOKIE + '=([^;]+)'));
  const vid = match ? match[1] : '';
  if (!vid || !(UUID_RE.test(vid) || FP_RE.test(vid))) {
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
    await env.DB.prepare(
      `INSERT INTO page_engagement (visitor_id, session_id, event_type, page_url, x, y, target, extra)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(vid, session_id || null, event_type, body.pageUrl || null, x, y, target, extra).run();
  } else {
    // heartbeat / pagehide / pageshow / focus — no x/y
    await env.DB.prepare(
      `INSERT INTO page_engagement (visitor_id, session_id, event_type, page_url)
       VALUES (?, ?, ?, ?)`
    ).bind(vid, session_id || null, event_type, body.pageUrl || null).run();
  }

  return Response.json({ ok: true }, { headers: base });
}

// ── POST /api/merge-visitors (session-gated, merge all visits from source → target) ──
async function handleMergeVisitors(request, env) {
  const h = securityHeaders({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: h });
  if (request.method !== 'POST') return Response.json({ error: 'method_not_allowed' }, { status: 405, headers: h });

  const session = sessionTokenFrom(request.headers.get('Cookie') || '');
  if (!session || !(await verifySessionToken(session, env))) {
    return Response.json({ error: 'unauthorized' }, { status: 401, headers: h });
  }

  let body = {};
  try { body = await request.json(); } catch (_) { return Response.json({ error: 'bad_json' }, { status: 400, headers: h }); }

  const source = String(body.source || '');
  const target = String(body.target || '');
  if (!source || !target || source === target) {
    return Response.json({ error: 'bad_params' }, { status: 400, headers: h });
  }

  // Validate that both visitor_ids exist
  const [srcCount, tgtCount] = await Promise.all([
    env.DB.prepare('SELECT COUNT(*) AS c FROM page_views WHERE visitor_id = ?').bind(source).first(),
    env.DB.prepare('SELECT COUNT(*) AS c FROM page_views WHERE visitor_id = ?').bind(target).first(),
  ]);
  if (!(srcCount && srcCount.c > 0)) {
    return Response.json({ error: 'source_not_found' }, { status: 404, headers: h });
  }
  if (!(tgtCount && tgtCount.c > 0)) {
    return Response.json({ error: 'target_not_found' }, { status: 404, headers: h });
  }

  // Merge page_views
  const r1 = await env.DB.prepare('UPDATE page_views SET visitor_id = ? WHERE visitor_id = ?').bind(target, source).run();
  const merged = (r1 && r1.changes) || 0;

  // Merge engagement rows too (heartbeats, clicks, etc.)
  const r2 = await env.DB.prepare('UPDATE page_engagement SET visitor_id = ? WHERE visitor_id = ?').bind(target, source).run();
  const engMerged = (r2 && r2.changes) || 0;

  console.log(JSON.stringify({ event: 'visitors_merged', source, target, visits: merged, engagement: engMerged }));
  return Response.json({ ok: true, merged, engagement: engMerged, source, target }, { headers: h });
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
      const okT = await verifyTurnstile(request, env, token);
      if (!okT) {
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
    const res = new Response(null, { status: 303, headers: { Location: '/dashboard', 'Cache-Control': 'no-store' } });
    res.headers.set(
      'Set-Cookie',
      `__Host-session=${token}; Max-Age=3600; Path=/; SameSite=Lax; Secure; HttpOnly`
    );
    return res;
  }

  if (request.method !== 'GET') {
    return new Response('Method Not Allowed', { status: 405, headers: htmlHeaders });
  }

  // GET: verify session cookie
  if (session && await verifySessionToken(session, env)) {
    const html = await renderDashboard(env.DB);
    return new Response(html, { headers: htmlHeaders });
  }

  return new Response(loginPage('', env), {
    status: 401,
    headers: htmlHeaders,
  });
}

// Optional Turnstile verification (only called when TURNSTILE_SECRET is configured)
async function verifyTurnstile(request, env, token) {
  try {
    const ip = request.headers.get('CF-Connecting-IP') || '';
    const params = new URLSearchParams();
    params.set('secret', env.TURNSTILE_SECRET);
    params.set('response', token);
    if (ip) params.set('remoteip', ip);
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
    const [totals, topCountries, recentVisits, seattleStats, seattleVisits, trend, referrers, engagement, profiles] = await Promise.all([
      queryStats(db),
      queryTopCountries(db),
      queryRecent(db),
      querySeattleStats(db),
      querySeattleAll(db),
      queryTrend(db, 30),
      queryTopReferrers(db),
      queryEngagement(db),
      queryVisitorProfiles(db),
    ]);
    return dashboardHtml(totals, topCountries, recentVisits, seattleStats, seattleVisits, trend, referrers, engagement, profiles);
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

  const [totals, topCountries, trend, referrers, seattleStats, seattleVisits, recent, engagement, profiles] = await Promise.all([
    queryStats(env.DB),
    queryTopCountries(env.DB),
    queryTrend(env.DB, 30),
    queryTopReferrers(env.DB),
    querySeattleStats(env.DB),
    querySeattleAll(env.DB),
    queryRecent(env.DB),
    queryEngagement(env.DB),
    queryVisitorProfiles(env.DB),
  ]);

  return Response.json({ totals, topCountries, trend, referrers, seattleStats, seattleVisits, recent, engagement, profiles }, { headers: jsonHeaders });
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
  const [oldest, newest] = await Promise.all([
    env.DB.prepare('SELECT created_at FROM page_views ORDER BY created_at ASC LIMIT 1').first(),
    env.DB.prepare('SELECT created_at FROM page_views ORDER BY created_at DESC LIMIT 1').first(),
  ]);
  return Response.json({
    version: VERSION,
    uptime: 'since scheduled',
    compat: '2026-08-02',
    runtime: 'workers',
    data_range: {
      first: oldest?.created_at || null,
      last: newest?.created_at || null,
    },
  }, { headers: h });
}

// ── DB queries ──
async function queryStats(db) {
  const row = await db.prepare(
    `SELECT
       (SELECT COUNT(*) FROM page_views) AS total,
       (SELECT COUNT(DISTINCT visitor_id) FROM page_views) AS uniq,
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

  return {
    sessions: totalSessions,
    avgDurationSec: avgSec,
    recent: perSession.slice(0, 10),
    topClicks: clicks || [],
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
    `SELECT created_at, country, city, region, referrer, page_url, visitor_id, device_type, os, browser, latitude, longitude, postal_code, isp, language
     FROM page_views
     ORDER BY created_at DESC
     LIMIT 100`
  ).all();
  return results || [];
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

// ── Seattle totals ──
async function querySeattleStats(db) {
  const row = await db.prepare(
    `SELECT
       (SELECT COUNT(*) FROM page_views WHERE city = 'Seattle') AS total,
       (SELECT COUNT(DISTINCT visitor_id) FROM page_views WHERE city = 'Seattle') AS uniq,
       (SELECT COUNT(*) FROM page_views WHERE city = 'Seattle' AND created_at >= datetime('now','-30 days')) AS last30,
       (SELECT created_at FROM page_views WHERE city = 'Seattle' ORDER BY created_at ASC LIMIT 1) AS first_seen,
       (SELECT created_at FROM page_views WHERE city = 'Seattle' ORDER BY created_at DESC LIMIT 1) AS last_seen`
  ).first();
  return {
    total: row?.total || 0,
    unique: row?.uniq || 0,
    last30: row?.last30 || 0,
    firstSeen: row?.first_seen || null,
    lastSeen: row?.last_seen || null,
  };
}

// ── All-time Seattle visits ──
async function querySeattleAll(db) {
  const { results } = await db.prepare(
    `SELECT created_at, country, region, timezone, referrer, user_agent, visitor_id, device_type, os, browser, latitude, longitude, postal_code, isp, language
     FROM page_views
     WHERE city = 'Seattle'
     ORDER BY created_at DESC
     LIMIT 500`
  ).all();
  return results || [];
}

// ── Grouped visitor profiles (one box per device/person) ──
async function queryVisitorProfiles(db) {
  const { results } = await db.prepare(
    `SELECT visitor_id,
            COUNT(*) as visits,
            MIN(created_at) as first_seen,
            MAX(created_at) as last_seen,
            GROUP_CONCAT(DISTINCT city) as cities,
            GROUP_CONCAT(DISTINCT region) as regions,
            GROUP_CONCAT(DISTINCT country) as countries,
            GROUP_CONCAT(DISTINCT isp) as isps,
            GROUP_CONCAT(DISTINCT user_agent) as uas,
            GROUP_CONCAT(DISTINCT device_type) as devices,
            GROUP_CONCAT(DISTINCT os) as oss,
            GROUP_CONCAT(DISTINCT browser) as browsers,
            GROUP_CONCAT(DISTINCT language) as langs,
            GROUP_CONCAT(DISTINCT timezone) as timezones
     FROM page_views
     GROUP BY visitor_id
     ORDER BY visits DESC`
  ).all();

  return (results || []).map(r => ({
    id: r.visitor_id,
    visits: r.visits || 0,
    firstSeen: r.first_seen,
    lastSeen: r.last_seen,
    cities: [...new Set((r.cities || '').split(',').filter(Boolean))],
    regions: [...new Set((r.regions || '').split(',').filter(Boolean))],
    countries: [...new Set((r.countries || '').split(',').filter(Boolean))],
    isps: [...new Set((r.isps || '').split(',').filter(Boolean))],
    uas: [...new Set((r.uas || '').split(',').filter(Boolean))],
    devices: [...new Set((r.devices || '').split(',').filter(Boolean))],
    oss: [...new Set((r.oss || '').split(',').filter(Boolean))],
    browsers: [...new Set((r.browsers || '').split(',').filter(Boolean))],
    langs: [...new Set((r.langs || '').split(',').filter(Boolean))],
    timezones: [...new Set((r.timezones || '').split(',').filter(Boolean))],
  }));
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
<svg style="position:fixed;width:0;height:0" aria-hidden="true"><defs>
<filter id="lg-login" x="-20%" y="-20%" width="140%" height="140%" color-interpolation-filters="sRGB">
<feTurbulence type="fractalNoise" baseFrequency="0.01 0.014" numOctaves="2" seed="12" result="noise"/>
<feDisplacementMap in="SourceGraphic" in2="noise" scale="16" xChannelSelector="R" yChannelSelector="G"/>
</filter>
</defs></svg>
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
    animation:aurora 28s ease-in-out infinite alternate}
  body::after{background:radial-gradient(50% 35% at 50% 0%,rgba(255,255,255,0.7) 0%,transparent 70%);animation:aurora-glow 20s ease-in-out infinite alternate;mix-blend-mode:overlay}
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
  .box{background:var(--glass);padding:3rem 2.5rem;border-radius:28px;box-shadow:var(--card-shadow);text-align:center;max-width:420px;width:92vw;position:relative;border:1px solid var(--border);backdrop-filter:blur(50px) saturate(200%) url(#lg-login);-webkit-backdrop-filter:blur(50px) saturate(200%);animation:fadeInUp 0.3s cubic-bezier(.22,.61,.36,1) both}
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
${hasTurnstile ? `<script>
  document.getElementById('loginForm').addEventListener('submit', function(e){
    var t = window.turnstile;
    if (!t) { return; } // widget not loaded yet — allow submit, server handles it
    var token = t.getResponse();
    if (token) {
      appendToken(this, token);
      t.reset();
      return;
    }
    // Token not ready (slow network / widget still rendering): wait for it,
    // then retry once — otherwise mobile users hit "verification failed".
    e.preventDefault();
    var tries = 0;
    var timer = setInterval(function(){
      tries++;
      var tk = window.turnstile && window.turnstile.getResponse();
      if (tk) {
        clearInterval(timer);
        appendToken(document.getElementById('loginForm'), tk);
        window.turnstile.reset();
        document.getElementById('loginForm').submit();
      } else if (tries > 25) { // ~5s timeout, then submit anyway
        clearInterval(timer);
        document.getElementById('loginForm').submit();
      }
    }, 200);
  });
  function appendToken(form, token){
    var h = document.createElement('input');
    h.type = 'hidden'; h.name = 'turnstile'; h.value = token;
    form.appendChild(h);
  }
</script>` : ''}
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

function dashboardHtml(totals, countries, visits, seattleStats, seattleVisits, trend, referrers, engagement, profiles) {
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
  const seattleBanner = '<div class="seattle-banner"><h3>Seattle Visits — All Time</h3>'
    + '<p>' + seattleStats.total + ' total views &middot; ' + seattleStats.unique + ' unique visitors &middot; '
    + seattleStats.last30 + ' in last 30 days'
    + (seattleStats.firstSeen ? ' &middot; first seen ' + formatTime(seattleStats.firstSeen) : '')
    + (seattleStats.lastSeen ? ' &middot; <strong>last seen ' + timeAgo(seattleStats.lastSeen) + '</strong>' : '')
    + '</p></div>';
  const seattleRows = seattleVisits.length ? seattleVisits.map(v => {
    const ago = timeAgo(v.created_at);
    const loc = [v.city, v.region, v.country].filter(Boolean).join(', ') || '—';
    const ispExtra = v.isp ? ' <span style="font-size:0.68rem;color:var(--muted)">' + esc(v.isp) + '</span>' : '';
    const osParts = [v.os, v.browser].filter(Boolean);
    const deviceLine = v.device_type ? ('<span class="badge" style="font-size:0.68rem">' + esc(v.device_type) + '</span> ') : '';
    const osLine = osParts.length ? deviceLine + esc(osParts.join(' · ')) : (v.user_agent ? parseUA(v.user_agent) : '—');
    const id = v.id || '';
    return '<tr data-id="' + id + '"><td><div style="font-weight:500">' + formatTime(v.created_at) + '</div><div style="font-size:0.68rem;color:var(--muted)">' + ago + '</div></td>'
      + '<td>' + esc(loc) + coordH(v) + ispExtra + '</td>'
      + '<td>' + (v.referrer
        ? '<a href="' + esc(v.referrer) + '" rel="noreferrer" style="color:var(--accent);text-decoration:none">' + truncate(esc(v.referrer), 28) + '</a>'
        : 'Direct') + '</td>'
      + '<td style="font-size:0.78rem"><span class="badge">' + esc(v.device_type || 'Unknown') + '</span> ' + esc(osLine) + '</td>'
      + '<td><span class="badge seattle">' + esc(v.visitor_id.slice(0, 8)) + '</span></td></tr>';
  }).join('') : '<tr><td colspan="5" class="empty-state">No Seattle visits recorded yet</td></tr>';
  const recentRows = visits.map(v => {
    const isSea = v.city === 'Seattle';
    const ago = timeAgo(v.created_at);
    const loc = [v.city, v.region, v.country].filter(Boolean).join(', ') || 'Unknown';
    const os = esc(v.os || '');
    const browser = esc(v.browser || '');
    const dev = esc(v.device_type || '');
    const id = v.id || '';
    return '<tr data-id="' + id + '"' + (isSea ? ' style="background:rgba(0,113,227,0.04)"' : '') + '>'
      + '<td><div>' + formatTime(v.created_at) + '</div><div style="font-size:0.7rem;color:var(--muted)">' + ago + '</div></td>'
      + '<td>' + esc(loc) + coordH(v) + (isSea ? ' <span class="badge seattle">SEA</span>' : '') + '</td>'
      + '<td style="font-size:0.78rem">' + (dev ? '<span class="badge">' + dev + '</span> ' : '') + ' ' + esc([os, browser].filter(Boolean).join(' · ') || '—') + '</td>'
      + '<td>' + (v.referrer
        ? '<a href="' + esc(v.referrer) + '" rel="noreferrer" style="color:var(--accent);text-decoration:none">' + truncate(esc(v.referrer), 30) + '</a>'
        : 'Direct') + '</td>'
      + '<td><span class="badge">' + esc(v.visitor_id.slice(0, 8)) + '</span></td></tr>';
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
<svg style="position:fixed;width:0;height:0" aria-hidden="true"><defs>
<filter id="lg-refract" x="-20%" y="-20%" width="140%" height="140%" color-interpolation-filters="sRGB">
<feTurbulence type="fractalNoise" baseFrequency="0.008 0.012" numOctaves="2" seed="7" result="noise"/>
<feDisplacementMap in="SourceGraphic" in2="noise" scale="14" xChannelSelector="R" yChannelSelector="G"/>
<feGaussianBlur stdDeviation="0.6"/>
</filter>
<filter id="lg-refract-strong" x="-20%" y="-20%" width="140%" height="140%" color-interpolation-filters="sRGB">
<feTurbulence type="fractalNoise" baseFrequency="0.006 0.01" numOctaves="3" seed="21" result="noise"/>
<feDisplacementMap in="SourceGraphic" in2="noise" scale="22" xChannelSelector="R" yChannelSelector="G"/>
<feGaussianBlur stdDeviation="0.8"/>
</filter>
</defs></svg>
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
    animation:aurora 28s ease-in-out infinite alternate;filter:blur(30px)}
  body::after{
    background:radial-gradient(55% 35% at 50% 0%,rgba(255,255,255,0.7) 0%,transparent 65%);
    animation:aurora-glow 18s ease-in-out infinite alternate;mix-blend-mode:overlay;filter:none}
  body>.aurora-layer{
    background:
      radial-gradient(500px 400px at 70% 30%,rgba(120,180,255,0.35) 0%,transparent 60%),
      radial-gradient(450px 380px at 15% 75%,rgba(180,140,255,0.3) 0%,transparent 55%);
    animation:aurora-2 22s ease-in-out infinite alternate;mix-blend-mode:screen;filter:blur(40px)}
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
    background:var(--glass-bg);backdrop-filter:blur(50px) saturate(200%) url(#lg-refract);-webkit-backdrop-filter:blur(50px) saturate(200%);
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
    box-shadow:var(--pill-shadow);backdrop-filter:blur(30px) saturate(200%) url(#lg-refract);-webkit-backdrop-filter:blur(30px) saturate(200%)}
  .theme-toggle:hover,.logout:hover{color:var(--accent);border-color:var(--accent);transform:translateY(-1px);box-shadow:0 0 0 3px var(--accent-soft),inset 0 1px 0 rgba(255,255,255,0.9)}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:1.5rem}
  .stat-card{position:relative;overflow:hidden;background:var(--glass-bg);padding:1.4rem 1.5rem;border-radius:var(--radius);
    box-shadow:var(--glass-shadow);border:1px solid var(--border);
    backdrop-filter:blur(50px) saturate(200%) url(#lg-refract);-webkit-backdrop-filter:blur(50px) saturate(200%);
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
    backdrop-filter:blur(50px) saturate(200%) url(#lg-refract);-webkit-backdrop-filter:blur(50px) saturate(200%)}
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
    border:1px solid var(--border);backdrop-filter:blur(30px) saturate(200%) url(#lg-refract);-webkit-backdrop-filter:blur(30px) saturate(200%);font-weight:500}
  .country-chip strong{color:var(--accent);font-weight:700}
  .table-wrap{background:var(--glass-bg);border-radius:var(--radius);overflow:hidden;box-shadow:var(--glass-shadow);border:1px solid var(--border);
    backdrop-filter:blur(50px) saturate(200%) url(#lg-refract);-webkit-backdrop-filter:blur(50px) saturate(200%)}
  table{width:100%;border-collapse:collapse;border-radius:var(--radius)}
  th,td{padding:11px 14px;text-align:left;font-size:0.82rem;white-space:nowrap;letter-spacing:0.01em}
  th{background:rgba(0,113,227,0.06);font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:0.05em;font-size:0.68rem}
  html[data-theme="dark"] th{background:rgba(41,151,255,0.10)}
  td{border-bottom:1px solid var(--border-soft);font-weight:500;font-variant-numeric:tabular-nums}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:rgba(0,113,227,0.05)}
  html[data-theme="dark"] tr:hover td{background:rgba(41,151,255,0.08)}
  .badge{display:inline-block;padding:3px 9px;border-radius:8px;font-size:0.68rem;font-weight:700;letter-spacing:0.02em;background:rgba(46,125,50,0.12);color:#2e7d32;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
  html[data-theme="dark"] .badge{background:rgba(129,199,132,0.16);color:#81c784}
  .badge.seattle{background:rgba(21,101,192,0.12);color:#1565c0}
  html[data-theme="dark"] .badge.seattle{background:rgba(100,181,246,0.18);color:#64b5f6}
  .profile-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:1rem;margin-top:0.5rem}
  .profile-card{position:relative;background:linear-gradient(150deg,rgba(255,255,255,0.6),rgba(255,255,255,0.25));border:1px solid var(--border);border-radius:var(--radius-md);padding:1.1rem;box-shadow:inset 0 1px 0 rgba(255,255,255,0.6);transition:transform 0.2s,box-shadow 0.2s}
  .profile-card:hover{transform:translateY(-2px);box-shadow:inset 0 1px 0 rgba(255,255,255,0.7),0 8px 24px rgba(0,80,180,0.12)}
  .profile-head{display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem}
  .profile-icon{font-size:1.3rem}
  .profile-id{font-family:monospace;font-size:0.72rem;color:var(--muted)}
  .prob{font-size:0.6rem;padding:2px 6px;border-radius:8px;font-weight:600;text-transform:uppercase;letter-spacing:0.03em}
  .prob-high{background:rgba(46,125,50,0.15);color:#2e7d32}
  .prob-med{background:rgba(245,124,0,0.15);color:#e65100}
  .prob-low{background:rgba(117,117,117,0.15);color:#616161}
  .profile-visits{font-size:1.4rem;font-weight:700;color:var(--text);margin-bottom:0.3rem}
  .profile-visits strong{font-variant-numeric:tabular-nums}
  .profile-loc{font-size:0.78rem;color:var(--accent);margin-bottom:0.4rem}
  .profile-meta{font-size:0.7rem;color:var(--muted);line-height:1.4}
  .profile-actions{display:flex;gap:0.4rem;margin-top:0.7rem}
  .profile-merge{font-size:0.68rem;padding:3px 10px;border-radius:8px;border:1px solid var(--border);background:rgba(255,255,255,0.5);cursor:pointer;font-weight:500;transition:all 0.15s;color:var(--text)}
  .profile-merge:hover{border-color:var(--accent);color:var(--accent);background:rgba(0,113,227,0.08)}
  html[data-theme="dark"] .profile-card{background:linear-gradient(150deg,rgba(50,58,78,0.5),rgba(28,31,38,0.35))}
  html[data-theme="dark"] .profile-merge{background:rgba(255,255,255,0.06)}
  html[data-theme="dark"] .prob-high{background:rgba(76,175,80,0.2);color:#81c784}
  html[data-theme="dark"] .prob-med{background:rgba(255,152,0,0.2);color:#ffb74d}
  html[data-theme="dark"] .prob-low{background:rgba(158,158,158,0.2);color:#bdbdbd}
  .table-scroll-x{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;border-radius:var(--radius)}
  .table-scroll-y{max-height:520px;width:100%;overflow-y:auto;-webkit-overflow-scrolling:touch}
  .table-scroll-y table{box-shadow:none;border-radius:0}
  .table-scroll-y thead th{position:sticky;top:0;z-index:1}
  .seattle-card{border-left:3px solid var(--accent)}
  .empty-state{color:var(--muted);font-size:0.85rem;text-align:center;padding:2rem 0}
  .auto-refresh{display:flex;align-items:center;gap:0.4rem;font-size:0.75rem;color:var(--muted);margin-top:1.5rem;text-align:center;justify-content:center}
  .dot{width:8px;height:8px;border-radius:50%;background:#34c759;display:inline-block;animation:pulse 2s infinite;box-shadow:0 0 0 4px rgba(52,199,89,0.15)}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
  .seattle-banner{position:relative;overflow:hidden;background:linear-gradient(135deg,rgba(0,113,227,0.12),rgba(90,200,250,0.08));color:var(--accent);padding:1.25rem 1.5rem;border-radius:var(--radius-md);margin-bottom:1rem;
    border:1px solid var(--border);backdrop-filter:blur(30px) saturate(180%);-webkit-backdrop-filter:blur(30px) saturate(180%);
    box-shadow:inset 0 1px 0 rgba(255,255,255,0.7),0 2px 12px rgba(0,113,227,0.08)}
  .seattle-banner::after{content:'';position:absolute;inset:0;border-radius:inherit;pointer-events:none;background:var(--specular);mix-blend-mode:screen}
  html[data-theme="dark"] .seattle-banner{background:linear-gradient(135deg,rgba(41,151,255,0.16),rgba(100,181,246,0.10));color:#64b5f6;
    box-shadow:inset 0 1px 0 rgba(255,255,255,0.18),0 2px 12px rgba(41,151,255,0.12)}
  .seattle-banner h3{font-size:1.1rem;font-weight:700;margin-bottom:0.25rem;position:relative;z-index:1}
  .seattle-banner p{font-size:0.8rem;font-weight:500;opacity:0.9;position:relative;z-index:1}
  .seattle-banner::after{z-index:0}
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
  @media(max-width:600px){body{padding:1rem}.top-bar{top:0.5rem}.stats{grid-template-columns:repeat(2,1fr)}.card{padding:1rem}.seattle-banner{padding:1rem}}
  @media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<svg style="position:fixed;top:0;left:0;width:0;height:0;overflow:hidden" aria-hidden="true"><defs>
<filter id="lg-refract-body" x="-20%" y="-20%" width="140%" height="140%" color-interpolation-filters="sRGB">
<feTurbulence type="fractalNoise" baseFrequency="0.008 0.012" numOctaves="2" seed="7" result="noise"/>
<feDisplacementMap in="SourceGraphic" in2="noise" scale="10" xChannelSelector="R" yChannelSelector="G"/>
</filter>
</defs></svg>
<div class="aurora-layer" aria-hidden="true"></div>
<div class="container">
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
  <div class="stats" style="margin-bottom:1.5rem">
    <div class="stat-card"><div class="stat-icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div><div class="stat-value" id="statSessions">${(engagement&&engagement.sessions)||0}</div><div class="stat-label">Sessions Tracked</div></div>
    <div class="stat-card"><div class="stat-icon"><svg viewBox="0 0 24 24"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg></div><div class="stat-value" id="statAvg">${fmtDur((engagement&&engagement.avgDurationSec)||0)}</div><div class="stat-label">Avg. Time on Page</div></div>
    <div class="stat-card"><div class="stat-icon"><svg viewBox="0 0 24 24"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg></div><div class="stat-value" id="statClicks">${(engagement&&engagement.topClicks||[]).length}</div><div class="stat-label">Most-Clicked</div></div>
    <div class="stat-card" style="display:flex;flex-direction:column;justify-content:center"><div class="stat-label" style="margin-bottom:0.4rem">Recent clicks</div><div style="font-size:0.8rem;color:var(--muted);line-height:1.5">${(engagement&&engagement.topClicks||[]).slice(0,3).map(c=>esc(c.target)+' <strong>'+c.count+'</strong>').join(' &middot; ')||'—'}</div></div>
  </div>

  ${profiles && profiles.length ? '<div class="card" style="margin-bottom:1.5rem"><h2>Visitor Profiles</h2><p style="font-size:0.78rem;color:var(--muted);margin-bottom:1rem">Each box is one device/person. Same visitor ID = same device. Click merge to combine profiles you recognize as the same person.</p><div class="profile-grid" id="profileGrid">' + profiles.map(function(p,i){
    var devIcon = p.devices && p.devices[0] ? (p.devices[0].toLowerCase().indexOf('mobile')>=0 ? '📱' : p.devices[0].toLowerCase().indexOf('desktop')>=0 ? '💻' : '📲') : '📱';
    var uaShort = p.uas && p.uas[0] ? (p.uas[0].indexOf('iPhone')>=0 ? 'iPhone' : p.uas[0].indexOf('Macintosh')>=0 ? 'Mac' : p.uas[0].indexOf('Android')>=0 ? 'Android' : 'Browser') : '?';
    var citiesStr = p.cities.slice(0,4).join(', ') + (p.cities.length>4 ? ' +'+(p.cities.length-4) : '');
    var prob = p.visits > 3 ? 'high' : p.visits > 1 ? 'med' : 'low';
    return '<div class="profile-card" data-vid="'+esc(p.id)+'"><div class="profile-head"><span class="profile-icon">'+devIcon+'</span><span class="profile-id" data-orig="'+esc(p.id.slice(0,10))+'">'+esc(p.id.slice(0,10))+'</span><span class="prob prob-'+prob+'">'+prob+'</span></div><div class="profile-visits"><strong>'+p.visits+'</strong> visits</div><div class="profile-loc">'+esc(citiesStr)+'</div><div class="profile-meta">'+esc(uaShort)+' · '+esc(p.countries.slice(0,2).join(', ')||'?')+'<br><span style="font-size:0.68rem">'+timeAgo(p.firstSeen)+' → '+timeAgo(p.lastSeen)+'</span></div><div class="profile-actions"><button class="profile-merge" data-vid="'+esc(p.id)+'" title="Merge into another profile">merge</button></div></div>';
  }).join('') + '</div></div>' : ''}

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

  <div class="card seattle-card">
    <div id="seattleBanner">${seattleBanner}</div>
    <div class="table-scroll-x">
      <div class="table-scroll-y">
        <table>
<thead><tr><th>Time (CST)</th><th>Location · Coords</th><th>Source</th><th>Device · OS</th><th>Visitor</th></tr></thead>
           <tbody id="seattleTbody">${seattleRows}</tbody>
        </table>
      </div>
    </div>
  </div>

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
        <thead><tr><th>Time (CST)</th><th>Location · Coords</th><th>Device · OS</th><th>Source</th><th>Visitor</th></tr></thead>
        <tbody id="recentTbody">${recentRows}</tbody>
      </table>
    </div>
  </div>
  <div class="auto-refresh"><span class="dot"></span> Auto-refreshes every 60s &middot; All times in CST</div>
</div>
<script>
  // ── Theme (localStorage with cookie fallback — mobile/private browsing blocks localStorage) ──
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
    if(t==='dark'){document.documentElement.setAttribute('data-theme','dark');}
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
    var b='Other';
    if(/Edg\\//.test(ua))b='Edge';else if(/Chrome\\//.test(ua)&&!/Chromium\\//.test(ua))b='Chrome';
    else if(/Firefox\\//.test(ua))b='Firefox';else if(/Safari\\//.test(ua)&&!/Chrome\\//.test(ua))b='Safari';
    var os='Unknown';
    if(/Windows NT 10/.test(ua))os='Windows';else if(/Mac OS X/.test(ua))os='macOS';
    else if(/Android/.test(ua))os='Android';else if(/iPhone|iPad/.test(ua))os='iOS';
    else if(/Linux/.test(ua))os='Linux';
    return b+' · '+os+' · '+(/Mobi|Android|iPhone|iPad/.test(ua)?'Mobile':'Desktop');
  }
  function flagH(c){if(!c||c.length!==2)return'';var a=0x1F1E6-65+c.toUpperCase().charCodeAt(0),b=0x1F1E6-65+c.toUpperCase().charCodeAt(1);return String.fromCodePoint(a,b);}
  function refLinkH(r,n){return r?'<a href="'+escH(r)+'" rel="noreferrer" style="color:var(--accent);text-decoration:none">'+truncH(escH(r),n)+'</a>':'Direct';}
  function agoH(t){if(!t)return'';var diff=Math.floor((Date.now()-new Date(t+'Z').getTime())/1000);if(diff<0)return'just now';if(diff<60)return diff+'s ago';if(diff<3600)return Math.floor(diff/60)+'m ago';if(diff<86400)return Math.floor(diff/3600)+'h ago';return Math.floor(diff/86400)+'d ago';}
  function devH(v){var d=v.device_type||'Unknown';var o=v.os||'';var b=v.browser||'';var line=[o,b].filter(Boolean).join(' · ');return '<span class="badge">'+escH(d)+'</span>'+(line?' '+escH(line):(v.user_agent?(' '+escH(uaH(v.user_agent))):''));}
  function locH(v){var base=escH([v.city,v.region,v.country].filter(Boolean).join(', ')||'—');var hasLat=v.latitude!=null&&v.latitude!=='',hasLon=v.longitude!=null&&v.longitude!=='';var lat=parseFloat(v.latitude),lon=parseFloat(v.longitude);var hasCoords=hasLat&&hasLon&&!isNaN(lat)&&!isNaN(lon);var bits=[];if(hasCoords)bits.push(lat.toFixed(5)+', '+lon.toFixed(5));if(v.postal_code)bits.push(escH(v.postal_code));if(!bits.length)return base;var out='<span style="font-size:0.68rem;color:var(--muted)">'+bits.join(' · ')+'</span>';if(hasCoords)out+=' <a href="https://www.google.com/maps/search/?api=1&query='+lat+','+lon+'" target="_blank" rel="noreferrer" style="color:var(--accent);font-size:0.68rem;text-decoration:none">map</a>';return base+'<div>'+out+'</div>';}
  function ispH(v){return v.isp?' <span style="font-size:0.68rem;color:var(--muted)">'+escH(v.isp)+'</span>':'';}
  // ── Search filter state ──
  var _allRecent=[];
  function rowHtml(v,seattleStyle){
    var isSea=v.city==='Seattle';
    var id=v.id||'';
    return '<tr data-id="'+id+'"'+(isSea?' style="background:rgba(0,113,227,0.04)"':'')+'><td><div>'+fmtH(v.created_at)+'</div><div style="font-size:0.7rem;color:var(--muted)">'+agoH(v.created_at)+'</div></td><td>'+locH(v)+(isSea?' <span class="badge seattle">SEA</span>':'')+'</td><td style="font-size:0.78rem">'+devH(v)+'</td><td>'+refLinkH(v.referrer,30)+'</td><td><span class="badge">'+escH((v.visitor_id||'').slice(0,8))+'</span></td></tr>';
  }
  function renderRecent(){
    var rt=document.getElementById('recentTbody');
    if(!rt)return;
    var q=(document.getElementById('recentSearch')||{}).value||'';
    q=q.trim().toLowerCase();
    var rv=_allRecent;
    if(q){rv=rv.filter(function(v){
      var hay=[v.city,v.region,v.country,v.device_type,v.os,v.browser,v.isp,v.postal_code,(v.visitor_id||'').slice(0,8),v.referrer].filter(Boolean).join(' ').toLowerCase();
      return hay.indexOf(q)!==-1;
    });}
    rt.innerHTML=rv.length?rv.map(rowHtml).join(''):'<tr><td colspan="5" class="empty-state">No visits match your filter</td></tr>';
  }
  function refresh(){
    fetch('/stats',{headers:{'Accept':'application/json'}})
      .then(function(r){if(r.status===401){location.href='/dashboard';return null;}return r.json();})
      .then(function(d){
        if(!d)return;
        var g=function(id,v){var el=document.getElementById(id);if(el)el.textContent=v;};
        g('statToday',d.totals.today);g('stat24h',d.totals.last24h);g('statTotal',d.totals.total);g('statUnique',d.totals.unique);
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
          var rx=d.referrers||[],rmax=Math.max(1,rx.length?rx[0].count:1);
          ref.innerHTML=rx.length?rx.map(function(r){var pct=(r.count/rmax)*100;return '<div class="ref-item"><span class="ref-name">'+escH(r.source)+'</span><div class="ref-bar"><div class="ref-fill" style="width:'+pct+'%"></div></div><span class="ref-count">'+r.count+'</span></div>';}).join(''):'<p class="empty-state">No referrer data</p>';
        }
        var cl=document.getElementById('countryList');
        if(cl){var cx=d.topCountries||[];
          cl.innerHTML=cx.map(function(c){return '<span class="country-chip"><strong>'+c.count+'</strong> '+flagH(c.country)+' '+escH(c.country)+'</span>';}).join('');}
        var sb=document.getElementById('seattleBanner');
        if(sb&&d.seattleStats){var s=d.seattleStats;
          sb.innerHTML='<div class="seattle-banner"><h3>Seattle Visits — All Time</h3><p>'+s.total+' total views &middot; '+s.unique+' unique visitors &middot; '+s.last30+' in last 30 days'+(s.firstSeen?' &middot; first seen '+fmtH(s.firstSeen):'')+(s.lastSeen?' &middot; <strong>last seen '+agoH(s.lastSeen)+'</strong>':'')+'</p></div>';}
        var st=document.getElementById('seattleTbody');
        if(st){var sv=d.seattleVisits||[];
          st.innerHTML=sv.length?sv.map(function(v){var id=v.id||'';return '<tr data-id="'+id+'"><td><div style="font-weight:500">'+fmtH(v.created_at)+'</div><div style="font-size:0.68rem;color:var(--muted)">'+agoH(v.created_at)+'</div></td><td>'+locH(v)+ispH(v)+'</td><td>'+refLinkH(v.referrer,28)+'</td><td style="font-size:0.78rem">'+devH(v)+'</td><td><span class="badge seattle">'+escH((v.visitor_id||'').slice(0,8))+'</span></td></tr>';}).join(''):'<tr><td colspan="5" class="empty-state">No Seattle visits recorded yet</td></tr>';}
        _allRecent=d.recent||[];
        renderRecent();
      })
      .catch(function(){});
  }
  applyTheme();
  refresh();
  setInterval(refresh,60000);
  var si=document.getElementById('recentSearch');
  if(si)si.addEventListener('input',renderRecent);

  // Profile merge — one-click: shows input for target ID
  document.addEventListener('click',function(e){
    var btn=e.target.closest('.profile-merge');
    if(!btn)return;
    e.preventDefault();e.stopPropagation();
    var src=btn.getAttribute('data-vid');
    if(!src)return;
    var cards=document.querySelectorAll('.profile-card');
    var ids=[];cards.forEach(function(c){var v=c.getAttribute('data-vid');if(v&&v!==src)ids.push(v);});
    if(!ids.length){alert('No other profiles to merge into.');return;}
    var tgt=prompt('Merge '+src.slice(0,10)+' into:\n'+ids.map(function(v,i){return '  ['+i+'] '+v.slice(0,10);}).join('\n')+'\n\nEnter number or ID:',ids[0]);
    if(!tgt)return;
    // Accept either index or full ID
    var idx=parseInt(tgt,10);
    var target=(idx>=0&&idx<ids.length)?ids[idx]:tgt.trim();
    if(target===src||ids.indexOf(target)<0){alert('Invalid target.');return;}
    if(!confirm('MERGE: '+src.slice(0,10)+' → '+target.slice(0,10)+'?'))return;
    btn.disabled=true;btn.textContent='…';
    fetch('/api/merge-visitors',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:src,target:target})})
      .then(function(r){return r.json().catch(function(){return{ok:false}});})
      .then(function(d){
        if(d&&d.ok){window.location.reload();}
        else{alert('Merge failed: '+(d&&d.error||'unknown'));btn.disabled=false;btn.textContent='merge';}
      })
      .catch(function(){alert('Network error');btn.disabled=false;btn.textContent='merge';});
  });

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

// Coord + postal detail line with a Google Maps link (shown when IP geo gave coords)
function coordH(v) {
  const hasLat = v.latitude != null && v.latitude !== '';
  const hasLon = v.longitude != null && v.longitude !== '';
  const lat = parseFloat(v.latitude);
  const lon = parseFloat(v.longitude);
  const hasCoords = hasLat && hasLon && !isNaN(lat) && !isNaN(lon);
  const bits = [];
  if (hasCoords) bits.push(lat.toFixed(5) + ', ' + lon.toFixed(5));
  if (v.postal_code) bits.push(esc(v.postal_code));
  if (!bits.length) return '';
  let out = '<span style="font-size:0.68rem;color:var(--muted)">' + bits.join(' · ') + '</span>';
  if (hasCoords) {
    out += ' <a href="https://www.google.com/maps/search/?api=1&query=' + lat + ',' + lon
      + '" target="_blank" rel="noreferrer" style="color:var(--accent);font-size:0.68rem;text-decoration:none">map</a>';
  }
  return '<div>' + out + '</div>';
}

// User‑agent parser — returns short display string \+ structured fields
function parseUA(ua) {
  if (!ua) return 'Unknown';
  let browser = 'Other';
  if (/Edg\//.test(ua)) browser = 'Edge';
  else if (/Chrome\//.test(ua) && !/Chromium\//.test(ua)) browser = 'Chrome';
  else if (/Firefox\//.test(ua)) browser = 'Firefox';
  else if (/Safari\//.test(ua) && !/Chrome\//.test(ua)) browser = 'Safari';
  let os = 'Unknown';
  if (/Windows NT 10/.test(ua)) os = 'Windows';
  else if (/Mac OS X/.test(ua)) os = 'macOS';
  else if (/Android/.test(ua)) os = 'Android';
  else if (/iPhone|iPad/.test(ua)) os = 'iOS';
  else if (/Linux/.test(ua)) os = 'Linux';
  const mobile = /Mobi|Android|iPhone|iPad/.test(ua);
  const device = mobile ? 'Mobile' : 'Desktop';
  return browser + ' · ' + os + ' · ' + device;
}

function parseUADetailed(ua) {
  if (!ua) return { device: 'Unknown', os: 'Unknown', browser: 'Unknown' };
  let browser = 'Unknown';
  if (/Edg\//.test(ua)) browser = 'Edge';
  else if (/SamsungBrowser\//.test(ua)) browser = 'Samsung';
  else if (/Chrome\//.test(ua) && !/Chromium\//.test(ua)) browser = 'Chrome';
  else if (/Firefox\//.test(ua)) browser = 'Firefox';
  else if (/Safari\//.test(ua) && !/Chrome\//.test(ua) && !/Chromium\//.test(ua)) browser = 'Safari';
  let os = 'Unknown';
  if (/Windows NT 10/.test(ua)) os = 'Windows';
  else if (/Mac OS X/.test(ua)) os = 'macOS';
  else if (/Android/.test(ua)) os = 'Android';
  else if (/iPhone/.test(ua)) os = 'iOS';
  else if (/iPad/.test(ua)) os = 'iPadOS';
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
