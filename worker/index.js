var VERSION = '3.3.0'; // bump when you change the worker code

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
  const visitorId = getVisitorId(request);
  const language = (request.headers.get('Accept-Language') || '').split(',')[0]?.trim() || null;
  const uaParsed = parseUADetailed(ua);

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

  console.log(JSON.stringify({ event: 'visit', ip, city: cf.city || null, country: cf.country || null }));

  const response = Response.json({ ok: true }, { headers: base });

  if (!request.headers.get('Cookie')?.includes('visitor_id=')) {
    response.headers.set(
      'Set-Cookie',
      `visitor_id=${visitorId}; Max-Age=31536000; Path=/; SameSite=Lax; Secure; HttpOnly`
    );
  }

  return response;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function getVisitorId(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/visitor_id=([^;]+)/);
  if (match && UUID_RE.test(match[1])) return match[1];
  return crypto.randomUUID();
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
    const [totals, topCountries, recentVisits, seattleStats, seattleVisits, trend, referrers] = await Promise.all([
      queryStats(db),
      queryTopCountries(db),
      queryRecent(db),
      querySeattleStats(db),
      querySeattleAll(db),
      queryTrend(db, 30),
      queryTopReferrers(db)
    ]);
    return dashboardHtml(totals, topCountries, recentVisits, seattleStats, seattleVisits, trend, referrers);
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

  const [totals, topCountries, trend, referrers, seattleStats, seattleVisits, recent] = await Promise.all([
    queryStats(env.DB),
    queryTopCountries(env.DB),
    queryTrend(env.DB, 30),
    queryTopReferrers(env.DB),
    querySeattleStats(env.DB),
    querySeattleAll(env.DB),
    queryRecent(env.DB),
  ]);

  return Response.json({ totals, topCountries, trend, referrers, seattleStats, seattleVisits, recent }, { headers: jsonHeaders });
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
    `SELECT created_at, country, city, region, referrer, page_url, visitor_id, device_type, os, browser
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
  :root{--bg:#f5f5f7;--surface:#fff;--text:#1d1d1f;--muted:#86868b;--accent:#0071e3}
  html[data-theme="dark"]{--bg:#1d1d1f;--surface:#2d2d2f;--text:#f5f5f7;--muted:#a1a1a6;--accent:#2997ff}
  @media (prefers-color-scheme: dark){
    :root{--bg:#1d1d1f;--surface:#2d2d2f;--text:#f5f5f7;--muted:#a1a1a6;--accent:#2997ff}
  }
  body{font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);display:flex;align-items:center;justify-content:center;min-height:100vh}
  .box{background:var(--surface);padding:3rem;border-radius:18px;box-shadow:0 2px 12px rgba(0,0,0,0.08);text-align:center;max-width:400px;width:90%;position:relative}
  .theme-toggle{position:absolute;top:1rem;right:1rem;background:none;color:var(--muted);border:1px solid var(--muted);padding:0.35rem 0.7rem;border-radius:8px;font-size:0.75rem;cursor:pointer;font-family:inherit}
  .theme-toggle:hover{color:var(--accent)}
  input{width:100%;padding:12px 16px;border:1px solid var(--muted);border-radius:10px;font-size:16px;margin:1rem 0;font-family:inherit;background:var(--bg);color:var(--text)}
  input:focus{outline:2px solid var(--accent);outline-offset:2px}
  button{background:var(--accent);color:#fff;border:none;padding:12px 32px;border-radius:10px;font-size:16px;cursor:pointer;font-family:inherit;font-weight:500}
  button:hover{opacity:0.9}
  .pw-wrap{position:relative;margin:1rem 0}
  .pw-wrap input{margin:0;padding-right:48px}
  .eye-btn{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;border:none;padding:8px;cursor:pointer;color:var(--muted);display:flex;align-items:center;justify-content:center}
  .eye-btn:hover{color:var(--accent)}
  .eye-btn svg{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
  .cf-turnstile{display:flex;justify-content:center;margin:1rem 0}
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

function dashboardHtml(totals, countries, visits, seattleStats, seattleVisits, trend, referrers) {
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
    return '<tr><td><div style="font-weight:500">' + formatTime(v.created_at) + '</div><div style="font-size:0.68rem;color:var(--muted)">' + ago + '</div></td>'
      + '<td>' + esc(loc) + ispExtra + '</td>'
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
    return '<tr' + (isSea ? ' style="background:rgba(0,113,227,0.04)"' : '') + '>'
      + '<td><div>' + formatTime(v.created_at) + '</div><div style="font-size:0.7rem;color:var(--muted)">' + ago + '</div></td>'
      + '<td>' + esc(loc) + (isSea ? ' <span class="badge seattle">SEA</span>' : '') + '</td>'
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
<style>
  *,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
  :root{--bg:#f5f5f7;--surface:#fff;--text:#1d1d1f;--muted:#86868b;--dim:#6e6e73;
    --border:#f0f0f2;--accent:#0071e3;--chip-shadow:0 1px 3px rgba(0,0,0,0.06);
    --card-shadow:0 1px 4px rgba(0,0,0,0.06);--header-bg:#f5f5f7}
  html[data-theme="dark"]{--bg:#1d1d1f;--surface:#2d2d2f;--text:#f5f5f7;--muted:#a1a1a6;
    --dim:#86868b;--border:#3a3a3d;--accent:#2997ff;--chip-shadow:0 1px 3px rgba(0,0,0,0.3);
    --card-shadow:0 1px 4px rgba(0,0,0,0.3);--header-bg:#1d1d1f}
  body{font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Segoe UI',system-ui,sans-serif;
    background:var(--bg);color:var(--text);padding:2rem;transition:background 0.3s,color 0.3s}
  .container{max-width:1000px;margin:0 auto}
  .top-bar{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:1.5rem;flex-wrap:wrap;gap:1rem}
  h1{font-size:2rem;font-weight:700;margin-bottom:0.25rem}
  .subtitle{color:var(--muted);margin-bottom:0.5rem;font-size:0.9rem}
  .top-actions{display:flex;align-items:center;gap:0.6rem}
  .theme-toggle,.logout{background:var(--surface);color:var(--muted);font-size:0.8rem;text-decoration:none;
    padding:0.4rem 0.9rem;border-radius:8px;border:1px solid var(--border);cursor:pointer;font-family:inherit}
  .theme-toggle:hover,.logout:hover{color:var(--accent)}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:1.5rem}
  .stat-card{background:var(--surface);padding:1.5rem;border-radius:14px;box-shadow:var(--card-shadow);
    transition:transform 0.2s,box-shadow 0.2s}
  .stat-card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,0.1)}
  .stat-value{font-size:2rem;font-weight:700;color:var(--accent)}
  .stat-label{font-size:0.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.05em;margin-top:0.25rem}
  .grid-2{display:grid;grid-template-columns:1.4fr 1fr;gap:1rem;margin-bottom:1.5rem}
  @media(max-width:768px){.grid-2{grid-template-columns:1fr}}
  .card{background:var(--surface);border-radius:14px;padding:1.5rem;box-shadow:var(--card-shadow);margin-bottom:1.5rem}
  h2{font-size:1.15rem;font-weight:600;margin-bottom:1rem}
  .trend-wrap{position:relative;padding-top:0.5rem}
  svg.trend{width:100%;height:60px;display:block}
  .trend-poly{fill:rgba(0,113,227,0.08);stroke:var(--accent);stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
  html[data-theme="dark"] .trend-poly{fill:rgba(41,151,255,0.1)}
  .trend-date{font-size:0.7rem;color:var(--muted);display:flex;justify-content:space-between;margin-top:0.5rem}
  .ref-item{display:flex;justify-content:space-between;align-items:center;padding:0.6rem 0;border-bottom:1px solid var(--border)}
  .ref-item:last-child{border-bottom:none}
  .ref-name{font-size:0.85rem;font-weight:500;max-width:40%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .ref-bar{flex:1;margin:0 1rem;height:6px;background:var(--bg);border-radius:3px;overflow:hidden}
  .ref-fill{height:100%;background:var(--accent);border-radius:3px;transition:width 0.4s ease}
  .ref-count{font-size:0.8rem;color:var(--muted);font-weight:600;min-width:2.5rem;text-align:right}
  .country-list{display:flex;flex-wrap:wrap;gap:0.5rem}
  .country-chip{background:var(--surface);padding:0.5rem 1rem;border-radius:20px;font-size:0.85rem;box-shadow:var(--chip-shadow)}
  .country-chip strong{color:var(--accent)}
  .table-wrap{background:var(--surface);border-radius:14px;overflow:hidden;box-shadow:var(--card-shadow)}
  table{width:100%;border-collapse:collapse;background:var(--surface);border-radius:14px}
  th,td{padding:10px 14px;text-align:left;font-size:0.82rem;white-space:nowrap}
  th{background:var(--header-bg);font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:0.03em;font-size:0.7rem}
  td{border-bottom:1px solid var(--border)}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:rgba(0,0,0,0.015)}
  html[data-theme="dark"] tr:hover td{background:rgba(255,255,255,0.03)}
  .badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:0.7rem;font-weight:500;background:#e8f5e9;color:#2e7d32}
  html[data-theme="dark"] .badge{background:#1b3a1f;color:#81c784}
  .badge.seattle{background:#e3f2fd;color:#1565c0}
  html[data-theme="dark"] .badge.seattle{background:#0d2944;color:#64b5f6}
  .table-scroll-x{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;border-radius:var(--radius)}
  .table-scroll-y{max-height:520px;width:100%;overflow-y:auto;-webkit-overflow-scrolling:touch}
  .table-scroll-y table{box-shadow:none;border-radius:0}
  .table-scroll-y thead th{position:sticky;top:0;z-index:1}
  .seattle-card{border-left:3px solid var(--accent)}
  .empty-state{color:var(--muted);font-size:0.85rem;text-align:center;padding:2rem 0}
  .auto-refresh{display:flex;align-items:center;gap:0.4rem;font-size:0.75rem;color:var(--muted);margin-top:1.5rem;text-align:center;justify-content:center}
  .dot{width:8px;height:8px;border-radius:50%;background:#34c759;display:inline-block;animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.3}}
  .seattle-banner{background:linear-gradient(135deg,#e3f2fd,#bbdefb);color:#0d47a1;padding:1.25rem 1.5rem;border-radius:14px;margin-bottom:1rem}
  html[data-theme="dark"] .seattle-banner{background:linear-gradient(135deg,#0d1b2a,#1b3a5c);color:#64b5f6}
  .seattle-banner h3{font-size:1.1rem;font-weight:600;margin-bottom:0.25rem}
  .seattle-banner p{font-size:0.8rem;opacity:0.85}
  @media(max-width:600px){body{padding:1rem}.stats{grid-template-columns:repeat(2,1fr)}.card{padding:1rem}.seattle-banner{padding:1rem}}
</style>
</head>
<body>
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
    <div class="stat-card"><div class="stat-value" id="statToday">${totals.today}</div><div class="stat-label">Today</div></div>
    <div class="stat-card"><div class="stat-value" id="stat24h">${totals.last24h}</div><div class="stat-label">Last 24 Hours</div></div>
    <div class="stat-card"><div class="stat-value" id="statTotal">${totals.total}</div><div class="stat-label">Total Views</div></div>
    <div class="stat-card"><div class="stat-value" id="statUnique">${totals.unique}</div><div class="stat-label">Unique Visitors</div></div>
  </div>

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
<thead><tr><th>Time (CST)</th><th>Location · ISP</th><th>Source</th><th>Device · OS</th><th>Visitor</th></tr></thead>
           <tbody id="seattleTbody">${seattleRows}</tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Recent Visits</h2>
    <div class="table-scroll-x">
      <table>
        <thead><tr><th>Time (CST)</th><th>Location</th><th>Device · OS</th><th>Source</th><th>Visitor</th></tr></thead>
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
          sb.innerHTML='<div class="seattle-banner"><h3>Seattle Visits — All Time</h3><p>'+s.total+' total views &middot; '+s.unique+' unique visitors &middot; '+s.last30+' in last 30 days'+(s.firstSeen?' &middot; first seen '+fmtH(s.firstSeen):'')+'</p></div>';}
        var st=document.getElementById('seattleTbody');
        if(st){var sv=d.seattleVisits||[];
          st.innerHTML=sv.length?sv.map(function(v){return '<tr><td>'+fmtH(v.created_at)+'</td><td>'+escH([v.region,v.country].filter(Boolean).join(', ')||'—')+'</td><td>'+refLinkH(v.referrer,28)+'</td><td style="font-size:0.78rem;color:var(--muted)">'+uaH(v.user_agent)+'</td><td><span class="badge seattle">'+escH((v.visitor_id||'').slice(0,8))+'</span></td></tr>';}).join(''):'<tr><td colspan="5" class="empty-state">No Seattle visits recorded yet</td></tr>';}
        var rt=document.getElementById('recentTbody');
        if(rt){var rv=d.recent||[];
          rt.innerHTML=rv.map(function(v){var isSea=v.city==='Seattle';return '<tr'+(isSea?' style="background:rgba(0,113,227,0.04)"':'')+'><td>'+fmtH(v.created_at)+'</td><td>'+escH([v.city,v.region,v.country].filter(Boolean).join(', ')||'Unknown')+(isSea?' <span class="badge seattle">SEA</span>':'')+'</td><td>'+refLinkH(v.referrer,30)+'</td><td><span class="badge">'+escH((v.visitor_id||'').slice(0,8))+'</span></td></tr>';}).join('');}
      })
      .catch(function(){});
  }
  applyTheme();
  refresh();
  setInterval(refresh,60000);
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
