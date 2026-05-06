export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/log-visit') {
      return handleLogVisit(request, env);
    }

    if (path === '/dashboard') {
      return handleDashboard(request, env);
    }

    if (path === '/stats') {
      return handleStats(request, env);
    }

    return new Response('Not Found', { status: 404 });
  },
};

// ── Rate limiter (in-memory, per-IP, resets on deploy) ──
const rateMap = new Map();
const RATE_WINDOW_MS = 10_000;
const MAX_PER_WINDOW = 3;

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateMap.get(ip);
  if (!entry || now - entry.start > RATE_WINDOW_MS) {
    rateMap.set(ip, { start: now, count: 1 });
    return false;
  }
  entry.count++;
  if (entry.count > MAX_PER_WINDOW) return true;
  return false;
}

// ── Session token helpers ──
async function createSessionToken(env) {
  const payload = JSON.stringify({
    exp: Date.now() + 3600_000, // 1 hour
    rand: crypto.randomUUID(),
  });
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
    if (Date.now() > payload.exp) return false;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(env.DASHBOARD_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sig = new Uint8Array(s.split('').map(c => c.charCodeAt(0)));
    return crypto.subtle.verify('HMAC', key, sig, enc.encode(p));
  } catch (_) {
    return false;
  }
}

// ── POST /log-visit ──
async function handleLogVisit(request, env) {
  const corsHeaders = {
    'Access-Control-Allow-Origin': 'https://shoaibsprojects.github.io',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405, headers: corsHeaders });
  }

  // Rate limit by IP
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (isRateLimited(ip)) {
    return Response.json({ ok: false, reason: 'rate_limited' }, { status: 429, headers: corsHeaders });
  }

  let body = {};
  try {
    body = await request.json();
  } catch (_) {
    // body can be empty
  }

  // Validate shared secret to prevent unauthenticated requests
  if (!body.key || body.key !== env.LOG_KEY) {
    return Response.json({ ok: false, reason: 'unauthorized' }, { status: 401, headers: corsHeaders });
  }

  // Validate pageUrl to prevent junk data
  const pageUrl = body.pageUrl || null;
  if (pageUrl && !pageUrl.startsWith('https://shoaibsprojects.github.io/') && !pageUrl.startsWith('http://localhost')) {
    return Response.json({ ok: false, reason: 'invalid_page_url' }, { status: 400, headers: corsHeaders });
  }

  const cf = request.cf || {};
  const visitorId = getVisitorId(request);

  const stmt = env.DB.prepare(
    `INSERT INTO page_views (country, city, region, timezone, user_agent, referrer, page_url, visitor_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );

  await stmt.bind(
    cf.country || null,
    cf.city || null,
    cf.region || null,
    cf.timezone || null,
    request.headers.get('User-Agent') || null,
    body.referrer || request.headers.get('Referer') || null,
    pageUrl,
    visitorId
  ).run();

  const response = Response.json({ ok: true }, { headers: corsHeaders });

  if (!request.headers.get('Cookie')?.includes('visitor_id=')) {
    response.headers.set(
      'Set-Cookie',
      `visitor_id=${visitorId}; Max-Age=31536000; Path=/; SameSite=Lax; Secure; HttpOnly`
    );
  }

  return response;
}

function getVisitorId(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/visitor_id=([^;]+)/);
  return match ? match[1] : crypto.randomUUID();
}

// ── GET/POST /dashboard ──
async function handleDashboard(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const sessionMatch = cookie.match(/session=([^;]+)/);

  // POST: authenticate and set session cookie
  if (request.method === 'POST') {
    let body;
    try {
      body = await request.formData();
    } catch (_) {
      try { body = await request.json(); } catch (__) { body = null; }
    }
    const key = body?.get?.('key') || body?.key || '';
    if (key !== env.DASHBOARD_KEY) {
      return new Response(loginPage('Invalid key'), {
        status: 401,
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }
    const token = await createSessionToken(env);
    const html = await renderDashboard(env.DB);
    const res = new Response(html, {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' },
    });
    res.headers.set(
      'Set-Cookie',
      `session=${token}; Max-Age=3600; Path=/; SameSite=Strict; Secure; HttpOnly`
    );
    return res;
  }

  // GET: verify session cookie
  if (sessionMatch && await verifySessionToken(sessionMatch[1], env)) {
    const html = await renderDashboard(env.DB);
    return new Response(html, {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' },
    });
  }

  return new Response(loginPage(), {
    status: 401,
    headers: { 'Content-Type': 'text/html;charset=UTF-8' },
  });
}

async function renderDashboard(db) {
  const [totals, topCountries, recentVisits] = await Promise.all([
    queryStats(db),
    queryTopCountries(db),
    queryRecent(db),
  ]);
  return dashboardHtml(totals, topCountries, recentVisits);
}

// ── GET /stats (JSON) ──
async function handleStats(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const sessionMatch = cookie.match(/session=([^;]+)/);

  if (!sessionMatch || !(await verifySessionToken(sessionMatch[1], env))) {
    return new Response(JSON.stringify({ error: 'unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const [totals, topCountries] = await Promise.all([
    queryStats(env.DB),
    queryTopCountries(env.DB),
  ]);

  return Response.json({ totals, topCountries });
}

// ── DB queries ──
async function queryStats(db) {
  const total = await db.prepare('SELECT COUNT(*) as count FROM page_views').first();
  const unique = await db.prepare('SELECT COUNT(DISTINCT visitor_id) as count FROM page_views').first();
  const today = await db.prepare(
    "SELECT COUNT(*) as count FROM page_views WHERE date(created_at) = date('now')"
  ).first();
  const last24h = await db.prepare(
    "SELECT COUNT(*) as count FROM page_views WHERE created_at >= datetime('now', '-1 day')"
  ).first();

  return {
    total: total?.count || 0,
    unique: unique?.count || 0,
    today: today?.count || 0,
    last24h: last24h?.count || 0,
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
    `SELECT created_at, country, city, region, referrer, page_url, visitor_id
     FROM page_views
     ORDER BY created_at DESC
     LIMIT 100`
  ).all();
  return results || [];
}

// ── HTML pages ──
function loginPage(msg) {
  const errorHtml = msg ? `<p style="color:#d32f2f;margin-bottom:1rem;font-size:0.85rem">${esc(msg)}</p>` : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Page View Dashboard</title>
<meta name="robots" content="noindex, nofollow">
<style>
  *,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Segoe UI',system-ui,sans-serif;background:#f5f5f7;color:#1d1d1f;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .box{background:#fff;padding:3rem;border-radius:18px;box-shadow:0 2px 12px rgba(0,0,0,0.08);text-align:center;max-width:400px;width:90%}
  input{width:100%;padding:12px 16px;border:1px solid #d2d2d7;border-radius:10px;font-size:16px;margin:1rem 0;font-family:inherit}
  input:focus{outline:2px solid #0071e3;outline-offset:2px}
  button{background:#0071e3;color:#fff;border:none;padding:12px 32px;border-radius:10px;font-size:16px;cursor:pointer;font-family:inherit;font-weight:500}
  button:hover{background:#0077ed}
</style>
</head>
<body>
<div class="box">
  <h1 style="font-size:1.5rem;margin-bottom:0.5rem">Dashboard Access</h1>
  <p style="color:#86868b;margin-bottom:1rem">Enter access key to continue</p>
  ${errorHtml}
  <form method="POST" action="/dashboard">
    <input type="password" name="key" placeholder="Access Key" autofocus autocomplete="off">
    <button type="submit">View Dashboard</button>
  </form>
</div>
</body>
</html>`;
}

function dashboardHtml(totals, countries, visits) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Page View Dashboard</title>
<meta name="robots" content="noindex, nofollow">
<style>
  *,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Segoe UI',system-ui,sans-serif;background:#f5f5f7;color:#1d1d1f;padding:2rem}
  .container{max-width:1000px;margin:0 auto}
  h1{font-size:2rem;font-weight:700;margin-bottom:0.25rem}
  .subtitle{color:#86868b;margin-bottom:0.5rem;font-size:0.9rem}
  .logout{float:right;color:#86868b;font-size:0.8rem;text-decoration:none;margin-top:-1.5rem}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:2rem}
  .stat-card{background:#fff;padding:1.5rem;border-radius:14px;box-shadow:0 1px 4px rgba(0,0,0,0.06)}
  .stat-value{font-size:2rem;font-weight:700;color:#0071e3}
  .stat-label{font-size:0.8rem;color:#86868b;text-transform:uppercase;letter-spacing:0.05em;margin-top:0.25rem}
  .section{margin-bottom:2rem}
  h2{font-size:1.2rem;font-weight:600;margin-bottom:1rem}
  .country-list{display:flex;flex-wrap:wrap;gap:0.5rem;margin-bottom:2rem}
  .country-chip{background:#fff;padding:0.5rem 1rem;border-radius:20px;font-size:0.85rem;box-shadow:0 1px 3px rgba(0,0,0,0.06)}
  .country-chip strong{color:#0071e3}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,0.06)}
  th,td{padding:12px 16px;text-align:left;font-size:0.85rem}
  th{background:#f5f5f7;font-weight:600;color:#6e6e73;text-transform:uppercase;letter-spacing:0.03em;font-size:0.75rem}
  td{border-bottom:1px solid #f5f5f7}
  tr:last-child td{border-bottom:none}
  .badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:0.75rem;font-weight:500;background:#e8f5e9;color:#2e7d32}
  .refresh{color:#86868b;font-size:0.8rem;margin-top:2rem;text-align:center}
  @media(max-width:600px){body{padding:1rem} .stats{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="container">
  <a href="/dashboard" class="logout" title="Session expires after 1 hour of inactivity">Logout</a>
  <h1>Page View Dashboard</h1>
  <p class="subtitle">Real-time visit tracking for your profile page</p>
  <div class="stats">
    <div class="stat-card"><div class="stat-value">${totals.today}</div><div class="stat-label">Today</div></div>
    <div class="stat-card"><div class="stat-value">${totals.last24h}</div><div class="stat-label">Last 24 Hours</div></div>
    <div class="stat-card"><div class="stat-value">${totals.total}</div><div class="stat-label">Total Views</div></div>
    <div class="stat-card"><div class="stat-value">${totals.unique}</div><div class="stat-label">Unique Visitors</div></div>
  </div>
  ${countries.length ? `
  <div class="section">
    <h2>Top Countries</h2>
    <div class="country-list">
      ${countries.map(c => `<span class="country-chip"><strong>${c.count}</strong> ${flag(c.country)} ${c.country}</span>`).join('')}
    </div>
  </div>` : ''}
  <div class="section">
    <h2>Recent Visits</h2>
    <table>
      <thead><tr><th>Time (CST)</th><th>Location</th><th>Source</th><th>Visitor</th></tr></thead>
      <tbody>
        ${visits.map(v => `
          <tr>
            <td>${formatTime(v.created_at)}</td>
            <td>${[v.city, v.region, v.country].filter(Boolean).join(', ') || 'Unknown'}</td>
            <td>${v.referrer ? '<a href="'+esc(v.referrer)+'" rel="noreferrer" style="color:#0071e3;text-decoration:none">'+truncate(esc(v.referrer),30)+'</a>' : 'Direct'}</td>
            <td><span class="badge">${v.visitor_id.slice(0,8)}</span></td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>
  <p class="refresh">Auto-refreshes when you reload &middot; All times in CST</p>
</div>
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
