import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import worker from './index.js';

const A = 'fp-aaaaaaaaaaaa';
const B = 'fp-bbbbbbbbbbbb';
const C = 'fp-cccccccccccc';

function d1(sqlite) {
  return {
    prepare(sql) {
      return {
        bind(...args) {
          const stmt = sqlite.prepare(sql);
          return {
            async first() { return stmt.get(...args) || null; },
            async all() { return { results: stmt.all(...args) }; },
            async run() { const result = stmt.run(...args); return { meta: { changes: result.changes }, changes: result.changes }; },
          };
        },
        async first() { return sqlite.prepare(sql).get() || null; },
        async all() { return { results: sqlite.prepare(sql).all() }; },
        async run() { const result = sqlite.prepare(sql).run(); return { meta: { changes: result.changes }, changes: result.changes }; },
      };
    },
    async batch(statements) {
      sqlite.exec('BEGIN');
      try {
        const results = [];
        for (const statement of statements) results.push(await statement.run());
        sqlite.exec('COMMIT');
        return results;
      } catch (error) {
        sqlite.exec('ROLLBACK');
        throw error;
      }
    },
  };
}

async function session(db, key) {
  const jti = 'test-session';
  const exp = Math.floor(Date.now() / 1000) + 3600;
  db.prepare('INSERT INTO sessions (jti, exp) VALUES (?, ?)').run(jti, exp);
  const p = JSON.stringify({ exp, jti });
  const hmac = await webcrypto.subtle.importKey('raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const bytes = new Uint8Array(await webcrypto.subtle.sign('HMAC', hmac, new TextEncoder().encode(p)));
  return btoa(JSON.stringify({ p, s: Array.from(bytes, byte => String.fromCharCode(byte)).join('') }));
}

test('manual links preserve raw visits and can be separated', async () => {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE page_views (
    id INTEGER PRIMARY KEY, created_at TEXT DEFAULT (datetime('now')), visitor_id TEXT,
    country TEXT, city TEXT, region TEXT, timezone TEXT, user_agent TEXT, referrer TEXT,
    page_url TEXT, device_type TEXT, os TEXT, browser TEXT, latitude REAL, longitude REAL,
    postal_code TEXT, isp TEXT, language TEXT, ip_hash TEXT, colo TEXT
  );
  CREATE TABLE page_engagement (
    id INTEGER PRIMARY KEY, created_at TEXT DEFAULT (datetime('now')), visitor_id TEXT,
    session_id TEXT, event_type TEXT, page_url TEXT, x INTEGER, y INTEGER, target TEXT,
    extra TEXT, section TEXT, cls TEXT, href TEXT
  );
  CREATE TABLE sessions (jti TEXT PRIMARY KEY, exp INTEGER NOT NULL);
  CREATE TABLE rate_limits (ip TEXT, scope TEXT, bucket INTEGER, count INTEGER, PRIMARY KEY(ip,scope,bucket));`);
  sqlite.exec(readFileSync(new URL('../migrations/0001_identity_links.sql', import.meta.url), 'utf8'));
  const insert = sqlite.prepare("INSERT INTO page_views (visitor_id, city, region, country, device_type, os, browser) VALUES (?, 'Austin', 'Texas', 'US', 'Mobile', 'iOS', 'Safari')");
  insert.run(A); insert.run(A); insert.run(B); insert.run(C);
  sqlite.prepare("INSERT INTO page_engagement (visitor_id, session_id, event_type, target) VALUES (?, 's1', 'click', 'CTA')").run(A);
  const env = { DB: d1(sqlite), DASHBOARD_KEY: 'test-key' };
  const token = await session(sqlite, env.DASHBOARD_KEY);
  const request = (path, body, origin = 'https://example.workers.dev') => worker.fetch(new Request('https://example.workers.dev' + path, {
    method: body ? 'POST' : 'GET',
    headers: { Cookie: '__Host-session=' + token, Origin: origin, 'Content-Type': 'application/json', 'User-Agent': 'Test Browser' },
    body: body ? JSON.stringify(body) : undefined,
  }), env, {});
  const stats = async () => (await (await request('/stats')).json());
  assert.equal((await stats()).totals.unique, 3);
  assert.equal((await request('/api/merge-visitors', { source: A, target: B }, 'https://attacker.example')).status, 403);
  assert.equal(sqlite.prepare('SELECT COUNT(*) AS n FROM visitor_identity_links').get().n, 0);
  const merged = await (await request('/api/merge-visitors', { source: A, target: B })).json();
  assert.equal(merged.ok, true);
  assert.equal((await stats()).totals.unique, 2);
  assert.equal((await stats()).profiles.find(p => p.id === B).visits, 3);
  assert.equal(sqlite.prepare('SELECT visitor_id FROM page_views WHERE id = 1').get().visitor_id, A);
  assert.equal(sqlite.prepare('SELECT visitor_id FROM page_engagement WHERE id = 1').get().visitor_id, A);
  assert.equal((await (await request('/api/merge-visitors', { source: B, target: C })).json()).ok, true);
  assert.deepEqual(sqlite.prepare('SELECT visitor_id FROM visitor_identity_links WHERE canonical_id = ? ORDER BY visitor_id').all(C).map(r => r.visitor_id), [A, B]);
  const separated = await (await request('/api/unmerge-visitor', { visitorId: A, canonicalId: C })).json();
  assert.equal(separated.ok, true);
  assert.equal((await stats()).totals.unique, 2);
  assert.equal((await stats()).profiles.find(p => p.id === A).visits, 2);
  assert.equal((await (await request('/api/unmerge-visitor', { visitorId: B, canonicalId: C })).json()).ok, true);
  assert.equal((await stats()).totals.unique, 3);
  assert.equal(sqlite.prepare('SELECT COUNT(*) AS n FROM visitor_identity_events').get().n, 4);
  const html = await (await request('/dashboard')).text();
  assert.match(html, /Identity studio/);
  assert.match(html, /IP-based estimate/);
  assert.doesNotMatch(html, /30\.\d{5}, -97\.\d{5}/);
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  for (const script of scripts) new Function(script[1]);
  sqlite.close();
});
