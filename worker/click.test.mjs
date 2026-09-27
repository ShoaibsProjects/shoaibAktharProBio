import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { DatabaseSync } from 'node:sqlite';
import { timingSafeEqual } from 'node:crypto';
import worker from './index.js';

if (!crypto.subtle.timingSafeEqual) {
  crypto.subtle.timingSafeEqual = (left, right) => timingSafeEqual(Buffer.from(left), Buffer.from(right));
}

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const start = html.lastIndexOf('(function ', html.indexOf('var WORKER_URL ='));
const end = html.indexOf('})();', start) + 5;
assert.ok(start > 0 && end > start);
const activityScript = html.slice(start, end);

test('authored control IDs are unique', () => {
  const ids = [...html.matchAll(/data-analytics-id="([^"]+)"/g)].map(match => match[1]);
  assert.ok(ids.length >= 14);
  assert.equal(new Set(ids).size, ids.length);
});

function element(tag, attrs = {}, parent = null) {
  return {
    nodeType: 1, tagName: tag.toUpperCase(), parentElement: parent,
    id: attrs.id || '', textContent: attrs.text || '',
    hasAttribute(name) { return Object.hasOwn(attrs, name); },
    getAttribute(name) { return attrs[name] ?? null; },
    querySelector(selector) { return selector === '.section-title' && attrs.heading ? { textContent: attrs.heading } : null; },
    matches(selector) {
      if (selector === '.fancybox__container') return (attrs.class || '').split(' ').includes('fancybox__container');
      if (selector === 'section') return tag === 'section';
      const link = tag === 'a' && !!attrs.href;
      const role = attrs.role;
      if (selector === 'a[href],[role="link"]') return link || role === 'link';
      if (selector === 'a[href],button,summary,[role="button"],[role="link"]') return link || tag === 'button' || tag === 'summary' || role === 'button' || role === 'link';
      return false;
    },
  };
}

function activityHarness(firstVisit = false) {
  const calls = [];
  let onClick;
  const body = element('body');
  const document = { body, addEventListener(name, handler) { if (name === 'click') onClick = handler; } };
  const location = { href: 'https://example.test/page?private=secret#fragment', origin: 'https://example.test', pathname: '/page' };
  const window = { innerWidth: 1440, innerHeight: 900, addEventListener() {} };
  const tab = firstVisit ? {} : { _pv_logged: '1', _pv_sid: 'sid' };
  const sessionStorage = { getItem(key) { return tab[key] || null; }, setItem(key, value) { tab[key] = value; } };
  const localStorage = { getItem() { return firstVisit ? null : 'fp-aaaaaaaaaaaa'; }, setItem() {} };
  runInNewContext(activityScript, {
    document, location, window, sessionStorage, localStorage, URL,
    setInterval() {},
    fetch(url, options) {
      calls.push({ path: new URL(url).pathname, body: JSON.parse(options.body) });
      return Promise.resolve({ json: () => Promise.resolve({ visitor_id: 'fp-aaaaaaaaaaaa' }) });
    },
  });
  return {
    body, calls,
    click(path, options = {}) {
      onClick({ target: path[0], composedPath: () => [...path, document], isTrusted: true,
        detail: 1, clientX: 1203, clientY: 78, ...options });
      return calls.at(-1)?.body;
    },
  };
}

test('nested site controls keep their authored names and strip URL queries', () => {
  const h = activityHarness();
  const main = element('main', { 'data-analytics-root': '' }, h.body);
  const section = element('section', { heading: 'Photo gallery' }, main);
  const link = element('a', { href: '/photo2.jpg?token=private', 'data-analytics-id': 'gallery.photo-2', 'data-analytics-label': 'Open photo 2' }, section);
  const img = element('img', {}, link);
  const event = h.click([img, link, section, main, h.body]);
  assert.equal(event.target, 'Open photo 2');
  assert.equal(event.action_id, 'gallery.photo-2');
  assert.equal(event.label_quality, 'named');
  assert.equal(event.section, 'Photo gallery');
  assert.equal(event.source, 'site');
  assert.equal(event.href, 'https://example.test/photo2.jpg');
  assert.equal(event.pageUrl, 'https://example.test/page');
  assert.equal(event.viewport_w, 1440);
});

test('outside elements are unidentified rather than guessed, and both quick clicks count', () => {
  const h = activityHarness();
  const host = element('div', { id: 'tav-host', text: 'Private overlay text' }, h.body);
  const first = h.click([host, h.body]);
  h.click([host, h.body]);
  assert.equal(h.calls.length, 2);
  assert.equal(first.target, 'Unidentified element outside site content');
  assert.equal(first.source, 'outside');
  assert.equal(first.label_quality, 'unknown');
  assert.equal(first.section, 'Outside site content');
  assert.equal(first.href, '');
  assert.ok(!JSON.stringify(first).includes('Private overlay text'));
});

test('a quick first-visit tap waits for the visitor ID instead of being lost', async () => {
  const h = activityHarness(true);
  const nav = element('nav', { 'data-analytics-root': '', 'data-analytics-section': 'Navigation' }, h.body);
  const link = element('a', { href: '#top', 'data-analytics-id': 'nav.home', 'data-analytics-label': 'Home navigation' }, nav);
  h.click([link, nav, h.body]);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].path, '/log-visit');
  await new Promise(resolve => setImmediate(resolve));
  const clicks = h.calls.filter(call => call.path === '/event' && call.body.event_type === 'click');
  assert.equal(clicks.length, 1);
  assert.equal(clicks[0].body.visitor_id, 'fp-aaaaaaaaaaaa');
  assert.equal(clicks[0].body.target, 'Home navigation');
});

test('gallery controls use accessible labels without copying arbitrary text', () => {
  const h = activityHarness();
  const gallery = element('div', { class: 'fancybox__container' }, h.body);
  const button = element('button', { 'aria-label': 'Next photo' }, gallery);
  const icon = element('svg', {}, button);
  const event = h.click([icon, button, gallery, h.body], { detail: 0 });
  assert.equal(event.target, 'Next photo');
  assert.equal(event.source, 'site-widget');
  assert.equal(event.action_id, '');
  assert.equal(event.label_quality, 'inferred');
  assert.equal(event.interaction, 'non-pointer');
  assert.equal(event.x, null);
  const main = element('main', { 'data-analytics-root': '' }, h.body);
  const sensitive = element('button', { text: 'secret@example.com 123456789' }, main);
  assert.equal(h.click([sensitive, main, h.body]).target, 'Unlabelled control');
});

function d1(sqlite) {
  return {
    prepare(sql) {
      return {
        bind(...args) {
          const stmt = sqlite.prepare(sql);
          return {
            async first() { return stmt.get(...args) || null; },
            async run() { const result = stmt.run(...args); return { meta: { changes: result.changes } }; },
          };
        },
        async first() { return sqlite.prepare(sql).get() || null; },
      };
    },
  };
}

test('Worker validates new click fields and keeps legacy events readable', async () => {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE rate_limits (ip TEXT, scope TEXT, bucket INTEGER, count INTEGER, PRIMARY KEY(ip,scope,bucket));
    CREATE TABLE page_engagement (id INTEGER PRIMARY KEY, visitor_id TEXT, session_id TEXT, event_type TEXT, page_url TEXT,
      x INTEGER, y INTEGER, target TEXT, extra TEXT, section TEXT, cls TEXT, href TEXT);`);
  sqlite.exec(readFileSync(new URL('../migrations/0003_click_semantics.sql', import.meta.url), 'utf8'));
  const edgeKeys = [];
  const env = {
    DB: d1(sqlite), LOG_KEY: 'test-key', ALLOWED_ORIGINS: 'https://example.test',
    EVENT_INGEST_LIMITER: { async limit({ key }) { edgeKeys.push(key); return { success: true }; } },
  };
  async function send(payload, requestEnv = env) {
    return worker.fetch(new Request('https://worker.test/event', { method: 'POST',
      headers: { Origin: 'https://example.test', 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 Safari/605.1.15', 'CF-Connecting-IP': '203.0.113.8' },
      body: JSON.stringify({ key: 'test-key', visitor_id: 'fp-aaaaaaaaaaaa', session_id: 'sid', event_type: 'click', ...payload }),
    }), requestEnv, {});
  }
  const named = await send({ pageUrl: 'https://example.test/page?secret=1', target: 'Contact navigation', section: 'Navigation',
    action_id: 'nav.contact', label_quality: 'named', source: 'site', interaction: 'pointer', x: 1203, y: 78,
    viewport_w: 1440, viewport_h: 900, href: 'https://example.test/page?secret=2#contact-title' });
  assert.equal(named.status, 200);
  const saved = sqlite.prepare('SELECT * FROM page_engagement WHERE id = 1').get();
  assert.equal(saved.action_id, 'nav.contact');
  assert.equal(saved.target, 'Contact navigation');
  assert.equal(saved.page_url, 'https://example.test/page');
  assert.equal(saved.href, 'https://example.test/page#contact-title');
  assert.equal(saved.viewport_w, 1440);
  const outside = await send({ target: 'Private overlay text', section: 'Private', href: 'javascript:alert(1)',
    source: 'outside', label_quality: 'named', action_id: 'fake.control', interaction: 'non-pointer', x: 5, y: 6 });
  assert.equal(outside.status, 200);
  const unknown = sqlite.prepare('SELECT * FROM page_engagement WHERE id = 2').get();
  assert.equal(unknown.target, 'Unidentified element outside site content');
  assert.equal(unknown.section, 'Outside site content');
  assert.equal(unknown.action_id, null);
  assert.equal(unknown.label_quality, 'unknown');
  assert.equal(unknown.href, null);
  assert.equal(unknown.x, null);
  const legacy = await send({ target: 'div#tav-host', section: 'page' });
  assert.equal(legacy.status, 200);
  assert.equal(sqlite.prepare('SELECT label_quality FROM page_engagement WHERE id = 3').get().label_quality, null);

  assert.equal(edgeKeys.length, 3);
  assert.ok(edgeKeys.every(key => key === '203.0.113.8'));
  const rateRowsBefore = sqlite.prepare('SELECT COUNT(*) AS n FROM rate_limits').get().n;
  const eventsBefore = sqlite.prepare('SELECT COUNT(*) AS n FROM page_engagement').get().n;
  const edgeRejected = await send({ event_type: 'heartbeat' }, {
    ...env, EVENT_INGEST_LIMITER: { async limit() { return { success: false }; } },
  });
  assert.equal(edgeRejected.status, 429);
  const missingLimiter = await send({ event_type: 'heartbeat' }, {
    DB: env.DB, LOG_KEY: env.LOG_KEY, ALLOWED_ORIGINS: env.ALLOWED_ORIGINS,
  });
  assert.equal(missingLimiter.status, 503);
  assert.equal(sqlite.prepare('SELECT COUNT(*) AS n FROM rate_limits').get().n, rateRowsBefore);
  assert.equal(sqlite.prepare('SELECT COUNT(*) AS n FROM page_engagement').get().n, eventsBefore);
  sqlite.close();
});
