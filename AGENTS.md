# Deployment Protocol — READ THIS FIRST

**Never use `npx wrangler deploy` directly. Never edit worker code live in the Cloudflare dashboard.**

GitHub Build is the single source of truth. One push = one correct deploy.

## Repo layout
```
shoaibAktharProBio/
├── wrangler.jsonc          ← deploy config (root) — the build reads this
├── worker/
│   ├── index.js            ← the worker code (deployed via build)
│   └── wrangler.toml       ← local dev only (ignored by CI)
└── index.html              ← profile page (GitHub Pages)
```

## The deploy flow (do exactly this)
```
git add .
git commit -m "Update site"
git push
```
→ GitHub Build runs `npx wrangler deploy` from root
→ finds `wrangler.jsonc` → `"main": "worker/index.js"`
→ deploys worker with D1 + vars + cron
→ secrets survive (they are per-worker, not per-deploy)

## Verify after every push (~30 seconds)
```
curl -s https://pageview-logger.shoaibtest2.workers.dev/health
```
OK = `{"status":"ok",...}` with `dashKey:true`, `turnstile:true`.

## Never do this
| Don't | Why |
|---|---|
| `cd worker && npx wrangler deploy` | Creates a second deploy path that fights the build |
| Change secrets in dashboard after a deploy | They survive; only change if you want new values |
| Edit worker code live in Cloudflare | Git is the source |

## D1 schema changes
Schema migrations are **DB-side, not deploys** — run `ALTER TABLE ...` against
D1 directly (e.g. via the Cloudflare D1 API/MCP). Then verify with `/health`.
Example fixed 2026-08-05: `ALTER TABLE page_views ADD COLUMN language TEXT`.

## Important values
- Worker: `pageview-logger` — https://pageview-logger.shoaibtest2.workers.dev
- D1 DB: `pageviews-db` (id `38c13894-511b-4786-af36-2c2a2cd166d2`)
- Secrets (write-only, live): `DASHBOARD_KEY`, `TURNSTILE_SECRET`, `LOG_KEY`
- Turnstile site key: `0x4AAAAAAEEnNXNege0uqc_0`
- Allowed origins: `https://shoaibsprojects.github.io`, `https://shoaibakthar.pro`, `http://localhost`
- Bump `VERSION` in `worker/index.js` when changing worker code.

## Profile page
- Served from GitHub Pages (auto-deploys on push to `main`).
- Keep original photos in repo; do not delete or compress them.
- `index.html` is the profile page — no public tracker trace on it.
