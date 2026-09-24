# Maintenance Log

## 2026-09-24 — v3.27.1 "smoothness hotfix: seed _dashSig from dashSeed so first /stats tick is a no-op"
- On the v3.27.0 seed path, `_dashSig` stayed `''` and the seed lacked referrer/country sig parts, so the first `/stats` tick (≤60s after load) still rebuilt the recent table, trend, referrer list, and country chips once with identical data.
- Fix: `dashboardHtml` now emits `refSig`/`ccSig` into `window.__DASH`; the client computes the initial `_dashSig` from the seed at boot. Verified locally: identical data → 0 rebuilds across 5 ticks; real data change → exactly 1 rebuild.
- Commit `95b0efe`, deployed live as `775b188f`.

## 2026-09-24 — v3.27.0 "dashboard + login smoothness (kill SVG turbulence filters, freeze aurora, single-source render)"
- Root cause of dashboard lag: every glass pane (`stat-card`, `.box`, `.table-wrap`, `.pill`, `.badge`, `.profile-card`, etc.) used `url(#lg-refract-...)`/`lg-login` SVG turbulence as `backdrop-filter`, forcing per-frame GPU re-rasterization on scroll + the aurora `animation:*` gradients repainting continuously.
- Fixes: (A) dropped all `url(#...)` turbulence filters (kept `blur()+saturate(180%)`, tamed radii 28/16/12px, removed `.badge` backdrop-filter) and deleted the 4 dead SVG `<filter>` defs; (B) frozen aurora layers (`animation:none` — static blurred gradient, look preserved); (C) server embeds `window.__DASH` (`dashSeed`, slim fields incl. lat/lng) and client skips the on-load `/stats` re-fetch — click table client-renders, recent table stays server-rendered; (D) client `refresh()` guarded by `_dashSig` signature — tables/trend/refList/countryList only rebuild when recent/click/referrer/country data changed; stat numbers always update; (E) `.card,.profile-card{content-visibility:auto;contain-intrinsic-size:auto 320px}`; (F) login `.box` → `blur(28px) saturate(180%)`, login aurora frozen.
- VERSION bumped 3.26.0 → 3.27.0. Commit `e298236` → pushed as `07f2066` after `gh auth switch --user ShoaibsProjects` (repo owned by that account; 403 fixed) + `git pull --rebase origin main` over `281f397`.
- Verified: `node --check` clean (worker + extracted client JS); local harness renders real `dashboardHtml` (seed parses, tables render, no `url(#`); `</script>`/U+2028 escape-safe); live bundle = 3.27.0 with `refSig` absent → then 3.27.1.

## 2026-08-10 — v3.26.0 "fix: clicks/heartbeats recorded despite third-party cookie blocking (localStorage visitor id)"
- Bug: modern browsers (Chrome/Safari) block the worker's cross-site `vid2` cookie on the GitHub Pages profile, so `/event` returned `403 no_session` and clicks/heartbeats silently vanished (page views still recorded via server fingerprint). Confirmed live: `fp-ad705c587dc3` (owner, Desktop) had page views but zero engagement rows.
- Fix: `/log-visit` now echoes the assigned `visitor_id` in its response; the tracker persists it in `localStorage` on the profile origin and sends `visitor_id` in every `/log-visit` + `/event` payload. Worker prefers the cookie, then the payload id (both regex-validated `fp-[0-9a-f]{12}` / UUID). `vid2` cookie also gets `Partitioned` (CHIPS) so it survives inside the profile page.
- Verified: manual cookie-less POST to `/event` with payload `visitor_id` inserts into `page_engagement`.

## 2026-08-09 — v3.25.0 "click details: always-visible engagement + enriched tracking (section/class/link)" (commit c3dd73c)
- Click tracking now records page section, element class, and link href (new `page_engagement` columns `section`/`cls`/`href`; `schema.sql` updated).
- Dashboard engagement stat cards (Sessions Tracked, Avg Time, Most-Clicked, Recent clicks + Reset button) are always visible, rendering zeros/`—` when empty.
- New "Click Details" table on dashboard: last 60 clicks (Time/CST · Visitor · Location · Section · Target · Link · Pos (x,y)).
- Deploy path: push to GitHub → GitHub Actions/Workers Builds → `wrangler.jsonc` (`"main": "worker/index.js"`).
- Worker `pageview-logger` (account shoaibtest2), D1 `pageviews-db` (id `38c13894-511b-4786-af36-2c2a2cd166d2`).
- Keep each maintenance record as a dated note here so it persists in the repo.
