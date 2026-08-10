# Maintenance Log

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
