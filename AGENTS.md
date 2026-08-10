# Maintenance Log

## 2026-08-09 — v3.25.0 "click details: always-visible engagement + enriched tracking (section/class/link)" (commit c3dd73c)
- Click tracking now records page section, element class, and link href (new `page_engagement` columns `section`/`cls`/`href`; `schema.sql` updated).
- Dashboard engagement stat cards (Sessions Tracked, Avg Time, Most-Clicked, Recent clicks + Reset button) are always visible, rendering zeros/`—` when empty.
- New "Click Details" table on dashboard: last 60 clicks (Time/CST · Visitor · Location · Section · Target · Link · Pos (x,y)).
- Deploy path: push to GitHub → GitHub Actions/Workers Builds → `wrangler.jsonc` (`"main": "worker/index.js"`).
- Worker `pageview-logger` (account shoaibtest2), D1 `pageviews-db` (id `38c13894-511b-4786-af36-2c2a2cd166d2`).
- Keep each maintenance record as a dated note here so it persists in the repo.
