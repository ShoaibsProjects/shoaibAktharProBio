# Maintenance Notes

## 2026-10-02 — v3.37.0 "dashboard delete controls"

- Added `POST /api/delete` (session + strict same-origin guarded, atomic via D1 batch, 20/min per IP) with scopes: `visitor` (a profile's visits + clicks + identity rows, resolving link/override groups), `visit` (a visit + the engagement inside its time window), `engagement` (specific click/heartbeat rows), and bulk `all_visits` / `all_engagement` / `all`.
- Dashboard now has per-row delete for Recent Visits and Click Details, a Delete button on each Visitor Profile, select-all + bulk delete bars, and a Danger Zone card.
- All deletions are logged with per-table row counts; system tables (sessions, rate_limits) are never touched. Deleting visits also clears visit-derived identity corrections.
- Verified: `node --check`, 14 Node tests (6 new in `worker/delete.test.mjs`), and Wrangler dry-run passed. Deployed as version `16127529`; live `/api/delete` returns 401 unauthenticated and 403 cross-origin, and `/health` still reports `eventLimiter:true`.
- Caution: the public-repo clone at `Github Aug 2/shoaibAktharProBio` is stale (v3.26.0) and its `wrangler.jsonc` lacks the `EVENT_INGEST_LIMITER` binding. Always deploy from THIS folder.

## 2026-09-27 — maintenance

- Restored the public profile's original layout, fonts, gallery, and full-resolution JPEG photos.
- Dashboard locations now open Apple Maps by place name; IP-based areas remain estimates, not precise device locations.
- Kept the Cloudflare Worker and D1 features; no production records were used for tests.
- Removed obsolete deployment examples and an internal architecture diagram from the public repo.
- Verified Worker syntax, 8 local Node tests, page scripts, and Wrangler dry-run before publishing.
