# Maintenance Notes

## 2026-09-27 — maintenance

- Refined responsive navigation and keyboard access; age and copyright year now update automatically.
- Replaced the remote photo gallery with a native dialog, converted profile photos to optimized WebP, and removed external font/gallery assets.
- Dashboard locations now open Apple Maps by place name; IP-based areas remain estimates, not precise device locations.
- Kept the Cloudflare Worker and D1 features. The page explains the activity data it records; no production records were used for tests.
- Removed obsolete deployment examples and an internal architecture diagram from the public repo.
- Verified Worker syntax, 8 local Node tests, page scripts, optimized asset references, and Wrangler dry-run before publishing.
