# Maintenance Log

## 2026-09-25 — v3.30.0 "diagnose Safari dashboard session cookie"
- Reported/tested: Turnstile showed success; the login key was accepted and a D1 session was created, but Safari returned to the login page without an "Invalid key" message.
- Root cause under investigation: the follow-up GET `/dashboard` did not use a session the Worker accepted. Existing evidence cannot distinguish a cookie Safari omitted from a cookie the Worker rejected.
- Diagnostic change: GET `/dashboard` now logs only `cookiePresent` and `valid` booleans as `dashboard_session_check`; it never logs the session token, access key, or Turnstile token.
- Verification: `node --check worker/index.js` and `git diff --check` passed. Live health reports all bindings true; unauthenticated GET `/dashboard` returns 401.
- Commit: `5ecf485` (`v3.30.0: diagnose Safari dashboard session cookie`). Deployment: `0b22eb26-3e6d-4357-935b-374680c0784f` (2026-09-25 17:11 UTC). Next step: one Safari login attempt while watching the sanitized session-check log.

## 2026-09-25 — v3.29.0 "fix iOS Safari login submit stalled by Turnstile polling"
- Reported: on iOS Safari, entering the dashboard password left Turnstile spinning, then reloaded the login page with the password blank.
- Root cause: loginPage intercepted submit and polled `turnstile.getResponse()` while disabling the submit button. If the Turnstile API/widget stalled or threw inside the interval callback on Safari, the native form POST could be prevented indefinitely. The Worker already accepts a missing token and applies the password check plus the existing 5-attempt/10-minute rate limit.
- Fix: removed the client-side submit interception and polling. The browser now submits the form immediately; Turnstile's generated response is included when available, and server verification remains authoritative for present tokens.
- Verification: `node --check worker/index.js` and `git diff --check` passed. Live health reports all bindings true; GET `/dashboard` returns 401; login page contains the native POST form and no submit interceptor; missing-token POST reaches `Invalid key`, while a present garbage token returns `Verification failed`.
- Commit: `09b0018` (`v3.29.0: fix Safari login submit with native form post`). Deployment: `790b0c9d-8fd1-449e-b914-9d1c410f853a` (2026-09-25 17:00 UTC). Successful-key login still requires the user to confirm in Safari.

## 2026-09-25 — v3.28.0 "fix iOS Safari login for real: set session cookie on 200, not 303 redirect (ITP drops Set-Cookie on 3xx)"
- Reported: still failing on Safari iOS while Brave/Chrome worked; Turnstile best-effort (v3.27.2) changed nothing. Rate-limit table showed a Safari IPv6 hammering `dashboard-login` (5/5 attempts in one 10-min bucket) → confirms form WAS submitting and the worker was responding, but Safari never got logged in.
- Root cause (NOT Turnstile): WebKit's ITP deliberately ignores/strips `Set-Cookie` when it rides on a `303`/`302` redirect response (known issue — Safari works-by-design here; Chromium stores it). The login success path was `303 See Other` + `Set-Cookie: __Host-session=...` on the same response → Safari discards the cookie → redirected GET `/dashboard` has no session → server re-serves the login page → "password goes blank / nothing happens." Brave stored the cookie, hence worked.
- Fix: login success now returns **`200`** with the session cookie on a normal (non-redirect) response, and a tiny HTML page that navigates client-side to `/dashboard` (`meta refresh` + `window.location.replace`, both CSP-safe with `script-src 'unsafe-inline'`). Cookie lands in Safari's jar from the 200, so the follow-up GET is authenticated. VERSION → 3.28.0. Commit `af7af88`.
- References: Stack Overflow "On Safari, cookies are not saved when sent with redirect" (WebKit known issue); Apple Dev Forums "Safari 16.4 loses session token cookie"; Chromium issue "Cookies are ignored on 302 redirects"; WebKit ITP docs.
- Security note: session cookie unchanged rules (`__Host-` prefix, Secure, HttpOnly, SameSite=Lax, Max-Age 3600); rate limit (5/10min/IP) still the brute-force guard; 200-cookie-then-client-redirect is the standard workaround, not a security regression.

## 2026-09-24 — v3.27.2 "fix iOS Safari login: Turnstile best-effort when widget can't complete"
- Reported: Safari iOS login "Cloudflare runs/spins, nothing happens, password goes blank." Root cause: the login page's client JS is deliberately built to submit the form WITHOUT a Turnstile token when the widget fails to initialize (`if(!t) return` and the ~10s "submit anyway" timeout), but the server hard-rejected any request missing a valid token when `TURNSTILE_SECRET` was set → `401 Verification failed` → login page re-rendered with an empty password field. On iOS Private Relay / mobile IP rotation the widget often never completes.
- Fixes: (1) server Turnstile is now best-effort — a *present but invalid* token still gets rejected, but a **missing** token is allowed through to the key check (brute-force rate limit still guards the endpoint); (2) dropped the optional `remoteip` from siteverify — IP at mint time vs verify time can differ on Private Relay/mobile and Cloudflare then rejects valid tokens; (3) client "submit anyway" timeout cut 10s → ~3s (15 polls × 200ms) so mobile users aren't stuck on a spinner.
- Verified live: POST to `/dashboard` with `key=wrong&turnstile=` now returns `Invalid key` (reaches key check) instead of `Verification failed`. Deployed bundle = 3.27.2 (`tries > 15`, no `remoteip`). Commit `a28de6f`, deployed as `9193627d`.
- Security note: rate limit (5 attempts/10min/IP via `rate_limits` D1 table) remains the primary brute-force guard; Turnstile is defense-in-depth and now degrades gracefully.

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
