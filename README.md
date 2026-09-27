# Shoaib Akthar — Profile

A responsive personal profile built with HTML, CSS, and JavaScript.

**Live site:** [shoaibsprojects.github.io/shoaibAktharProBio](https://shoaibsprojects.github.io/shoaibAktharProBio/)

## Design and features

- Adapts to light and dark appearance and small screens.
- Shows the original full-resolution JPEG photos in a Fancybox gallery.
- Uses Google Fonts and Fancybox assets from their hosted services.
- Opens approximate location searches in Apple Maps from the private dashboard. These are broad IP-based estimates, not device GPS locations.

## Site activity and privacy

The profile sends page views and selected link/button interactions to a restricted Cloudflare dashboard. The service uses a first-party browser ID and records browser/device details and coarse network-derived location. It does not request precise GPS location or run advertising scripts. Page-view and interaction records currently have no automatic expiry configured; session and request-limit records are periodically cleaned. Review retention before using this service for a larger audience.

## Hosting and cost limits

GitHub Pages serves `index.html` from the repository root. The optional Cloudflare service is configured in [`wrangler.jsonc`](wrangler.jsonc) and uses an existing Worker, D1 database, built-in rate-limit binding, and included Workers Logs—no paid add-on is configured here.

Cloudflare's Free plan currently enforces its own limits (including 100,000 Worker requests/day, D1 daily read/write caps and 5 GB storage, and 200,000 log events/day). Excess usage on Free is rejected rather than billed as overage. The repository cannot select or lock the Cloudflare account's subscription; verify the account is on the Free plan before deployment. A paid account plan could bill under its own terms.

## Local checks

```sh
node --check worker/index.js
node --test worker/click.test.mjs worker/identity.test.mjs
```

Tests use in-memory data and do not write to the live Worker or database.
