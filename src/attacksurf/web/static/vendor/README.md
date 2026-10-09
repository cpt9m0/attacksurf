# Vendored front-end assets

Served from our own origin (no CDNs at runtime, strict CSP). Never edit these files by hand:
replace them with a new upstream release, update `SHA256SUMS` (`sha256sum *.js > SHA256SUMS`)
and the references in `templates/layouts/base.html`. A test checks the hashes.

| File | Upstream | Version | License |
|---|---|---|---|
| `htmx-2.0.11.min.js` | npm `htmx.org` `dist/htmx.min.js` | 2.0.11 | 0BSD |
| `alpinejs-csp-3.17.4.min.js` | npm `@alpinejs/csp` `dist/cdn.min.js` (CSP build: no `eval`) | 3.17.4 | MIT |
| `../icons.svg` | npm `lucide-static` `icons/*.svg`, merged into a `<symbol>` sprite | 1.54.0 | ISC |

Each npm tarball was verified against the registry's `sha512` integrity before extraction.
