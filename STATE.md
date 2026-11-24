# State

**Current focus:** Issue #77 implemented (`web.headers`, `web.cors`, 9 rules); preparing PR for epic `#66`.

## What's done recently

- Epic `#66` (`Website module: HTTP attack surface of verified hosts`) progress:
  - `#69` (`ADR 0033`, PR `#193`), `#70` (active queue & rate limits, PR `#194`), `#71` (guarded TLS adapter, PR `#195`), `#74` (vulnintel sync & `match_product`, PR `#196`), `#72` (`web.probe` & `web_active`, PR `#197`), `#73` (`scanners/web/fingerprint.py` & `web.disclosure.version_banner`, PR `#198`), `#75` (`web.components` CVE/KEV/EPSS matching, PR `#199`), and `#76` (`web.tls` 7 TLS checks & rules, PR `#200`) merged to `main`.
  - `#77` (`scanners/web/headers.py` + `domain/rules/web.py` + `SafeHttpClient.get(..., headers=...)`): added `web.headers` (passive check over `web.probe` metadata for `hsts_missing`, `hsts_weak`, `csp_missing`, `csp_unsafe`, `clickjacking`, `nosniff_missing`, `web.cookies.insecure_flags`, and `web.https.no_redirect` + `Asset.details["security_headers"]`) and `web.cors` (verified active `GET` with `Origin: https://cors-probe.invalid` checking `web.cors.wildcard_credentials`), registered in `web_active.checks`, `app.py`, and `workers/app.py`.

## Next step

- Merge PR for `#77` after CI & `@codex review` pass, then plan and implement `#78` (exposed sensitive paths & admin panels), followed by `#79`–`#82`.
