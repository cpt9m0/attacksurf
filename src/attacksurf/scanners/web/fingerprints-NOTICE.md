# Web technology fingerprint dataset — attribution and changes

`fingerprints.json` in this directory is derived from the
[enthec/webappanalyzer](https://github.com/enthec/webappanalyzer) signature database, licensed
under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html)
(compatible with `attacksurf`'s `AGPL-3.0-or-later`), vendored at pinned commit
`7dba7bf3e8b4f25c6a5b4b2c9f5e7a0e73e6a1bf` (2026-11-22). This file serves as the attribution
and modification notice required by GPL-3.0 §5.

Changes made to the upstream `src/technologies/*.json` and `src/categories.json` files at the
pinned commit:

- Curated a 66-technology subset covering widely deployed web servers, reverse proxies, CDNs,
  runtimes, web frameworks, CMS/wikis, JavaScript libraries, and DevOps/enterprise applications.
- Resolved integer category IDs via `src/categories.json` into human-readable category names
  and dropped presentation/pricing/DOM-execution fields (`icon`, `website`, `description`,
  `pricing`, `saas`, `oss`, `cpe`, `dom`, `js`, `css`, `url`, `xhr`, `text`, `robots`).
- Kept only passive HTTP-response channels (`headers`, `cookies`, `meta`, `script_src` from
  upstream `scriptSrc`, and `html`), normalized header and `<meta>` names to lowercase, and
  retained only `implies` edges targeting technologies within the curated subset.
- Restricted `cookies` entries strictly to cookie-name presence patterns (`^(?:<name>)$`); any
  upstream cookie rule that inspects a cookie value was dropped so secret cookie values are never
  examined or matched.
- Audited every regular expression at extraction time to reject invalid patterns or nested
  quantifiers (catastrophic backtracking / ReDoS risk on untrusted HTML responses).

To update: re-fetch `src/categories.json` and `src/technologies/*.json` from
`enthec/webappanalyzer` at a new pinned commit, re-apply the curation and transformation rules
above, update the commit SHA here, and adjust the pinned entry count in
`tests/unit/scanners/web/test_fingerprint.py`.
