# DESIGN.md: attacksurf web UI design system

> **Status: foundation built (#6), visual values are placeholders.** Structure, constraints and
> token *names* are final. Token *values* live in `src/attacksurf/web/static/css/tokens.css` as
> neutral, contrast-checked placeholders marked `TODO(DESIGN.md)`; the Claude Design pass replaces
> them there (and in the tables below) without touching templates. Agents: follow what's defined,
> don't invent new values; use existing tokens.

## 1. Principles

1. **Clarity over decoration**: security data first; every pixel helps triage.
2. **Severity is the main visual signal**: consistent everywhere (badges, charts, rows).
3. **Calm by default**: no alarm fatigue; red is reserved for high/critical.
4. **Fast and server-rendered**: HTMX partials, minimal JS, no layout shift on updates.
5. **Accessible**: WCAG 2.2 AA, keyboard-first, never color alone to convey meaning.
6. **Light and dark themes** from day one.

## 2. Tech constraints

- Jinja templates + HTMX + Alpine.js (ADR 0002). No SPA framework, no Node build step required
  at runtime.
- CSS approach (decided in #6): **plain CSS + design tokens**, no framework, no build step.
  `static/css/tokens.css` holds every value; `static/css/app.css` uses only `var(--…)`.
- Vendored assets only (no CDNs at runtime): HTMX and the **Alpine CSP build** in
  `static/vendor/` with `SHA256SUMS` (see its README). Strict CSP: no inline `<script>`, `style=`,
  `on*=` or `eval`. Alpine components are registered in `static/js/app.js` (`Alpine.data`), not
  written as inline expressions.
- Icons: Lucide (ISC) as an SVG sprite, `static/icons.svg`; use the `icon(name)` macro
  (`components/icon.html`), always next to visible text or an `aria-label`.
- Theme: `static/js/theme.js` sets `data-theme` before first paint (saved choice, else OS).

## 3. Design tokens

Defined once as CSS custom properties on `:root`, overridden under `[data-theme="dark"]`.

### Color
| Token | Purpose | Light | Dark |
|---|---|---|---|
| `--color-bg` | page background | TBD | TBD |
| `--color-surface` | cards, tables | TBD | TBD |
| `--color-border` | dividers | TBD | TBD |
| `--color-text` | primary text | TBD | TBD |
| `--color-text-muted` | secondary text | TBD | TBD |
| `--color-primary` | actions, links, focus | TBD | TBD |
| `--color-success` / `--color-warning` / `--color-danger` | status | TBD | TBD |
| `--color-backdrop` | behind modal dialogs | TBD | TBD |

### Severity scale (core)
| Token | Severity | Color | Icon/shape (non-color cue) |
|---|---|---|---|
| `--sev-critical-fg/-bg` | critical | TBD (placeholder: red) | `octagon-alert` |
| `--sev-high-fg/-bg` | high | TBD (placeholder: orange) | `triangle-alert` |
| `--sev-medium-fg/-bg` | medium | TBD (placeholder: amber) | `circle-alert` |
| `--sev-low-fg/-bg` | low | TBD (placeholder: blue) | `circle-arrow-down` |
| `--sev-info-fg/-bg` | info | TBD (placeholder: slate) | `info` |

All severity colors must reach 4.5:1 contrast for text on their badge background in both themes.

### Typography
| Token | Value |
|---|---|
| `--font-sans` | TBD (system stack acceptable) |
| `--font-mono` | TBD (for DNS records, hostnames, evidence) |
| Type scale | TBD (e.g. 12 / 14 / 16 / 20 / 24 / 32) |

### Spacing, radius, elevation
| Token | Value |
|---|---|
| `--space-1 … --space-8` | TBD (4px base suggested) |
| `--radius-sm/md/lg` | TBD |
| `--shadow-sm/md` | TBD |
| Borders, focus ring, opacity | `--border-width`, `--border-width-accent`, `--focus-ring-width/-offset`, `--opacity-disabled` (placeholders) |
| Layout widths | `--nav-width`, `--auth-card-width`, `--user-menu-min-width`, `--field-min-width`, `--filter-min-width`, `--meta-column-min-width` (placeholders) |
| Line heights, weights, icons | `--line-height-body/-heading/-badge`, `--font-weight-semibold/-bold`, `--icon-size`, `--icon-size-lg`, `--measure` (placeholders) |

`app.css` uses only these variables (a test rejects raw colors); the only raw dimension is the
48rem mobile breakpoint, because CSS can't read custom properties inside `@media`.

## 4. Layout

- App shell: top bar (logo, org, user menu, theme toggle) + left nav (Dashboard, Assets, Scans,
  Findings, Settings) + content area. Collapses to a top menu on mobile. On phones (≤ 48rem) the
  top bar is two rows — brand + theme toggle, then user menu + Log out — with the email truncated
  (`title` keeps the full text), and the nav row scrolls horizontally inside itself.
- Footer: "Source code" link (required by AGPL §13).
- Content width: `.content` fills the main column at every width (no max-width cap). Prose that
  needs a shorter line caps itself with `--measure` (empty-state copy, dialogs), and wide tables
  scroll inside `.table-wrap` (`.content` keeps `min-width: 0`).
- Templates: `layouts/base.html` (shell), `layouts/fragment.html` (HTMX partial), pages in
  `pages/`, errors in `errors/error.html`.

## 5. Components

Implemented as Jinja macros in `templates/components/`. Each entry: purpose, variants, states.
Built in #6: `button`, `severity_badge` + `status_pill` (`badges.html`), `data_table` +
`pagination` (`table.html`), `empty_state`, `flash_messages`, `icon`; #7 added `form_field`,
`form_error`, `csrf_field` (`form.html`) and `layouts/auth.html` (signed-out pages). #13 added
`select_field` and `form_field(autofocus=)` (`form.html`), `confirm_dialog` (`confirm.html`),
`relative_time` (`time.html`) and call-block cells for `data_table`. #14 added
`ownership_badge` + `ownership_card` (`verification.html`) and `Alpine.data("copyField")`.
#87 added `file_field` (`form.html`); #101 reuses it for the binary upload form. #24 added
`/settings` AI provider configuration (`_ai_settings_form.html`, `Alpine.data("aiSettingsForm")`
replace-key `<dialog>`), `confirm_dialog` for removing a saved key, polled connection test status
(`_ai_test_status.html`, `.ai-test-status`), a monthly token/cost `data_table`, and `.notice-list`.
Specs (visuals) stay TBD.

| Component | Notes | Spec |
|---|---|---|
| Button | primary / secondary / danger / ghost; loading state for HTMX (`htmx-request`) | TBD |
| Severity badge | text + color + icon, never color alone | TBD |
| Status pill | finding: open / fixed / accepted_risk / false_positive / regressed; scan: queued / running / completed / failed / cancelled | TBD |
| Data table | sortable headers, filters bar, pagination, row selection for bulk actions, empty state. Rich cells (links, badges, `<code>`): `{% call(row, key) data_table(...) %}`, still autoescaped. Wide tables scroll inside `.table-wrap` (`.content` has `min-width: 0`) | TBD |
| Card / stat tile | dashboard counts by severity | TBD |
| Form field | label, hint, inline error (HTMX validation) | TBD |
| File field | `file_field(name, label, accept=, error=, hint=)`: a native file input with the form field's label, hint and inline error; never a `value`. The hint states accepted formats and the size limit | TBD |
| Flash / toast | success / error / info | TBD |
| Progress | scan stage progress (`pages/_scan_progress.html`, polled via HTMX): a "N of M jobs finished" line with `role="status"`, a native `<progress>` element, a per-job table (stage, scanner, asset, status pill, sanitized error, finished time), the new/fixed/regressed/observed finding counts by severity with new/disappeared asset links (each bucket capped at 100 rows with a "Showing N of M" notice). The section polls itself (`hx-get` to `ui.scan_progress`, `hx-trigger="every 2s"`, `hx-target="this"`, `hx-swap="outerHTML"`, `hx-sync="this:replace"`, `aria-busy`); once the scan is terminal the attributes are gone, so polling stops and the final swap reveals the diff. The same response carries out-of-band swaps (`hx-swap-oob`) for the status pill, the meta block and the cancel action outside the section; the cancel action (behind `confirm_dialog`, secondary variant) lives outside the polled subtree, so a poll never closes the dialog mid-read. The scan detail page includes the same fragment for first paint | Implemented in #21 (visual spec TBD) |
| Code / evidence block | monospace, escaped, copy button, size-capped with "show more" | TBD |
| Findings list | filter bar (severity, status, root, rule, asset substring, sort, "new since last scan") swapping only the results region; columns select / severity / finding (title + rule + location) / asset / root / status / first seen / last seen; export CSV/JSON links live in the swapped region so they always match the filters. The results region warns next to the export actions when the current filtered total exceeds the download cap. #22 | Implemented in #22 (visual spec TBD) |
| Finding detail | breadcrumb, severity + status, meta (`dl.meta`: asset, root, rule, location, confidence, scanner, dates, scan count), description, evidence cards (one per record: structured fields + `<pre class="evidence-body">`, visibly truncated when capped), remediation, references, AI panel, timeline, status form. Every scan-derived value stays autoescaped. #22 | Implemented in #22 (visual spec TBD) |
| Bulk action bar | checkbox selection inside a form wrapping the table, a "Select all" checkbox and live count (progressive enhancement in `static/js/app.js`, event delegation on `.bulk-form`; the strict CSP build does not run Alpine handlers on the swapped table), status select, comment input and submit. The server owns the 50-item cap and all-or-nothing semantics; a filter swap clears the selection. #22 | Implemented in #22 (visual spec TBD) |
| AI panel | AI triage output (`components/ai_panel.html`, ADR 0029). `ai_triage_panel(triage, scanner_severity)` on the finding page: an `.ai-label` line (AI-generated, model, prompt version, when, "a person decides"), then `dl.meta` with a `priority_pill` (P1 `bad`, P2 `active`, P3/P4 neutral, always with words), the AI's severity badge beside the scanner's, false-positive likelihood and AI confidence, then rationale, exploitation and suggested fix steps. An untriaged finding keeps the muted "hasn't run" line. A judgment made before its finding last changed (`stale`) stays visible with an `.ai-stale` note and an "Outdated" `stale_marker()` (warning color, words not color alone), on the finding page and beside its priority on the scan page. On the scan page `pages/_scan_triage.html` is a card of its own (`#scan-triage`): it polls itself every 2 s from first paint while the scan is active, for a minute after it completes (until its triage job appears), and while the run is queued or running ("N of M assets done…", `role="status"`), shows skip and failure notices, then a `data_table` of the scan's judged findings, most urgent first, capped at 100 with a "Showing N of M" line. All AI text stays autoescaped. Never call an LLM in a request | Implemented in #25 |
| Empty state | illustration/icon + one-line explanation + primary action | TBD |
| Modal / confirm | destructive actions (archive asset, accept risk): `confirm_dialog(id, trigger_label, title, message, action, confirm_label, trigger_variant="danger", confirm_variant="danger")`, a native `<dialog>` opened by `Alpine.data("confirmDialog")`; focus starts on Cancel, Escape closes, confirm POSTs with CSRF. Keep the danger variant for anything that removes data; reversible or recoverable actions (rotate a token) use `secondary` | TBD |
| DNS chain / records | monospace `asset → CNAME → IP` chain with `overflow-wrap:anywhere`, then a data table of record type → values; non-public addresses called out in muted text. All values are scan data and stay autoescaped | TBD |
| Ownership card | proof of domain control: status badge, the exact TXT record in a `.copy-field` with a copy button (`Alpine.data("copyField")`, the code block stays selectable without the Clipboard API), and admin-only actions (start / verify now / rotate behind a confirm). Subdomains show their root's record read-only. A check queued past the grace with no consumer renders `Stalled` with a queue (not record) explanation and stops polling (#174) | TBD |
| Scheduled rescans card | overview card on an active root: status line (`Weekly. Next run: <exact UTC time>` or `Scheduling is off.`), and for admins a plain POST form with a labeled `enabled` checkbox, a `Daily`/`Weekly` `select_field`, and a `Save schedule` secondary button. Members see the status only; no JS, no polling. Absolute times use `<time datetime>` plus the `exact_time` filter because a future due date reads as "just now" in the relative macro (#27) | TBD |

## 6. Interaction patterns (HTMX)

- Partial responses: routes call `web.rendering.render_page()`; pages start with
  `{% extends "layouts/fragment.html" if is_htmx else "layouts/base.html" %}`. HTMX requests get
  the fragment; boosted requests, history restores (`HX-History-Restore-Request`: Back after
  `hx-push-url` when HTMX's history cache misses, which HTMX sends with `HX-Request` and swaps
  into the whole `<body>`) and normal loads get the full page (`Vary` on all three headers).
- Long-running work: show job progress via polling (`hx-trigger="every 2s"`), stop when done.
  Ownership cards poll the viewed asset, including subdomains inheriting a root's proof, so
  refreshing a read-only card preserves its available actions. A verify job still queued past
  the grace stops polling and names the queue, not the record (#174).
- Forms: inline validation errors; disable the submit button during request.
- Destructive actions: confirm modal; never one-click delete.
- Lists: filters update the URL query string (`hx-push-url`) so views are shareable. The
  filter form targets only the results region (`hx-target` + `hx-select="#…-results"`), so
  inputs keep focus while typing; search fires on `input changed delay:300ms`. Without JS it
  is a plain GET form. Put `hx-sync="this:replace"` on the form: the search box sends its own
  requests and inherits it (`this` resolves to the form), so an older response can't overwrite
  newer results. Same on tab bars. The findings list's export links and bulk form live inside
  the swapped region for the same reason: they must carry the filters currently on screen.
- Bulk actions (findings): a form wraps the results table; checkboxes are `name="finding_ids"`
  with `data-bulk-item`, the bar posts one status plus an optional comment to a URL carrying the
  current filters. "Select all" and the live count are plain event delegation in
  `static/js/app.js` (not Alpine: the CSP build does not reliably run handlers on the swapped
  table), and they are only a convenience; the server enforces the cap, the required
  suppression comment and all-or-nothing application.
- Tabs on detail pages are links (`?tab=…`, `aria-current="page"`); the tab bar lives inside the
  swapped region so its state updates with the content.
- Inline-validated forms swap themselves (`hx-target="this"`, 422 with the field error) and set
  `autofocus` on the invalid field; success responds with `HX-Redirect` (and a flash).
- Upload forms are inline-validated forms with `enctype="multipart/form-data"` **and**
  `hx-encoding="multipart/form-data"` (HTMX otherwise sends no file), `csrf_field()` and
  `hx-disabled-elt="find button"`. A rejected upload re-renders the form with the error (413 /
  415 / 422 / 429 / 503), including a 413 or 429 raised before the view runs
  (`web.uploads.upload_form`); when storage isn't configured the form is replaced by one muted
  line saying so. Each upload form is its own card and partial on the Assets page (codebase,
  then binary), with its own file field name so ids and errors don't collide: an HTMX swap
  passes `upload_error`, a full-page render scopes `<field>_error` to its form. Leave `accept`
  off when the format has no dependable extension (executables); the hint lists the formats.
- An uploaded file's name is shown as "Uploaded file" in the asset's meta list, in monospace,
  escaped and wrapping (`overflow-wrap: anywhere`); a binary's title is its `sha256:` value.
- Dates: `relative_time(dt)` renders "3 days ago" with the exact UTC time on hover (§7).

## 7. Content and tone

- Plain language; explain *why it matters* and *how to fix*, not just jargon.
- AI-generated text always labeled as such.
- Dates: relative ("3 days ago") with exact timestamp on hover.
- Hostnames, records, and evidence in monospace, never truncated without a way to see all.

## 8. Accessibility checklist

- [ ] Contrast AA in both themes
- [ ] Visible focus ring (`--color-primary`)
- [ ] All interactive elements reachable by keyboard
- [ ] HTMX updates announced (`aria-live` on status regions)
- [ ] Tables have proper headers; icons have labels

## 9. Open items (to complete with Claude Design)

- [ ] Brand: logo, name lockup, favicon, social preview image
- [ ] Color palette + severity scale (light/dark), contrast-verified
- [ ] Typography and spacing scales
- [ ] Component specs for the table above
- [x] Key screens: dashboard, asset list/detail, scan progress, findings list/detail, settings
  (scan progress, like the rest, has structure only; visual values are still placeholders)
- [x] Decide CSS approach (#6): plain CSS + tokens
