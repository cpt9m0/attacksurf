# DESIGN.md: attacksurf web UI design system

> **Status: draft skeleton.** Structure and constraints are final; visual values marked `TBD` will
> be filled in using Claude Design (or another design tool) before/while building the UI
> foundation (#6). Agents: follow what's defined, don't invent values for `TBD` items. Use
> neutral defaults and leave a `TODO(DESIGN.md)` comment instead.

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
- CSS approach: `TBD` (Tailwind standalone CLI or Pico.css + custom properties, decided in #6).
  Either way, **all values come from the design tokens below as CSS custom properties**.
- Vendored assets only (no CDNs at runtime); CSP without inline scripts.
- Icons: `TBD` (e.g. Lucide / Heroicons as inline SVG sprites).

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

### Severity scale (core)
| Token | Severity | Color | Icon/shape (non-color cue) |
|---|---|---|---|
| `--sev-critical` | critical | TBD | TBD |
| `--sev-high` | high | TBD | TBD |
| `--sev-medium` | medium | TBD | TBD |
| `--sev-low` | low | TBD | TBD |
| `--sev-info` | info | TBD | TBD |

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

## 4. Layout

- App shell: top bar (logo, org, user menu, theme toggle) + left nav (Dashboard, Assets, Scans,
  Findings, Settings) + content area. Collapses to a top menu on mobile.
- Footer: "Source code" link (required by AGPL §13).
- Max content width: TBD. Data tables may go full width.

## 5. Components

Implemented as Jinja macros in `templates/components/`. Each entry: purpose, variants, states.

| Component | Notes | Spec |
|---|---|---|
| Button | primary / secondary / danger / ghost; loading state for HTMX (`htmx-request`) | TBD |
| Severity badge | text + color + icon, never color alone | TBD |
| Status pill | finding: open / fixed / accepted_risk / false_positive / regressed; scan: queued / running / completed / failed / cancelled | TBD |
| Data table | sortable headers, filters bar, pagination, row selection for bulk actions, empty state | TBD |
| Card / stat tile | dashboard counts by severity | TBD |
| Form field | label, hint, inline error (HTMX validation) | TBD |
| Flash / toast | success / error / info | TBD |
| Progress | scan stage progress, polled via HTMX | TBD |
| Code / evidence block | monospace, escaped, copy button, size-capped with "show more" | TBD |
| AI panel | AI triage output, clearly labeled as AI-generated, shows model + prompt version | TBD |
| Empty state | illustration/icon + one-line explanation + primary action | TBD |
| Modal / confirm | destructive actions (delete asset, accept risk) | TBD |

## 6. Interaction patterns (HTMX)

- Partial responses: if `HX-Request` header is present, return the fragment; otherwise the full page.
- Long-running work: show job progress via polling (`hx-trigger="every 2s"`), stop when done.
- Forms: inline validation errors; disable the submit button during request.
- Destructive actions: confirm modal; never one-click delete.
- Lists: filters update the URL query string (`hx-push-url`) so views are shareable.

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
- [ ] Key screens: dashboard, asset list/detail, scan progress, findings list/detail, settings
- [ ] Decide CSS approach (#6)
