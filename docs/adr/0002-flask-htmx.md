# 0002. Flask + server-rendered Jinja + HTMX

- Status: accepted
- Date: 2026-10-07

## Context
UI is mostly tables, forms, detail pages and job-progress views. A SPA would add a JS build
pipeline and a second codebase.

## Decision
Flask with an app factory and blueprints; Jinja templates; HTMX for partial updates and polling;
Alpine.js for small client-side state. A JSON API (`/api/v1`) shares the same services. HTMX and
Alpine are vendored (pinned) into `static/`.

## Consequences
- One language for agents to work in; fast iteration.
- Highly interactive views (graph visualizations) may need a focused JS component later.
- Flask is sync; slow work goes to Celery anyway (ADR 0003).
