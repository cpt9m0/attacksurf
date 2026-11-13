# 0027. Finding lifecycle and scan diffing

- Status: accepted
- Date: 2026-11-13

## Context
Issue #20 turns a series of scans into change over time: new, fixed and regressed findings, an
asset diff, and per-scan stats. ADR 0011 left `diff` as an explicit no-op and defined
`FindingFixed` without emitting it, because a wrong "fixed" is worse than no lifecycle at all.

The pieces it left open:

- A finding row is identified by `(org_id, asset_id, rule_id, location)`. It carries no scanner
  name, and rules are not declared per scanner, so "the scanner that reported this finding" is
  not stored anywhere.
- A finding can be suppressed by the user (`accepted_risk`, `false_positive`). Re-observing it
  must not silently reopen a decision the user made.
- `Scan.stats` is empty and #21 needs a stable shape for the scan-history diff view.
- A scanner can fail, be skipped by ScopeGuard, or not be planned for an asset at all. Absence
  of a finding then proves nothing.

## Decision
- **A `regressed` status.** `FindingStatus` gains `REGRESSED`: a finding that was `fixed` and is
  observed again becomes `regressed` with `fixed_at` cleared. It counts as active in views
  (`ACTIVE_STATUSES = {open, regressed}`) and is fixed again by a later scan that does not see
  it. A separate flag column would duplicate the state the UI already renders as a pill.
- **Scanner provenance on the finding.** A nullable `Finding.scanner` stores the `Job.scanner`
  that last observed it; `run_check` passes it to `persist_scan_output`. A re-observation from a
  newer scan updates it, and an output that names no scanner never erases it. Rows written
  before #20 stay `NULL` and are never auto-fixed.
- **Coverage is per scanner and asset.** The diff fixes an active finding only when a
  `COMPLETED` `check`/`discovery` job for this scan has the finding's `scanner` and `asset_id`.
  Failed, skipped, exhausted-retry and unplanned checks confer no coverage.
- **Suppressed findings stay suppressed unless the evidence changes materially.** Re-observation
  reopens an `accepted_risk`/`false_positive` finding only when its severity or confidence
  changed, or when the incoming evidence set (kind + canonical JSON, order-insensitive) differs
  from the finding's latest recorded evidence batch (fetched alone with `max(captured_at)`, so
  the finding's history size never slows persistence). The comparison happens in persistence,
  before the upsert, and is applied as a conditional `CASE` that re-checks the current status
  and the observation order, so neither a concurrent user decision nor a delayed older scan can
  override the decision blindly. A reopen emits `FindingReopened`.
- **The diff stage owns scan-level transitions.** `services.scan_diff.diff_scan` runs after the
  `persist` barrier: it marks re-observed fixed findings `regressed`, fixes active findings whose
  scanner completed and did not re-observe them, diffs assets, writes `Scan.stats` and audits
  `scan.diffed` in one transaction, then publishes `FindingFixed`/`FindingRegressed`.
  `FindingFixed`/`FindingRegressed`/`FindingReopened` carry identifiers only. `fixed_at` records
  the fixing scan's start, not wall-clock time, and a finding only regresses when that fix
  predates the scanning scan: a delayed observation from an older scan can update
  `last_seen_scan_id` after a newer scan already fixed the finding, and must not undo it.
- **Asset diff.** `new` = discovered assets (subdomains and IPs under the scan root) with
  `first_seen` at or after this scan's start. `disappeared` = subdomains the previous completed
  scan of the same root still saw (`last_seen` between that scan's start and this one's),
  reported only when this scan's discovery stage actually completed: a failed or absent
  discovery means we did not look. IP assets are excluded: they come from `dns.resolve`, and a
  failed resolution leaves their `last_seen` stale, so they would look gone when nothing was
  resolved (per-hostname resolution coverage is a follow-up).
- **`Scan.stats` shape.** `findings.{new,fixed,regressed,total}` are `{total, by_severity}` with
  every severity zero-filled; `total` counts findings observed by this scan in any post-diff
  status (suppressed included). `assets.{new,disappeared}` are `{total, assets: [{id, type,
  value}]}`, capped at 1000 entries while `total` stays exact. The diff is replay-safe: once the
  stats hold a diff, a redelivery changes nothing.

## Consequences
- A scanner removed from a profile stops conferring coverage, so its findings stay open rather
  than being fixed by a check that no longer runs. Deleting a scanner's rule or asset has the
  same conservative effect.
- A fail-open scanner (e.g. RDAP outage) can make its findings look fixed while the upstream is
  down. The job did complete, so the issue's "ran successfully" rule is satisfied; operators see
  the scan's job history.
- Findings on a deactivated asset are never fixed: no scanner runs on an inactive asset, so
  there is no coverage. The takeover finding on a dangling CNAME therefore survives the
  subdomain going inactive, which is the safe direction.
- Suppressed findings are compared against their latest evidence batch, so two scans that share
  a timestamp are compared as one batch. Batches are small (≤10 items) and the comparison is
  order-insensitive.
- Concurrent scans of the same root can both diff; the conditional updates, the `newer` reopen
  gate, the `last_seen <= seen` fix guard and the `fixed_at < seen` regress guard keep an older
  scan from undoing a newer observation or decision in either direction. #21 adds the
  concurrent-scan prevention that makes the window rare.
- IP assets are not reported as disappeared yet; a follow-up can add per-hostname resolution
  coverage (a completed `dns.resolve` job for each hostname that pointed at the address).
- No UI is added here: #21 renders `Scan.stats`, #22 the finding timeline. The status and event
  contracts are fixed by this ADR.
