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
- **Scan-scoped observations.** `finding_observations` holds one row per `(scan, finding)` with
  the severity at observation time, written by persistence (`ON CONFLICT DO NOTHING`, so replay
  cannot duplicate it). "This scan saw it" is that row, never `Finding.last_seen_scan_id`: the
  pointer follows the latest observation, which overlapping scans can move, and deriving a
  scan's totals, fix eligibility or regressions from it made them wrong. The rows cascade with
  their scan and finding.
- **Suppressed findings stay suppressed unless the evidence changes materially.** Re-observation
  reopens an `accepted_risk`/`false_positive` finding only when its severity or confidence
  changed, or when the incoming evidence set (kind + canonical JSON, order-insensitive) differs
  from the last observed set. `Finding.evidence_digest` stores the SHA-256 of that set, with an
  empty batch as a batch of its own, so the comparison is O(1) and never loads evidence history.
  A DNS RRset's answer order is not meaningful, so `values` is sorted before hashing; a CNAME
  chain's order is the path and is kept.
  `NULL` (a row migrated from before this feature) has an unknown baseline: its first
  observation records the baseline and never reopens on its own, so a migration cannot discard
  a suppression. The comparison happens
  in persistence, before the upsert, and is applied as a conditional `CASE` that re-checks the
  current status and the observation order, so neither a concurrent user decision nor a delayed
  older scan can override the decision blindly. A reopen emits `FindingReopened`.
- **The diff stage owns scan-level transitions.** `services.scan_diff.diff_scan` runs after the
  `persist` barrier: it marks re-observed fixed findings `regressed`, fixes active findings whose
  scanner completed and did not re-observe them, diffs assets, writes `Scan.stats` and audits
  `scan.diffed` in one transaction, then publishes `FindingFixed`/`FindingRegressed`.
  `FindingFixed`/`FindingRegressed`/`FindingReopened` carry identifiers only. `fixed_at` records
  the fixing scan's start, not wall-clock time, and a finding only regresses when that fix
  predates the scanning scan: a delayed observation from an older scan can be persisted after a
  newer scan already fixed the finding, and must not undo it.
- **Asset diff.** `new` = discovered assets (subdomains and IPs under the scan root) whose
  `first_seen_scan_id` is this scan. `disappeared` = subdomains whose `deactivated_by_scan_id`
  is this scan and that an earlier scan first saw: that is a resolution verdict from ADR 0025,
  not an inference from absence, so it does not depend on how complete CT discovery was. Both
  are scan-scoped columns (set by persistence), so an overlapping scan's discoveries or
  deactivations never enter this scan's diff. IP assets are excluded: a failed `dns.resolve`
  leaves their `last_seen` stale without deactivating them, so they would look gone when
  nothing was resolved (per-hostname resolution coverage is a follow-up).
- **`Scan.stats` shape.** `findings.{new,fixed,regressed,total}` are `{total, by_severity}` with
  every severity zero-filled; `total` counts this scan's observation rows in any post-diff
  status (suppressed included), and `new` counts the ones whose finding this scan first saw.
  `assets.{new,disappeared}` are `{total, assets: [{id, type, value}]}`, capped at 1000 entries
  while `total` stays exact. The diff is replay-safe: once the stats hold a diff, a redelivery
  changes nothing.

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
- Suppressed findings compare evidence digests, so two observations with the same evidence set
  (in any order, or both empty) are the same batch.
- Concurrent scans of the same root can both diff; the observation rows make each scan's own
  set independent of the other, and the conditional updates, the `newer` reopen gate, the
  `last_seen <= seen` fix guard and the `fixed_at < seen` regress guard keep an older scan from
  undoing a newer observation or decision in either direction. #21 adds the concurrent-scan
  prevention that makes the window rare.
- IP assets are not reported as disappeared yet; a follow-up can add per-hostname resolution
  coverage (a completed `dns.resolve` job for each hostname that pointed at the address).
- No UI is added here: #21 renders `Scan.stats`, #22 the finding timeline. The status and event
  contracts are fixed by this ADR.
