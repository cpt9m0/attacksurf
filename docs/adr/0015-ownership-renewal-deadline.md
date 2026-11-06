# 0015. Renew ownership proofs before authorization expires

- Status: accepted
- Date: 2026-11-05

## Context
ADR 0014 schedules daily re-verification when the proof expires. An hourly beat can pick it
up almost an hour later, leaving even healthy domains without authorization until renewal.
Zone discovery also must distinguish an absent NS record from a failed lookup: walking past
a failure can mistake a parent's referral for absence of the child's proof.

## Decision
Amend ADR 0014's renewal schedule: a successful check sets `recheck_at` 20 hours ahead and
`expires_at` 24 hours ahead. The hourly scheduler uses `recheck_at`; the gate continues to use
only `expires_at`. Four hours allow an hourly scheduling delay and one two-hour lookup retry
backoff. Missing records retain the existing expiry grace; errors never extend authorization.
Migration 0007 backfills the deadline four hours before existing expiry without changing it.
Verified rows without a deadline are immediately due, and rotating a token clears its deadline.

Zone discovery propagates NS lookup failures as `TxtError`, preserving the proof's stored
status and triggering the existing transient retry and backoff. Only a successful lookup with
no NS records for the queried owner permits walking to a parent.

## Consequences
Healthy proofs can renew while still authorizing checks. Prolonged DNS or worker outages can
still expire authorization after 24 hours. A discovery failure cannot revoke a valid proof by
falling back to the wrong zone. The additional deadline requires a nullable database column.
