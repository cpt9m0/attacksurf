# 0014. Ownership verification and authoritative DNS lookups

- Status: accepted
- Date: 2026-11-03

## Context
ADR 0013 put every scanner run behind ScopeGuard and made active checks (target HTTP, and any
plugin declaring `requires_verification`) conditional on `OwnershipChecker.is_verified`, which
was a stub returning `False`. #14 has to make that real: an org must prove it controls a
domain before anything but passive lookups runs against it.

A proof is only meaningful if the app sees the *current* zone data. Resolvers cache TXT
records for minutes to hours, including negative answers, so a check against the system
resolver can report a removed record as present (or a just-published one as absent). It also
has to be impossible to use the check as an SSRF primitive: the check follows nameservers,
which are attacker-influenced when a domain is delegated.

## Decision
- **Proof method**: one TXT record at `_attacksurf-verify.<root>` whose value is
  `attacksurf-verification=<token>`, with a 32-byte random URL-safe token. The token is *not* a
  secret: it is shown in the UI and copied into the owner's DNS provider, and only write access
  to the zone proves anything. Tokens are stored in plain text; rotating one (re-issuing)
  rotates the row back to `pending`, so an old copy stops counting immediately.
- **Inheritance**: proofs belong to root domains. A `subdomain` asset is verified when its
  parent (the scan root it was discovered under) is verified, since both are names in the
  root's zone. Nothing else inherits: discovery sets `parent_id` for every asset a scan finds,
  which records provenance, not ownership — DNS pointing at an IP or URL says nothing about
  controlling it, so those need their own proof method and stay unverified (and their active
  checks denied) until one exists. Re-adding a domain re-issues a token; archived assets are
  never verified.
- **Enclosing zone**: a root added as a subdomain (`eng.example.com`) usually has no NS RRset
  of its own, so the check walks up from the name to the closest ancestor with one, stopping at
  the registrable domain (never at the PSL itself). The TXT record is still read at the
  original `_attacksurf-verify.<root>` name.
- **Authoritative lookups**: `infra/authoritative_dns.py` asks the zone's nameservers for the
  TXT record. This is the **one** place allowed to send a query to a server named in a DNS
  answer (ADR 0013 forbids it for scanners), and it is narrow:
  - the nameserver names come from the stub resolver (`NS` of the scanned root);
  - every nameserver address is validated with the scan-target policy
    (`domain.scope.check_addresses`): loopback, private, link-local (metadata), multicast and
    reserved addresses are never contacted, and an internal-only delegation fails the check;
  - answers are *read*, never followed: an NS or CNAME in the reply is ignored, and only a
    direct TXT record for the exact name counts;
  - bounded: at most 3 nameservers, 2 s per query, UDP with a TCP retry on truncation, and a
    64 KiB response cap;
  - a server that answers SERVFAIL/REFUSED/NOTIMP/FORMERR is treated as unavailable (try the
    next one, then fail the check as transient), never as "the record is absent": interpreting
    an outage as absence would revoke a valid proof.
- **Revocation and grace**: a verified proof is re-checked daily by an hourly beat task; a
  missing record revokes it once `expires_at` (one day after the last success) has passed, so
  a flaky lookup or a worker outage doesn't cut active checks off immediately. Verified proofs
  also expire for the gate after a day, so a revoked domain can't keep its proof just because
  the re-check failed to run.
- **Gate wiring**: `services/ownership.DbOwnershipChecker` implements `OwnershipChecker` over
  the `verifications` table (one indexed read, no writes, denies on any database error) and
  `workers.runtime.scanner_gate()` uses it. The record side is
  `services/ownership.check_ownership`, run by the `passive.verify_ownership` task.
- **Jobs without a scan**: verification isn't a scan, so `jobs.scan_id` is now nullable and
  `create_job` accepts `None`. The row keeps the usual lifecycle (retries, attempts, sanitized
  errors) and job history shows it; deleting a scan no longer deletes its jobs (they are kept
  with `scan_id = NULL`).

## Consequences
- Active checks stay denied until an admin starts verification *and* the record resolves, and
  are revoked automatically when the record disappears.
- The re-verification task is the first `beat_schedule` entry; it runs hourly and only queues
  jobs for proofs that are due, capped per run.
- A hijacked or malicious nameserver can only cause a false "not found" (denial), never a
  false "verified": the token is matched exactly and can't be borrowed from another name.
- DNS lookups from the check are not tied to the scanner grant budget; they are issued by the
  worker, not by plugin code, and bounded as above.
- Verification for IPs and URLs needs its own method; this ADR covers DNS TXT only.
