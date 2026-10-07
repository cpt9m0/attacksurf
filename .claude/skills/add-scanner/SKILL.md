---
name: add-scanner
description: Add a new scanner plugin or security check (DNS, IP, web, code, binary) with its rules, fixtures and tests. Use when implementing any new check, detection rule, or discovery source.
---

# Add a scanner plugin

Read `docs/architecture.md` (scan pipeline section) first.

## Rules of the road
- A scanner **detects and returns normalized output**. It never touches the DB, never calls an
  LLM, and never makes network calls except through `infra/scope_guard` + the safe HTTP client /
  DNS resolver wrappers.
- Passive vs active: if the check sends anything to the target beyond normal public lookups
  (zone transfer, port scan, probing payloads), it is **active** and must declare
  `requires_verification = True`.
- Never exploit, brute force, or claim resources (e.g. takeover checks only *detect*).

## Steps
1. **Rules first:** add rule entries to the rule catalog for the scanner's target type:
   - `rule_id`: dotted, `<target>.<area>.<issue>` e.g. `dns.email.dmarc_missing`
   - default severity (`info|low|medium|high|critical`), title, description, remediation,
     references (RFCs, vendor docs)
2. **Plugin:** `src/attacksurf/scanners/<target>/<name>.py`
   - Implement the `Scanner` protocol, decorate with `@register_scanner`.
   - Set `asset_types`, `queue` (`passive` / `active` / `analysis`), `requires_verification`, timeout.
   - Return `ScanOutput` (discovered assets, relations, raw findings with evidence).
   - Evidence must be what a human needs to confirm the issue: raw records, response snippets
     (size-capped). No secrets.
3. **Profile:** add the scanner to the relevant scan profile(s).
4. **Fixtures:** record realistic responses into `tests/fixtures/<target>/<name>/`. No live
   network in tests.
5. **Tests:** `tests/unit/scanners/<target>/test_<name>.py`:
   - positive case per rule, negative case (clean config → no finding)
   - malformed/hostile input (huge records, weird encodings, HTML/JS in TXT records)
   - timeout/error → scanner fails gracefully
   - fingerprint stability (same input → same fingerprint)
6. **Docs:** add the rules to the scanner/rule list in `docs/`.
7. Run `pre-pr-check`.
