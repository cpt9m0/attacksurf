# Writing a Scanner Plugin

Every check in **attacksurf** is a self-contained plugin under `src/attacksurf/scanners/<target>/`
that emits normalized `ScanOutput` objects ([architecture](architecture.md#scan-pipeline)).

> [!IMPORTANT]
> **Defensive boundary:** checks must only *detect and report*. Never exploit vulnerabilities,
> brute-force credentials, flood targets, or claim dangling resources.

---

## Rules of the Road

1. **No direct network or LLM calls:** plugins never import `requests`, `httpx`, `socket`,
   `urllib.request`, `dnspython` resolvers, `anthropic`, or `openai` (enforced by
   `tests/unit/scanners/test_network_boundary.py`). All I/O uses `ctx.runtime` adapters bounded
   by the plugin's frozen `ScannerGrant`.
2. **Passive vs. verified active:** if a plugin sends anything to the target beyond normal public
   lookups (for example, target HTTP GETs or zone transfers), set `requires_verification = True`
   and declare `HttpPermission.TARGET` or `zone_transfer=True` in `grant`. `ScopeGuard` enforces
   an unexpired DNS TXT ownership proof before running it.
3. **No database access:** plugins receive immutable `ScanContext` and `AssetRef` inputs and
   return `ScanOutput`. The worker pipeline validates and persists outputs atomically.
4. **Bounded outputs & timeouts:** `timeout_seconds` must satisfy `0 < timeout <= 240`. Total
   serialized `ScanOutput` is capped at 2 MiB and individual `RawEvidence.data` payloads at
   64 KiB UTF-8.
5. **Deterministic fingerprints:** when a rule can fire multiple times on one asset, pass a
   stable `location` string (such as a selector name or CNAME target) — never volatile fields
   like TTLs, timestamps, or record order.

---

## Step-by-Step Guide

### 1. Define the Rule (`src/attacksurf/domain/rules/`)

Add your `Rule` dataclass to the target module (e.g., `src/attacksurf/domain/rules/dns.py`) and
include it in `_ALL_RULES` in `src/attacksurf/domain/rules/__init__.py`:

```python
EXAMPLE_MISSING = Rule(
    id="dns.example.record_missing",
    title="No example record published",
    description="Plain-language explanation of the weakness and why it matters.",
    default_severity=Severity.MEDIUM,
    remediation="Publish the expected record at $domain.",
    references=("https://www.rfc-editor.org/rfc/rfc1234",),
)
```

### 2. Implement the Plugin (`src/attacksurf/scanners/<target>/`)

Implement the `Scanner` protocol and decorate the class with `@register_scanner`:

```python
from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import EvidenceKind
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError, DnsQuery, DnsRecordType, DnsStatus
from attacksurf.domain.scanners import (
    AssetRef,
    RawEvidence,
    RawFinding,
    ScanContext,
    ScannerError,
    ScannerGrant,
    ScanOutput,
)
from attacksurf.scanners.registry import register_scanner


@register_scanner
class ExampleCheck:
    name = "dns.example"
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 30.0
    grant = ScannerGrant(dns_lookups=4)

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        runtime = ctx.runtime
        if runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        try:
            lookup = runtime.dns.lookup_many((DnsQuery(asset.value, DnsRecordType.TXT),))[0]
        except DnsError:
            raise TransientJobError("Example lookup failed.") from None
        if lookup.status is DnsStatus.ERROR:
            raise TransientJobError("Example lookup failed.")
        if lookup.values:
            return ScanOutput()
        return ScanOutput(
            findings=(
                RawFinding(
                    rule_id="dns.example.record_missing",
                    evidence=(RawEvidence(kind=EvidenceKind.DNS_RECORD, data={"values": []}),),
                    remediation_context={"domain": asset.value},
                ),
            )
        )
```

For public HTTP data sources, set `grant = ScannerGrant(http=HttpPermission.SERVICES, http_hosts=frozenset({"api.example.com"}), dns_lookups=2)` and use `runtime.http.get(url, limit=...)`. Use `runtime.cache` only for non-tenant public source data and fail open on cache misses.

### 3. Register the Plugin and Enable It in a Profile

1. Add an explicit import in **both** [src/attacksurf/app.py](../src/attacksurf/app.py) and
   [src/attacksurf/workers/app.py](../src/attacksurf/workers/app.py) so every web and worker
   process registers the plugin at startup.
2. Add the plugin's `name` to `ScanProfile.discover` or `ScanProfile.checks` in
   [src/attacksurf/scanners/profiles.py](../src/attacksurf/scanners/profiles.py).

### 4. Record Offline Fixtures and Write Tests

- Place realistic recorded responses under `tests/fixtures/<target>/<name>/` (no live network in tests).
- Add unit tests in `tests/unit/scanners/<target>/test_<name>.py` covering:
  - Positive detection for each rule
  - Clean/negative config returning no findings
  - Hostile/malformed inputs (oversized TXT records, control characters, `<script>` payloads)
  - Transient errors (`TransientJobError`) and timeouts
  - Fingerprint stability across repeated runs

### 5. Document and Verify

1. Add the scanner and rule entries to [docs/scanners.md](scanners.md) (enforced by
   `tests/unit/scanners/test_docs_sync.py`).
2. Run the full verification suite:

```bash
uv run pre-commit run --all-files
uv run pyright
TEST_DATABASE_URL=postgresql+psycopg://attacksurf:attacksurf@127.0.0.1:5432/attacksurf_test uv run pytest
```
