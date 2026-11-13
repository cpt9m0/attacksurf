"""CAA publication check (#19, ADR 0026).

`dns.caa` looks for a CAA record at the scanned name and at every ancestor up to and including
the registrable domain (CAA is inherited down the tree, RFC 8659 section 3). When every query
succeeded and none has a record, any certificate authority may issue for the domain and the info
finding `dns.caa.missing` is reported. A failed query proves nothing, so it fails open; only a
round where every query errored is retryable. A name too deep for the lookup budget also fails
open, because an unchecked ancestor could still publish the record.
"""

from attacksurf.domain.findings import EvidenceKind
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError, DnsQuery, DnsRecordType, DnsStatus
from attacksurf.domain.scanners import (
    AssetRef,
    AssetType,
    RawEvidence,
    RawFinding,
    ScanContext,
    ScannerError,
    ScannerGrant,
    ScanOutput,
)
from attacksurf.scanners.registry import register_scanner

# One query per label between the asset and its registrable domain; deeper names fail open.
DNS_LOOKUPS = 6


@register_scanner
class DnsCertificateAuthority:
    name = "dns.caa"
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 30.0
    grant = ScannerGrant(dns_lookups=DNS_LOOKUPS)

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        runtime = ctx.runtime
        if runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        org_domain = runtime.org_domain(asset.value) if runtime.org_domain else None
        names = _chain(asset.value, org_domain)
        queried = names[:DNS_LOOKUPS]
        try:
            lookups = runtime.dns.lookup_many(
                tuple(DnsQuery(name, DnsRecordType.CAA) for name in queried)
            )
        except DnsError:
            raise TransientJobError("CAA check failed.") from None
        if any(lookup.values for lookup in lookups):
            return ScanOutput()
        if any(lookup.status is DnsStatus.ERROR for lookup in lookups):
            if all(lookup.status is DnsStatus.ERROR for lookup in lookups):
                raise TransientJobError("CAA check failed.")
            return ScanOutput()  # absence is not proven for a name we could not read
        if len(queried) < len(names):
            return ScanOutput()  # an unchecked ancestor could still publish CAA
        return ScanOutput(
            findings=(
                RawFinding(
                    rule_id="dns.caa.missing",
                    evidence=(_evidence("CAA", names[0]),),
                    remediation_context={"zone": names[-1]},
                ),
            )
        )


def _chain(name: str, registrable: str | None) -> list[str]:
    """`name` and each of its ancestors up to the registrable domain, closest first."""
    normalized = name.strip().rstrip(".").lower()
    if not registrable:
        return [normalized]
    root = registrable.strip().rstrip(".").lower()
    if normalized == root or not normalized.endswith(f".{root}"):
        return [normalized]
    labels = normalized.split(".")
    depth = len(labels) - len(root.split("."))
    return [".".join(labels[index:]) for index in range(depth + 1)]


def _evidence(record: str, name: str) -> RawEvidence:
    return RawEvidence(
        kind=EvidenceKind.DNS_RECORD, data={"record": record, "name": name, "values": []}
    )
