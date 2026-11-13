"""Zone-transfer exposure check (#19, ADR 0026).

`dns.axfr` asks every nameserver of the scanned zone for a full zone transfer. A server that
hands the zone to an unauthenticated client exposes every hostname and record in it
(`dns.axfr.allowed`, high). This is an active check: the grant requires a verified asset, and
ScopeGuard skips unverified roots before the plugin runs. The adapter only attempts a transfer
when the scanned name owns NS records itself, so a non-apex root can never cause a parent zone
to be transferred. Only the number of records in the first response is kept; zone content is
never stored.
"""

from attacksurf.domain.findings import EvidenceKind
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

DNS_LOOKUPS = 10


@register_scanner
class DnsZoneTransfer:
    name = "dns.axfr"
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "passive"  # the active queue is reserved until #70; the grant still needs a proof
    requires_verification = True
    timeout_seconds = 60.0
    grant = ScannerGrant(zone_transfer=True, dns_lookups=DNS_LOOKUPS)

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        runtime = ctx.runtime
        if runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        attempts = runtime.zone_transfer.attempt(asset.value)
        findings = tuple(
            RawFinding(
                rule_id="dns.axfr.allowed",
                location=attempt.server,
                evidence=(
                    RawEvidence(
                        kind=EvidenceKind.DNS_RECORD,
                        data={
                            "record": "AXFR",
                            "name": asset.value,
                            "values": [attempt.server],
                            "records": attempt.records,
                        },
                    ),
                ),
                remediation_context={
                    "zone": asset.value,
                    "server": attempt.server,
                    "records": str(attempt.records),
                },
            )
            for attempt in attempts
            if attempt.allowed
        )
        return ScanOutput(findings=findings)
