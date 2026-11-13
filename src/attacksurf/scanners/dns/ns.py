"""Nameserver hygiene checks (#19, ADR 0026).

`dns.ns` asks every authoritative nameserver of the scanned zone for its SOA record and reports
three delegation problems: a zone with a single nameserver (no redundancy), a server that does
not answer authoritatively (a lame delegation), and servers whose SOA serials disagree (they
serve different zone versions). Only the zone apex itself is checked, so a non-apex root is not
attributed findings that belong to its parent zone.

Unreachable servers are not evidence of lameness and are skipped; a server that answers but
lacks authority, returns NXDOMAIN, or refuses the query is reported. Evidence is capped raw
SOA/NS data.
"""

from collections.abc import Sequence

from attacksurf.domain.findings import Confidence, EvidenceKind
from attacksurf.domain.net import AuthoritativeAnswer, DnsRecordType, DnsStatus
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

DNS_LOOKUPS = 16
MAX_EVIDENCE_VALUES = 5
MAX_VALUE_LENGTH = 256
_SOA_SERIAL_INDEX = 2


@register_scanner
class DnsNameservers:
    name = "dns.ns"
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 60.0
    grant = ScannerGrant(authoritative_dns=True, dns_lookups=DNS_LOOKUPS)

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        runtime = ctx.runtime
        if runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        answers = runtime.authoritative.query(asset.value, DnsRecordType.SOA)
        if answers.zone != asset.value:
            return ScanOutput()  # only the zone apex itself is checked
        findings: list[RawFinding] = []
        if len(answers.servers) == 1:
            findings.append(_single_nameserver(answers.zone, answers.servers))
        findings.extend(_lame_answers(answers.zone, answers.answers))
        serials = _serials(answers.answers)
        if len(serials) > 1:
            findings.append(_inconsistent_soa(answers.zone, answers.answers, serials))
        return ScanOutput(findings=tuple(findings))


def _single_nameserver(zone: str, servers: Sequence[str]) -> RawFinding:
    return RawFinding(
        rule_id="dns.ns.single_nameserver",
        evidence=(_evidence("NS", zone, servers),),
        remediation_context={"zone": zone},
    )


def _lame_answers(zone: str, answers: Sequence[AuthoritativeAnswer]) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for answer in answers:
        if not answer.rcode:
            continue  # unreachable: no evidence either way
        if answer.rcode == "noerror" and answer.authoritative and answer.status is DnsStatus.OK:
            continue
        findings.append(
            RawFinding(
                rule_id="dns.ns.lame_delegation",
                location=answer.server,
                confidence=Confidence.MEDIUM,
                evidence=(
                    _evidence(
                        "SOA",
                        zone,
                        [
                            f"rcode={answer.rcode} "
                            f"authoritative={'yes' if answer.authoritative else 'no'}",
                            *answer.values,
                        ],
                    ),
                ),
                remediation_context={"zone": zone, "server": answer.server},
            )
        )
    return findings


def _serials(answers: Sequence[AuthoritativeAnswer]) -> dict[int, str]:
    """Serial -> first server that reported it, over authoritative SOA answers only."""
    serials: dict[int, str] = {}
    for answer in answers:
        if answer.status is not DnsStatus.OK or not answer.authoritative or not answer.values:
            continue
        serial = _soa_serial(answer.values[0])
        if serial is not None:
            serials.setdefault(serial, answer.server)
    return serials


def _inconsistent_soa(
    zone: str, answers: Sequence[AuthoritativeAnswer], serials: dict[int, str]
) -> RawFinding:
    values = [
        f"{answer.server}: {answer.values[0]}"
        for answer in answers
        if answer.status is DnsStatus.OK and answer.authoritative and answer.values
    ]
    return RawFinding(
        rule_id="dns.ns.inconsistent_soa",
        confidence=Confidence.MEDIUM,
        evidence=(_evidence("SOA", zone, values),),
        remediation_context={"zone": zone, "count": str(len(serials))},
    )


def _soa_serial(value: str) -> int | None:
    """The serial field of a SOA presentation value (`mname rname serial refresh retry ...`)."""
    parts = value.split()
    if len(parts) <= _SOA_SERIAL_INDEX:
        return None
    try:
        return int(parts[_SOA_SERIAL_INDEX])
    except ValueError:
        return None


def _evidence(record: str, name: str, values: Sequence[str]) -> RawEvidence:
    return RawEvidence(
        kind=EvidenceKind.DNS_RECORD,
        data={
            "record": record,
            "name": name,
            "values": [value[:MAX_VALUE_LENGTH] for value in values[:MAX_EVIDENCE_VALUES]],
        },
    )
