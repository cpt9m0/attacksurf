"""DNSSEC delegation-chain check (#19, ADR 0026).

The check asks the zone's own nameservers for their DNSKEY RRset and the stub resolver for the
DS record at the delegation. A zone with no DS is not signed (`dns.dnssec.not_enabled`, info).
A DS that no published key matches is a broken chain (`dns.dnssec.broken_chain`, high): a
validating resolver treats the zone as bogus and returns SERVFAIL. Only the DS -> DNSKEY
*linkage* is verified (key tag, algorithm and digest per RFC 4034 section 5.1.4); RRSIG
signature validation is out of scope for this check.

DNS answers are untrusted: values are stripped, deduplicated and truncated before they reach
evidence. A DS lookup error is retryable; when no nameserver answered authoritatively the check
fails open rather than guessing.
"""

import base64
import binascii
import hashlib
import struct
from collections.abc import Sequence
from dataclasses import dataclass

from attacksurf.domain.findings import Confidence, EvidenceKind
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError, DnsLookup, DnsQuery, DnsRecordType, DnsStatus
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

DNS_LOOKUPS = 12
MAX_EVIDENCE_VALUES = 5
MAX_VALUE_LENGTH = 256
# DS digest types we can verify: SHA-1, SHA-256, SHA-384 (RFC 4034 section 5.1.4).
DIGESTS = {1: "sha1", 2: "sha256", 4: "sha384"}
# RSAMD5 is deprecated and its key tag has a special form; such a zone is left unjudged.
_RSAMD5 = 1
_RDATA_FIELDS = 4
_ZONE_KEY_FLAG = 0x0100
_DNSKEY_PROTOCOL = 3


@dataclass(frozen=True)
class _Ds:
    key_tag: int
    algorithm: int
    digest_type: int
    digest: bytes


@dataclass(frozen=True)
class _Key:
    flags: int
    protocol: int
    algorithm: int
    rdata: bytes  # flags + protocol + algorithm + public key, exactly as digested


@register_scanner
class DnsDnssec:
    name = "dns.dnssec"
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 60.0
    grant = ScannerGrant(authoritative_dns=True, dns_lookups=DNS_LOOKUPS)

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        runtime = ctx.runtime
        if runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        keys = runtime.authoritative.query(asset.value, DnsRecordType.DNSKEY)
        if keys.zone != asset.value:
            return ScanOutput()  # only the zone apex itself carries DS/DNSKEY data
        try:
            ds_lookup = runtime.dns.lookup_many((DnsQuery(asset.value, DnsRecordType.DS),))[0]
        except DnsError:
            raise TransientJobError("DNSSEC check failed.") from None
        if ds_lookup.status is DnsStatus.ERROR:
            raise TransientJobError("DNSSEC check failed.")
        ds_values = _values(ds_lookup)
        if not ds_values:
            return ScanOutput(findings=(_not_enabled(asset.value, ds_lookup),))
        authoritative = [answer for answer in keys.answers if answer.authoritative and answer.rcode]
        if not authoritative:
            return ScanOutput()  # no nameserver gave an authoritative answer: no evidence
        key_values = [value for answer in authoritative for value in answer.values]
        ds_records = [record for record in (_parse_ds(v) for v in ds_values) if record]
        if not ds_records:
            return ScanOutput()  # every DS uses a digest/algorithm we can't verify
        parsed_keys = [key for key in (_parse_dnskey(v) for v in key_values) if key]
        if any(_matches(ds, key, asset.value) for ds in ds_records for key in parsed_keys):
            return ScanOutput()
        return ScanOutput(
            findings=(
                _broken_chain(
                    asset.value,
                    ds_values,
                    key_values,
                    confidence=(Confidence.HIGH if parsed_keys else Confidence.MEDIUM),
                ),
            )
        )


def _not_enabled(zone: str, ds_lookup: DnsLookup) -> RawFinding:
    return RawFinding(
        rule_id="dns.dnssec.not_enabled",
        confidence=Confidence.LOW,
        evidence=(_evidence("DS", zone, _values(ds_lookup)),),
        remediation_context={"zone": zone},
    )


def _broken_chain(
    zone: str, ds_values: Sequence[str], key_values: Sequence[str], *, confidence: Confidence
) -> RawFinding:
    return RawFinding(
        rule_id="dns.dnssec.broken_chain",
        confidence=confidence,
        evidence=(
            _evidence("DS", zone, ds_values),
            _evidence("DNSKEY", zone, key_values),
        ),
        remediation_context={"zone": zone},
    )


def _parse_ds(value: str) -> _Ds | None:
    """`<key tag> <algorithm> <digest type> <hex digest>`; None when unusable."""
    parts = value.split()
    if len(parts) != _RDATA_FIELDS:
        return None
    try:
        key_tag, algorithm, digest_type = int(parts[0]), int(parts[1]), int(parts[2])
        digest = bytes.fromhex(parts[3])
    except ValueError:
        return None
    if digest_type not in DIGESTS or algorithm == _RSAMD5 or not digest:
        return None
    return _Ds(key_tag, algorithm, digest_type, digest)


def _parse_dnskey(value: str) -> _Key | None:
    """`<flags> <protocol> <algorithm> <base64 key>`; None for a non-zone or malformed key."""
    parts = value.split()
    if len(parts) != _RDATA_FIELDS:
        return None
    try:
        flags, protocol, algorithm = int(parts[0]), int(parts[1]), int(parts[2])
        key = base64.b64decode("".join(parts[3].split()), validate=True)
    except (ValueError, binascii.Error):
        return None
    if (
        not key
        or protocol != _DNSKEY_PROTOCOL
        or not flags & _ZONE_KEY_FLAG
        or algorithm == _RSAMD5
    ):
        return None
    rdata = struct.pack("!HBB", flags, protocol, algorithm) + key
    return _Key(flags, protocol, algorithm, rdata)


def _key_tag(rdata: bytes) -> int:
    """RFC 4034 Appendix B key tag over the DNSKEY RDATA."""
    accumulator = 0
    for index, byte in enumerate(rdata):
        accumulator += byte << 8 if index % 2 == 0 else byte
    accumulator += (accumulator >> 16) & 0xFFFF
    return accumulator & 0xFFFF


def _matches(ds: _Ds, key: _Key, zone: str) -> bool:
    if ds.algorithm != key.algorithm or ds.key_tag != _key_tag(key.rdata):
        return False
    digest = hashlib.new(DIGESTS[ds.digest_type], _canonical_name(zone) + key.rdata).digest()
    return digest == ds.digest


def _canonical_name(zone: str) -> bytes:
    """Canonical (lowercase, length-prefixed, root-terminated) wire name (RFC 4034 section 6.2)."""
    labels = zone.rstrip(".").lower().split(".")
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"


def _values(lookup: DnsLookup) -> tuple[str, ...]:
    if lookup.status is not DnsStatus.OK:
        return ()
    seen: set[str] = set()
    result: list[str] = []
    for raw in lookup.values:
        value = raw.strip().replace("\x00", "\\0")
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return tuple(result)


def _evidence(record: str, name: str, values: Sequence[str]) -> RawEvidence:
    return RawEvidence(
        kind=EvidenceKind.DNS_RECORD,
        data={
            "record": record,
            "name": name,
            "values": [value[:MAX_VALUE_LENGTH] for value in values[:MAX_EVIDENCE_VALUES]],
        },
    )
