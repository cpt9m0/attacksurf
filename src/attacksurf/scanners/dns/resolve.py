"""Resolve a domain's DNS records and build the IP/CNAME asset graph (#16).

The scanner only asks the configured public resolvers through ScopeGuard. Answers are untrusted
data: hostnames and addresses are normalized, values are capped, and a private address is
reported (never contacted). External CNAME targets are kept in `Asset.details` rather than turned
into tenant assets; only names under the scanned root join the graph.
"""

import ipaddress
import json
from collections.abc import Iterable
from dataclasses import dataclass
from itertools import pairwise

from pydantic import JsonValue

from attacksurf.domain.assets import (
    AssetError,
    AssetType,
    InvalidAssetValue,
    RelationKind,
    normalize_hostname,
    normalize_ip,
)
from attacksurf.domain.findings import EvidenceKind
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import (
    DnsError,
    DnsLookup,
    DnsQuery,
    DnsRecordType,
    DnsResolver,
    DnsStatus,
)
from attacksurf.domain.scanners import (
    MAX_ASSET_DETAILS_BYTES,
    AssetObservation,
    AssetRef,
    DiscoveredRelation,
    RawEvidence,
    RawFinding,
    ScanContext,
    ScannerError,
    ScannerGrant,
    ScanOutput,
)
from attacksurf.domain.scope import is_blocked_address
from attacksurf.scanners.registry import register_scanner

DNS_LOOKUPS = 40
RECORD_TYPES = (
    DnsRecordType.A,
    DnsRecordType.AAAA,
    DnsRecordType.CNAME,
    DnsRecordType.MX,
    DnsRecordType.NS,
    DnsRecordType.TXT,
    DnsRecordType.CAA,
    DnsRecordType.SOA,
)
MAX_CNAME_DEPTH = 5
MAX_ADDRESSES = 20
MAX_REVERSE_LOOKUPS = 10
MAX_RECORDS_PER_TYPE = 5
MAX_RECORD_LENGTH = 256
MAX_HOSTNAME_LENGTH = 253
PRIVATE_IP_RULE = "dns.records.private_ip_exposed"


@dataclass(frozen=True)
class _Resolution:
    by_type: dict[DnsRecordType, DnsLookup]
    chain: tuple[str, ...]
    chain_error: bool
    addresses: tuple[tuple[DnsRecordType, str], ...]
    address_error: bool
    ptr: dict[str, str]


@register_scanner
class DnsResolve:
    name = "dns.resolve"
    asset_types = frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 60.0
    grant = ScannerGrant(dns_lookups=DNS_LOOKUPS)

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        runtime = ctx.runtime
        if runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        try:
            initial = runtime.dns.lookup_many(
                tuple(DnsQuery(asset.value, record_type) for record_type in RECORD_TYPES)
            )
        except DnsError:
            raise TransientJobError("DNS resolution failed.") from None
        if all(result.status is DnsStatus.ERROR for result in initial):
            raise TransientJobError("DNS resolution failed.")
        by_type = {result.query.record_type: result for result in initial}
        chain, chain_error = _cname_chain(runtime.dns, asset.value, by_type[DnsRecordType.CNAME])
        addresses, address_error = _addresses(runtime.dns, chain, by_type)
        ptr = _reverse_dns(runtime.dns, addresses)
        return _output(
            ctx,
            asset,
            _Resolution(
                by_type=by_type,
                chain=chain,
                chain_error=chain_error,
                addresses=addresses,
                address_error=address_error,
                ptr=ptr,
            ),
        )


def _cname_chain(dns: DnsResolver, start: str, first: DnsLookup) -> tuple[tuple[str, ...], bool]:
    """Follow CNAMEs up to the depth cap; the bool reports a lookup error, not a missing hop."""
    chain = [start]
    seen = {start}
    current = start
    lookup = first
    for _ in range(MAX_CNAME_DEPTH):
        if lookup.status is DnsStatus.ERROR:
            return tuple(chain), True
        if lookup.status is not DnsStatus.OK or not lookup.values:
            return tuple(chain), False
        target = _hostname(lookup.values[0])
        if target is None:
            return tuple(chain), False
        if target in seen:
            return tuple(chain), False
        chain.append(target)
        seen.add(target)
        current = target
        try:
            lookup = dns.lookup_many((DnsQuery(current, DnsRecordType.CNAME),))[0]
        except DnsError:
            return tuple(chain), True
    return tuple(chain), False


def _addresses(
    dns: DnsResolver, chain: tuple[str, ...], by_type: dict[DnsRecordType, DnsLookup]
) -> tuple[tuple[tuple[DnsRecordType, str], ...], bool]:
    """Unique normalized A/AAAA addresses for the chain's terminal name.

    The initial A/AAAA queries already followed a short CNAME chain; when a chain is present we
    ask the terminal name explicitly so a long/looping chain cannot hide the final answer.
    """
    error = False
    if len(chain) > 1:
        try:
            results = dns.lookup_many(
                (
                    DnsQuery(chain[-1], DnsRecordType.A),
                    DnsQuery(chain[-1], DnsRecordType.AAAA),
                )
            )
        except DnsError:
            return (), True
        lookups = {result.query.record_type: result for result in results}
    else:
        lookups = by_type
    found: list[tuple[DnsRecordType, str]] = []
    seen: set[str] = set()
    for record_type in (DnsRecordType.A, DnsRecordType.AAAA):
        lookup = lookups.get(record_type)
        if lookup is None:
            continue
        error = error or lookup.status is DnsStatus.ERROR
        for raw in lookup.values:
            try:
                address = normalize_ip(raw)
            except InvalidAssetValue:
                continue
            if address in seen:
                continue
            seen.add(address)
            found.append((record_type, address))
            if len(found) >= MAX_ADDRESSES:
                return tuple(found), error
    return tuple(found), error


def _reverse_dns(
    dns: DnsResolver, addresses: tuple[tuple[DnsRecordType, str], ...]
) -> dict[str, str]:
    """PTR names for the first few addresses; failures are simply absent enrichment."""
    targets = addresses[:MAX_REVERSE_LOOKUPS]
    queries: list[DnsQuery] = []
    reverse: dict[str, str] = {}
    for _record_type, address in targets:
        try:
            reverse_name = ipaddress.ip_address(address).reverse_pointer
        except ValueError:
            continue
        reverse[reverse_name] = address
        queries.append(DnsQuery(reverse_name, DnsRecordType.PTR))
    if not queries:
        return {}
    try:
        results = dns.lookup_many(tuple(queries))
    except DnsError:
        return {}
    names: dict[str, str] = {}
    for result in results:
        if result.status is not DnsStatus.OK or not result.values:
            continue
        host = _hostname(result.values[0])
        address = reverse.get(result.query.name)
        if host is not None and address is not None:
            names[address] = host
    return names


def _output(ctx: ScanContext, asset: AssetRef, resolution: _Resolution) -> ScanOutput:
    runtime = ctx.runtime
    if runtime is None:
        raise ScannerError("Scanner runtime is not configured.")
    private = {
        address
        for record_type, address in resolution.addresses
        if _is_private(record_type, address)
    }
    dns_details = _fit_details(
        _dns_details(resolution.by_type, resolution.chain, resolution.addresses, private)
    )
    active = _active(
        resolution.by_type,
        resolution.chain,
        resolution.chain_error,
        resolution.address_error,
        ctx.target_is_wildcard,
    )
    # A transient failure with no data must not erase records from the last good scan; a
    # confirmed empty answer (active False) does replace them.
    details: dict[str, JsonValue] = {}
    if dns_details or active is False:
        details["dns"] = dns_details
    assets, relations = _graph(ctx, asset, resolution.chain, resolution.addresses)
    observations = [AssetObservation(asset=asset, details=details, active=active)]
    findings = _private_findings(asset, resolution.chain, private)
    for _record_type, address in resolution.addresses:
        info = runtime.ip_intel.lookup(address)
        ip_details: dict[str, JsonValue] = {}
        if address in resolution.ptr:
            ip_details["ptr"] = resolution.ptr[address]
        if info is not None:
            if info.asn is not None:
                ip_details["asn"] = info.asn
            if info.org:
                ip_details["org"] = info.org[:200]
            if info.country:
                ip_details["country"] = info.country[:8]
        if ip_details:
            observations.append(
                AssetObservation(
                    asset=AssetRef(type=AssetType.IP, value=address),
                    details={"ip": ip_details},
                    active=True,
                )
            )
    return ScanOutput(
        assets=tuple(assets),
        relations=tuple(relations),
        findings=tuple(findings),
        observations=tuple(observations),
    )


def _dns_details(
    by_type: dict[DnsRecordType, DnsLookup],
    chain: tuple[str, ...],
    addresses: tuple[tuple[DnsRecordType, str], ...],
    private: set[str],
) -> dict[str, JsonValue]:
    details: dict[str, JsonValue] = {}
    for record_type, key in (
        (DnsRecordType.CNAME, "cname"),
        (DnsRecordType.MX, "mx"),
        (DnsRecordType.NS, "ns"),
        (DnsRecordType.TXT, "txt"),
        (DnsRecordType.CAA, "caa"),
        (DnsRecordType.SOA, "soa"),
    ):
        values = _values(by_type.get(record_type))
        if record_type in {DnsRecordType.CNAME, DnsRecordType.NS}:
            values = tuple(
                host for host in (_hostname(value) for value in values) if host is not None
            )
        records = _records(values)
        if records:
            details[key] = list[JsonValue](records)
    for record_type, key in ((DnsRecordType.A, "a"), (DnsRecordType.AAAA, "aaaa")):
        records = _records(
            address for address_type, address in addresses if address_type is record_type
        )
        if records:
            details[key] = list[JsonValue](records)
    if len(chain) > 1:
        details["cname_chain"] = list[JsonValue](
            _records(chain, limit=MAX_CNAME_DEPTH + 1, length=253)
        )
    if private:
        details["private_ips"] = list[JsonValue](sorted(private))
    return details


def _fit_details(details: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Trim records until the JSON fits the observation cap; never let a huge TXT fail the job."""
    while _details_size(details) > MAX_ASSET_DETAILS_BYTES:
        for key in (
            "txt",
            "soa",
            "caa",
            "mx",
            "ns",
            "cname",
            "aaaa",
            "a",
            "private_ips",
            "cname_chain",
        ):
            values = details.get(key)
            if isinstance(values, list) and values:
                values.pop()
                if not values:
                    del details[key]
                break
        else:
            break
    return details


def _details_size(details: dict[str, JsonValue]) -> int:
    return len(json.dumps(details, ensure_ascii=False, allow_nan=False).encode())


def _graph(
    ctx: ScanContext,
    asset: AssetRef,
    chain: tuple[str, ...],
    addresses: tuple[tuple[DnsRecordType, str], ...],
) -> tuple[list[AssetRef], list[DiscoveredRelation]]:
    assets: list[AssetRef] = []
    relations: list[DiscoveredRelation] = []
    seen_assets = {(asset.type, asset.value)}
    seen_relations: set[tuple[tuple[AssetType, str], tuple[AssetType, str], RelationKind]] = set()
    chain_refs: list[AssetRef | None] = []
    for hop in chain:
        ref = _chain_ref(ctx, asset, hop)
        chain_refs.append(ref)
        if ref is not None and ref not in (asset, ctx.root_asset):
            key = (ref.type, ref.value)
            if key not in seen_assets:
                seen_assets.add(key)
                assets.append(ref)
    for previous, current in pairwise(chain_refs):
        if previous is None or current is None or previous == current:
            continue
        _add_relation(relations, seen_relations, previous, current, RelationKind.CNAME_TO)
    for _record_type, address in addresses:
        target = AssetRef(type=AssetType.IP, value=address)
        key = (target.type, target.value)
        if key not in seen_assets:
            seen_assets.add(key)
            assets.append(target)
        _add_relation(relations, seen_relations, asset, target, RelationKind.RESOLVES_TO)
    return assets, relations


def _chain_ref(ctx: ScanContext, asset: AssetRef, hop: str) -> AssetRef | None:
    if hop == asset.value:
        return asset
    if hop == ctx.root_asset.value:
        return ctx.root_asset
    if hop.endswith(f".{ctx.root_asset.value}"):
        try:
            return AssetRef(type=AssetType.SUBDOMAIN, value=hop)
        except ValueError:
            return None
    return None


def _add_relation(
    relations: list[DiscoveredRelation],
    seen: set[tuple[tuple[AssetType, str], tuple[AssetType, str], RelationKind]],
    source: AssetRef,
    target: AssetRef,
    kind: RelationKind,
) -> None:
    key = ((source.type, source.value), (target.type, target.value), kind)
    if key in seen:
        return
    seen.add(key)
    relations.append(DiscoveredRelation(from_asset=source, to_asset=target, kind=kind))


def _active(
    by_type: dict[DnsRecordType, DnsLookup],
    chain: tuple[str, ...],
    chain_error: bool,
    address_error: bool,
    wildcard: bool,
) -> bool | None:
    if len(chain) > 1 or any(result.found for result in by_type.values()):
        return True
    if chain_error or address_error or wildcard:
        return None
    return False


def _private_findings(
    asset: AssetRef, chain: tuple[str, ...], addresses: set[str]
) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for address in sorted(addresses):
        findings.append(
            RawFinding(
                rule_id=PRIVATE_IP_RULE,
                location=address,
                evidence=(
                    RawEvidence(
                        kind=EvidenceKind.DNS_RECORD,
                        data={
                            "record": "A" if ":" not in address else "AAAA",
                            "value": address,
                            "cname_chain": list(chain),
                        },
                    ),
                ),
                remediation_context={"domain": asset.value, "address": address},
            )
        )
    return findings


def _is_private(record_type: DnsRecordType, address: str) -> bool:
    if record_type not in {DnsRecordType.A, DnsRecordType.AAAA}:
        return False
    try:
        return is_blocked_address(ipaddress.ip_address(address))
    except ValueError:
        return False


def _values(lookup: DnsLookup | None) -> tuple[str, ...]:
    if lookup is None or lookup.status is not DnsStatus.OK:
        return ()
    return lookup.values


def _records(
    values: Iterable[str], *, limit: int = MAX_RECORDS_PER_TYPE, length: int = MAX_RECORD_LENGTH
) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = raw.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value[:length])
        if len(result) >= limit:
            break
    return tuple(result)


def _hostname(raw: str) -> str | None:
    """Normalize a DNS name (trailing dot stripped); None for anything not a hostname."""
    candidate = raw.strip().removesuffix(".")
    if not candidate or len(candidate) > MAX_HOSTNAME_LENGTH:
        return None
    try:
        return normalize_hostname(candidate)
    except (AssetError, ValueError, UnicodeError):
        return None
