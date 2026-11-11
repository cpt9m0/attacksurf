"""Passive subdomain discovery from Certificate Transparency logs (#15).

The scanner only reads public CT sources through ScopeGuard and returns normalized assets and
relations. Complete source results are cached per root so a flaky crt.sh does not cost a request
on every rescan; wildcard zones are detected with a bounded number of random-label DNS queries so
later resolution does not mistake wildcard answers for real hosts (ADR 0022).
"""

import json
import secrets
from collections.abc import Iterable
from itertools import islice

from attacksurf.domain.assets import AssetType, RelationKind
from attacksurf.domain.cache import ScanCache
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError, DnsResolver
from attacksurf.domain.scanners import (
    AssetRef,
    DiscoveredRelation,
    ScanContext,
    ScannerError,
    ScannerGrant,
    ScanOutput,
)
from attacksurf.domain.scope import HttpPermission, ScopeError
from attacksurf.scanners.dns import ct
from attacksurf.scanners.registry import register_scanner

CACHE_KEY_PREFIX = "ct:v1:"
CACHE_TTL_SECONDS = 6 * 60 * 60
MAX_WILDCARD_CHECKS = 6
DNS_LOOKUPS = 20


@register_scanner
class CtDiscovery:
    name = "dns.discovery.ct"
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 180.0
    grant = ScannerGrant(
        http=HttpPermission.SERVICES,
        http_hosts=frozenset({ct.CRT_SH_HOST, ct.CERTSPOTTER_HOST}),
        dns_lookups=DNS_LOOKUPS,
    )

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        runtime = ctx.runtime
        if runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        root = asset.value
        result = _load_cache(runtime.cache, root)
        if result is None:
            result = ct.query_sources(runtime.http, root)
            if result is None:
                raise TransientJobError("Certificate Transparency sources are unavailable.")
            _store_cache(runtime.cache, root, result)
        names = tuple(islice(result.names, _limit(ctx)))
        assets = tuple(AssetRef(type=AssetType.SUBDOMAIN, value=name) for name in names)
        relations = tuple(
            DiscoveredRelation(
                from_asset=discovered, to_asset=asset, kind=RelationKind.SUBDOMAIN_OF
            )
            for discovered in assets
        )
        zones = _detect_wildcards(runtime.dns, root, result.wildcard_zones)
        return ScanOutput(
            assets=assets,
            relations=relations,
            wildcard_zones=_wildcard_refs(asset, names, zones),
        )


def _limit(ctx: ScanContext) -> int:
    if ctx.max_discovered_assets is None:
        return ct.MAX_NAMES
    return max(0, min(ctx.max_discovered_assets, ct.MAX_NAMES))


def _wildcard_refs(
    root: AssetRef, names: tuple[str, ...], zones: tuple[str, ...]
) -> tuple[AssetRef, ...]:
    """Root and discovered zone refs, skipping zones a cap dropped: never mark a missing row."""
    available = set(names)
    refs: list[AssetRef] = []
    seen: set[tuple[AssetType, str]] = set()
    for zone in zones:
        if zone == root.value:
            ref = root
        elif zone in available:
            ref = AssetRef(type=AssetType.SUBDOMAIN, value=zone)
        else:
            continue
        key = (ref.type, ref.value)
        if key in seen:
            continue
        seen.add(key)
        refs.append(ref)
    return tuple(refs)


def _detect_wildcards(dns: DnsResolver, root: str, candidates: tuple[str, ...]) -> tuple[str, ...]:
    """Zones whose random label resolves. The root is always checked; failures are not fatal."""
    ordered = tuple(dict.fromkeys((root, *candidates)))[:MAX_WILDCARD_CHECKS]
    return tuple(zone for zone in ordered if _resolves_random(dns, zone))


def _resolves_random(dns: DnsResolver, zone: str) -> bool:
    host = f"{secrets.token_hex(8)}.{zone}"
    try:
        return bool(dns.resolve_name(host))
    except (DnsError, ScopeError):
        # NXDOMAIN is the normal "no wildcard" answer; a blocked address or exhausted DNS
        # budget is likewise not evidence of a wildcard, and must not fail the discovery run.
        return False


def _load_cache(cache: ScanCache, root: str) -> ct.SourceResult | None:
    raw = cache.get(_cache_key(root))
    if raw is None:
        return None
    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    if not isinstance(payload, dict):
        return None
    names = _strings(payload.get("names"))
    zones = _strings(payload.get("wildcard_zones"))
    if names is None or zones is None:
        return None
    return ct.SourceResult(
        names=_cached_names(names, root),
        wildcard_zones=_cached_zones(zones, root),
    )


def _store_cache(cache: ScanCache, root: str, result: ct.SourceResult) -> None:
    if not result.complete:
        return
    payload = json.dumps(
        {"names": list(result.names), "wildcard_zones": list(result.wildcard_zones)},
        separators=(",", ":"),
    )
    cache.set(_cache_key(root), payload, ttl_seconds=CACHE_TTL_SECONDS)


def _cache_key(root: str) -> str:
    return f"{CACHE_KEY_PREFIX}{root}"


def _strings(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return tuple(value[: ct.MAX_NAMES])


def _cached_names(names: Iterable[str], root: str) -> tuple[str, ...]:
    filtered = {name for name in (ct.under_root(raw, root) for raw in names) if name}
    filtered.discard(root)
    return tuple(sorted(filtered, key=_order))[: ct.MAX_NAMES]


def _cached_zones(zones: Iterable[str], root: str) -> tuple[str, ...]:
    filtered = {zone for zone in (ct.under_root(raw, root) for raw in zones) if zone}
    return tuple(sorted(filtered, key=_order))[: ct.MAX_WILDCARD_CANDIDATES]


def _order(name: str) -> tuple[int, str]:
    return (name.count("."), name)
