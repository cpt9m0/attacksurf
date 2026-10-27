"""Deterministic, no-network plugins. Never imported by production worker startup."""

from attacksurf.domain.assets import AssetType, RelationKind
from attacksurf.domain.findings import Severity
from attacksurf.domain.net import HttpBody, ScannerRuntime
from attacksurf.domain.rules import Rule
from attacksurf.domain.scanners import (
    AssetRef,
    DiscoveredRelation,
    RawEvidence,
    RawFinding,
    ScanContext,
    Scanner,
    ScannerGrant,
    ScanOutput,
    ScanProfile,
)
from attacksurf.scanners.registry import ScannerRegistry

RULE = Rule(
    "test.fixture.issue", "Fixture issue", "Fixture description", Severity.LOW, "Fix $domain"
)

NO_NETWORK = ScannerGrant()


class FixtureGate:
    """Scope-only gate for pipeline tests: fixture scanners get stub adapters."""

    def __init__(self, redirect_allowed: bool = False) -> None:
        self.checked: list[tuple[ScanContext, AssetRef, Scanner]] = []
        self.redirect_allowed = redirect_allowed

    def check(self, ctx: ScanContext, asset: AssetRef, scanner: Scanner) -> ScannerRuntime:
        self.checked.append((ctx, asset, scanner))
        return ScannerRuntime(StubDns(), StubHttp(self.redirect_allowed))


class StubDns:
    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        return ("93.184.216.34",)

    def resolve_name(self, host: str) -> tuple[str, ...]:
        return ("93.184.216.34",)


class StubHttp:
    def __init__(self, redirect_allowed: bool = False) -> None:
        self.redirect_allowed = redirect_allowed

    def get(self, url: str, *, limit: int) -> HttpBody:
        return HttpBody(status_code=200, content=b"[]")

    def close(self) -> None:
        pass


class FakeScanner:
    name = "fixture.discovery"
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 1.0
    grant = NO_NETWORK

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        child = AssetRef(type=AssetType.SUBDOMAIN, value=f"www.{asset.value}")
        return ScanOutput(
            assets=(child,),
            relations=(
                DiscoveredRelation(
                    from_asset=child,
                    to_asset=asset,
                    kind=RelationKind.SUBDOMAIN_OF,
                ),
            ),
        )


class FakeCheck(FakeScanner):
    name = "fixture.check"
    asset_types = frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN})

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        return ScanOutput(
            findings=(
                RawFinding(
                    rule_id=RULE.id,
                    evidence=(RawEvidence(data={"record": "fixture"}),),
                    remediation_context={"domain": asset.value},
                ),
            )
        )


class FailingCheck(FakeCheck):
    name = "fixture.failure"

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        raise RuntimeError("secret upstream response")


def fixture_registry() -> ScannerRegistry:
    registry = ScannerRegistry()
    for plugin in (FakeScanner, FakeCheck, FailingCheck):
        registry.register(plugin)
    return registry


class AssetCountScanner:
    """Discovery plugin that returns three subdomains, to exercise the per-root cap."""

    name = "fixture.names"
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 1.0
    grant = NO_NETWORK

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        return ScanOutput(
            assets=(
                AssetRef(type=AssetType.SUBDOMAIN, value=f"h0.{asset.value}"),
                AssetRef(type=AssetType.SUBDOMAIN, value=f"h1.{asset.value}"),
                AssetRef(type=AssetType.SUBDOMAIN, value=f"h2.{asset.value}"),
            ),
            relations=(
                # h2 is dropped by the cap: its relation must be skipped, not guessed.
                DiscoveredRelation(
                    from_asset=AssetRef(type=AssetType.SUBDOMAIN, value=f"h2.{asset.value}"),
                    to_asset=asset,
                    kind=RelationKind.SUBDOMAIN_OF,
                ),
            ),
        )


def capped_registry() -> ScannerRegistry:
    registry = fixture_registry()
    registry.register(CappedDiscovery)
    return registry


class CappedDiscovery(AssetCountScanner):
    name = "fixture.many"


PROFILES = {
    "fixture": ScanProfile(
        name="fixture",
        discover=(FakeScanner.name,),
        checks=(FakeCheck.name, FailingCheck.name),
    ),
    "capped": ScanProfile(name="capped", discover=("fixture.many",), max_discovered_assets=2),
}
