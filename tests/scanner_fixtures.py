"""Deterministic, no-network plugins. Never imported by production worker startup."""

from attacksurf.domain.assets import AssetType, RelationKind
from attacksurf.domain.findings import Severity
from attacksurf.domain.rules import Rule
from attacksurf.domain.scanners import (
    AssetRef,
    DiscoveredRelation,
    RawEvidence,
    RawFinding,
    ScanContext,
    Scanner,
    ScannerError,
    ScanOutput,
    ScanProfile,
)
from attacksurf.scanners.registry import ScannerRegistry

RULE = Rule(
    "test.fixture.issue", "Fixture issue", "Fixture description", Severity.LOW, "Fix $domain"
)


class FixtureGate:
    def check(self, ctx: ScanContext, asset: AssetRef, scanner: Scanner) -> None:
        if not scanner.name.startswith("fixture.") or scanner.requires_verification:
            raise ScannerError("Not a fixture scanner.")


class FakeScanner:
    name = "fixture.discovery"
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 1.0

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


PROFILES = {
    "fixture": ScanProfile(
        name="fixture",
        discover=(FakeScanner.name,),
        checks=(FakeCheck.name, FailingCheck.name),
    )
}
