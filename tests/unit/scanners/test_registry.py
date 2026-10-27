import pytest

from attacksurf.domain.assets import AssetType
from attacksurf.domain.scanners import (
    AssetRef,
    ScanContext,
    ScannerGrant,
    ScanOutput,
    ScanProfile,
)
from attacksurf.domain.scope import HttpPermission
from attacksurf.scanners.registry import ScannerRegistry


class EmptyScanner:
    name = "test.empty"
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 1.0
    grant = ScannerGrant()

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        return ScanOutput()


def test_registration_rejects_duplicate_names() -> None:
    registry = ScannerRegistry()
    assert registry.register(EmptyScanner) is EmptyScanner
    with pytest.raises(ValueError, match="duplicate"):
        registry.register(EmptyScanner)


def test_profile_rejects_unknown_plugins() -> None:
    with pytest.raises(ValueError, match="unknown scanner"):
        ScannerRegistry().validate(ScanProfile(name="test", discover=("missing",)))


def test_registration_rejects_invalid_timeout() -> None:
    class BadScanner(EmptyScanner):
        timeout_seconds = 0.0

    with pytest.raises(ValueError, match="timeout"):
        ScannerRegistry().register(BadScanner)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", "invalid name"),
        ("queue", "unknown"),
        ("asset_types", frozenset()),
        ("timeout_seconds", float("nan")),
    ],
)
def test_registry_rejects_invalid_metadata(field: str, value: object) -> None:
    class Invalid(EmptyScanner):
        pass

    setattr(Invalid, field, value)
    with pytest.raises(ValueError, match=r"invalid|asset types|timeout"):
        ScannerRegistry().register(Invalid)


def test_profiles_reject_duplicate_scanners_and_unconsumed_queues() -> None:
    registry = ScannerRegistry()
    registry.register(EmptyScanner)
    with pytest.raises(ValueError, match="duplicate"):
        registry.validate(ScanProfile("test", checks=(EmptyScanner.name, EmptyScanner.name)))

    class ActiveScanner(EmptyScanner):
        name = "test.active"
        queue = "active"
        requires_verification = True

    registry.register(ActiveScanner)
    with pytest.raises(ValueError, match="only passive"):
        registry.validate(ScanProfile("test", checks=(ActiveScanner.name,)))

    with pytest.raises(ValueError, match="max_discovered_assets"):
        registry.validate(ScanProfile("test", checks=(EmptyScanner.name,), max_discovered_assets=0))


@pytest.mark.parametrize(
    ("http", "hosts", "lookups", "error"),
    [
        (HttpPermission.SERVICES, frozenset(), 0, "at least one http host"),
        (HttpPermission.NONE, frozenset({"crt.sh"}), 0, "only meaningful for services"),
        (HttpPermission.NONE, frozenset(), -1, "negative dns budget"),
        (HttpPermission.SERVICES, frozenset({"not a host"}), 1, "invalid http host"),
        (HttpPermission.SERVICES, frozenset({"localhost"}), 1, "invalid http host"),
    ],
)
def test_grants_are_validated_at_registration(
    http: HttpPermission, hosts: frozenset[str], lookups: int, error: str
) -> None:
    class BadGrant(EmptyScanner):
        name = "test.bad_grant"

    with pytest.raises(ValueError, match=error):
        ScannerGrant(http=http, http_hosts=hosts, dns_lookups=lookups)
    # The dataclass is frozen, so a plugin can't patch a bad grant in after construction either.
    with pytest.raises(ValueError, match=error):
        BadGrant.grant = ScannerGrant(http=http, http_hosts=hosts, dns_lookups=lookups)
