import pytest

from attacksurf.domain.assets import AssetType
from attacksurf.domain.scanners import AssetRef, ScanContext, ScanOutput, ScanProfile
from attacksurf.scanners.registry import ScannerRegistry


class EmptyScanner:
    name = "test.empty"
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 1.0

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
