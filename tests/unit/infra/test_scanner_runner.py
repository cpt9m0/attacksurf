from threading import BoundedSemaphore, Event
from uuid import uuid4

import pytest

from attacksurf.domain.assets import AssetType
from attacksurf.domain.scanners import AssetRef, ScanContext, ScannerError, ScanOutput
from attacksurf.infra import scanner_runner
from tests.scanner_fixtures import FakeCheck


def test_timed_out_scanner_cannot_deliver_a_late_result(monkeypatch: pytest.MonkeyPatch) -> None:
    release, finished = Event(), Event()
    monkeypatch.setattr(scanner_runner, "_slots", BoundedSemaphore(1))

    class SlowScanner(FakeCheck):
        timeout_seconds = 0.01

        def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
            release.wait(timeout=2)
            finished.set()
            return super().run(ctx, asset)

    root = AssetRef(type=AssetType.DOMAIN, value="example.com")
    ctx = ScanContext(uuid4(), uuid4(), root, "fixture")
    try:
        with pytest.raises(ScannerError, match="time budget"):
            scanner_runner.run_scanner(SlowScanner(), ctx, root)
        with pytest.raises(ScannerError, match="capacity"):
            scanner_runner.run_scanner(FakeCheck(), ctx, root)
    finally:
        release.set()
        assert finished.wait(timeout=2)


def test_runner_propagates_plugin_failure() -> None:
    class BrokenScanner(FakeCheck):
        def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
            raise RuntimeError("fixture")

    root = AssetRef(type=AssetType.DOMAIN, value="example.com")
    with pytest.raises(RuntimeError, match="fixture"):
        scanner_runner.run_scanner(
            BrokenScanner(), ScanContext(uuid4(), uuid4(), root, "fixture"), root
        )
