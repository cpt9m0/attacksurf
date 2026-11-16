"""Entry point: `python -m attacksurf.sandbox_launcher`.

Before it accepts any work the launcher asks the proxy which runtimes Docker has (ADR 0023) and
applies the ADR 0016 rule: gVisor (`runsc`) always; plain `runc` only outside prod and only when
`SANDBOX_ALLOW_RUNC` says so. Anything else, including a proxy that can't be asked, ends the
process with a non-zero exit instead of running with a weaker sandbox than intended. There is no
retry loop: a broken host should show as a failing service, not a running but useless one.
"""

import functools
from collections.abc import Collection
from pathlib import Path
from typing import NoReturn

import structlog

from attacksurf.config import SandboxLauncherSettings
from attacksurf.sandbox_launcher.catalog import load_catalog
from attacksurf.sandbox_launcher.proxy import ProxyClient, ProxyError
from attacksurf.sandbox_launcher.runner import run_sandbox
from attacksurf.sandbox_launcher.server import make_server

log = structlog.get_logger(__name__)


class RuntimeUnavailable(Exception):
    """Docker has no runtime this launcher is allowed to use."""


def select_runtime(names: Collection[str], *, prod: bool, allow_runc: bool) -> str:
    """`runsc` when registered (it wins even if `runc` is allowed); else `runc` only outside
    prod and only when allowed. The prod check is repeated here although the settings already
    refuse `runc` in prod: this is the gate, so it must not rely on a check elsewhere."""
    if "runsc" in names:
        return "runsc"
    if not prod and allow_runc and "runc" in names:
        return "runc"
    raise RuntimeUnavailable


def _fail(reason: str) -> NoReturn:
    # Fixed text only: the proxy URL is a secret setting and error details are not ours to echo.
    raise SystemExit(f"sandbox launcher: {reason}")


def main() -> None:
    settings = SandboxLauncherSettings()
    try:
        catalog = load_catalog(Path(settings.sandbox_images_lock))
    except (ValueError, OSError):
        _fail("the images lock is missing or invalid")
    try:
        proxy = ProxyClient.from_url(settings.sandbox_proxy_url.get_secret_value())
    except ValueError:
        _fail("the sandbox proxy URL is not usable")
    try:
        names = proxy.runtimes()
    except ProxyError:
        _fail("the sandbox proxy did not report its runtimes")
    try:
        runtime = select_runtime(
            names, prod=settings.env == "prod", allow_runc=settings.sandbox_allow_runc
        )
    except RuntimeUnavailable:
        _fail("no permitted container runtime is registered (runsc is required in prod)")

    if runtime == "runc":
        log.warning("sandbox_launcher_runc_fallback")
    log.info(
        "sandbox_launcher_started",
        runtime=runtime,
        analyzers=len(catalog),
        host=settings.sandbox_launcher_host,
        port=settings.sandbox_launcher_port,
    )
    with make_server(
        settings.sandbox_launcher_host,
        settings.sandbox_launcher_port,
        catalog=catalog,
        artifact_root=Path(settings.sandbox_artifact_root),
        run=functools.partial(
            run_sandbox,
            proxy,
            runtime=runtime,
            wall_time=settings.sandbox_wall_time_seconds,
        ),
        max_concurrent_runs=settings.sandbox_max_concurrent_runs,
    ) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
