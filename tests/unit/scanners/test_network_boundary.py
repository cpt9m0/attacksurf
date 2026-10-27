"""No scanner can reach the network except through ScopeGuard and the safe clients.

Import rules are not a sandbox: plugin code runs in-process. What is enforced here is that
production scanner code doesn't *depend* on raw network libraries (requests, sockets, urllib
HTTP, dnspython), so a plugin only gets what its `ScannerGrant` allows, through
`ctx.runtime` (ADR 0013).
"""

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[3] / "src" / "attacksurf"
FORBIDDEN = {
    "requests",
    "httpx",
    "httpcore",
    "socket",
    "urllib.request",
    "http.client",
    "dns.resolver",
    "dns.query",
    "dns.asyncresolver",
    "aiohttp",
    "urllib3",
}
SCANNER_FILES = sorted((PACKAGE / "scanners").rglob("*.py"))


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def _violations(path: Path) -> set[str]:
    return {
        name
        for name in _imports(path)
        if any(name == bad or name.startswith(f"{bad}.") for bad in FORBIDDEN)
    }


@pytest.mark.parametrize("path", SCANNER_FILES, ids=lambda path: path.name)
def test_scanner_modules_do_not_import_raw_network_libraries(path: Path) -> None:
    assert _violations(path) == set()


def test_scanner_package_has_modules_to_check() -> None:
    # Guards against the parametrization silently covering nothing after a move.
    assert SCANNER_FILES


def test_detector_catches_a_direct_network_import(tmp_path: Path) -> None:
    sample = tmp_path / "plugin.py"
    sample.write_text("import requests\nfrom urllib import request\nimport httpx\n")
    assert _violations(sample) == {"requests", "httpx"}
