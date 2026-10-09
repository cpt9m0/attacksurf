import hashlib
from pathlib import Path

import attacksurf.web

VENDOR = Path(attacksurf.web.__file__).parent / "static" / "vendor"


def test_vendored_assets_match_checksums() -> None:
    # Supply-chain guard: vendored JS changes only together with SHA256SUMS (vendor/README.md).
    lines = (VENDOR / "SHA256SUMS").read_text().splitlines()

    assert lines
    for line in lines:
        expected, name = line.split()
        assert hashlib.sha256((VENDOR / name).read_bytes()).hexdigest() == expected, name


def test_vendored_assets_ship_their_license_notices() -> None:
    # MIT/ISC require the copyright and permission notice to accompany copies.
    licenses = VENDOR / "licenses"

    for name, holder in [
        ("htmx-LICENSE.txt", "Zero-Clause BSD"),
        ("alpinejs-LICENSE.md", "Caleb Porzio"),
        ("lucide-LICENSE.txt", "Lucide Icons and Contributors"),
    ]:
        assert holder in (licenses / name).read_text(), name


def test_every_vendored_script_is_checksummed() -> None:
    listed = {line.split()[1] for line in (VENDOR / "SHA256SUMS").read_text().splitlines()}

    assert {p.name for p in VENDOR.glob("*.js")} == listed
