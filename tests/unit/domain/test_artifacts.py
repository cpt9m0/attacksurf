from pathlib import Path

import pytest

from attacksurf.domain.artifacts import SNIFF_BYTES, sniff_archive

ARCHIVES = Path(__file__).resolve().parents[2] / "fixtures" / "archives"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ok.zip", "zip"),
        ("ok.tar", "tar"),
        ("ok.tar.gz", "gzip"),
        ("ok.tar.bz2", "bzip2"),
        ("ok.tar.xz", "xz"),
    ],
)
def test_sniff_archive_recognizes_supported_formats_by_leading_bytes(
    name: str, expected: str
) -> None:
    head = (ARCHIVES / name).read_bytes()[:SNIFF_BYTES]

    assert sniff_archive(head) == expected


@pytest.mark.parametrize(
    "head", [b"", b"PK", b"\x7fELF\x02\x01\x01", b"MZ\x90\x00", b"#!/bin/sh\n", b"\x00" * 600]
)
def test_sniff_archive_rejects_everything_else(head: bytes) -> None:
    assert sniff_archive(head) is None
