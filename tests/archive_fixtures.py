"""Builds the archive corpus in `tests/fixtures/archives/` (#86). Hostile on purpose.

Regenerate with `uv run python -m tests.archive_fixtures`. Every file is tiny and deterministic
apart from compressor versions; tests read the committed bytes, check the set of names and
compare the bytes of the files no compressor touched (`UNCOMPRESSED`).
"""

import bz2
import gzip
import hashlib
import io
import lzma
import stat
import struct
import tarfile
import warnings
import zipfile
import zlib
from collections.abc import Callable, Iterable
from pathlib import Path

CORPUS_DIR = Path(__file__).parent / "fixtures" / "archives"

README = b"# demo\n"
APP = b"print('hello')\n"
GOOD = (("README.md", README), ("src/", b""), ("src/app.py", APP))
NOISE = b"".join(hashlib.sha256(bytes([index])).digest() for index in range(256))

ZipEntry = tuple[str, bytes] | tuple[str, bytes, int]


def make_zip(entries: Iterable[ZipEntry], method: int = zipfile.ZIP_DEFLATED) -> bytes:
    """Entries are `(name, data)` or `(name, data, unix_mode)`."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as archive, warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)  # duplicate names are the point
        for name, data, *mode in entries:
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = method
            info.create_system = 3
            info.external_attr = (mode[0] if mode else stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
    return buffer.getvalue()


def raw_zip(
    name: str,
    packed: bytes,
    plain: bytes = b"",
    method: int = zipfile.ZIP_STORED,
    packed_size: int | None = None,
) -> bytes:
    """One entry written by hand, so its data and its declared sizes need not agree."""
    raw = name.encode()
    sizes = (zlib.crc32(plain), len(packed) if packed_size is None else packed_size, len(plain))
    fields = (20, 0, method, 0, 0x5C21, *sizes, len(raw), 0)
    local = struct.pack("<4s5H3L2H", b"PK\x03\x04", *fields) + raw + packed
    attr = (stat.S_IFREG | 0o644) << 16
    central = struct.pack("<4s6H3L5H2L", b"PK\x01\x02", 0x0314, *fields, 0, 0, 0, attr, 0) + raw
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def deflated(data: bytes) -> bytes:
    packer = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return packer.compress(data) + packer.flush()


def member(
    name: str, data: bytes = b"", kind: bytes = tarfile.REGTYPE, mode: int = 0o644, link: str = ""
) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.type, info.mode, info.linkname, info.size = kind, mode, link, len(data)
    return info, data


def make_tar(members: Iterable[tuple[tarfile.TarInfo, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for info, data in members:
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def good_tar() -> bytes:
    return make_tar(
        member(name.rstrip("/"), data, tarfile.DIRTYPE if name.endswith("/") else tarfile.REGTYPE)
        for name, data in GOOD
    )


def gzipped(data: bytes) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as stream:
        stream.write(data)
    return buffer.getvalue()


def patched(data: bytes, old: bytes, new: bytes, count: int = -1) -> bytes:
    assert old in data
    assert len(old) == len(new)
    return data.replace(old, new, count)


def with_zip_flags(data: bytes, flags: int) -> bytes:
    """Set the general-purpose flags of a one-entry zip in both of its headers."""
    central = data.index(b"PK\x01\x02")
    raw = bytearray(data)
    struct.pack_into("<H", raw, 6, flags)
    struct.pack_into("<H", raw, central + 8, flags)
    return bytes(raw)


def _symlink_tar() -> bytes:
    return make_tar(
        [
            member("escape", kind=tarfile.SYMTYPE, link="../"),
            member("passwd", kind=tarfile.SYMTYPE, link="/etc/passwd"),
            member("ok.txt", b"ok\n"),
        ]
    )


def _bad_header_tar() -> bytes:
    """The second member's header checksum is wrong: tarfile stops there without an error."""
    raw = bytearray(make_tar([member("a.txt", b"a\n"), member("b.txt", b"b\n")]))
    raw[1024 + 148 : 1024 + 156] = b"7777777\0"
    return bytes(raw)


def _short_data_zip() -> bytes:
    """Both headers agree on a compressed size four bytes short of the deflate stream."""
    plain = bytes(range(256)) * 4
    data = make_zip([("a.txt", plain)])
    packed = zipfile.ZipFile(io.BytesIO(data)).getinfo("a.txt").compress_size
    sizes = struct.pack("<II", packed, len(plain))
    return patched(data, sizes, struct.pack("<II", packed - 4, len(plain)))


def _local_header_zip(offset: int, value: int) -> bytes:
    """A stored one-entry zip whose local header alone has `value` in the field at `offset`."""
    raw = bytearray(make_zip([("a.txt", b"data\n")], zipfile.ZIP_STORED))
    struct.pack_into("<H", raw, offset, value)
    return bytes(raw)


def _bad_signature_zip() -> bytes:
    data = make_zip([("a.txt", b"a\n"), ("b.txt", b"b\n")], zipfile.ZIP_STORED)
    second = data.index(b"PK\x03\x04", 4)
    return data[:second] + b"PK\x03\x00" + data[second + 4 :]


def _junk_after_deflate_zip() -> bytes:
    """More than one 64 KiB output chunk, then bytes past the stream's end inside the entry."""
    plain = NOISE * 10
    return raw_zip("a.bin", deflated(plain) + b"junk" * 16, plain, zipfile.ZIP_DEFLATED)


def _device_tar() -> bytes:
    char, block = member("dev/null", kind=tarfile.CHRTYPE), member("dev/sda", kind=tarfile.BLKTYPE)
    char[0].devmajor, char[0].devminor = 1, 3
    block[0].devmajor = 8
    return make_tar([char, block, member("ok.txt", b"ok\n")])


BUILDERS: dict[str, Callable[[], bytes]] = {
    # Well-formed archives.
    "ok.zip": lambda: make_zip(GOOD),
    "ok-stored.zip": lambda: make_zip(GOOD, zipfile.ZIP_STORED),
    "ok.tar": good_tar,
    "ok.tar.gz": lambda: gzipped(good_tar()),
    "ok.tar.bz2": lambda: bz2.compress(good_tar()),
    "ok.tar.xz": lambda: lzma.compress(good_tar()),
    "nested.zip": lambda: make_zip([("inner.zip", make_zip(GOOD)), ("inner.tar", good_tar())]),
    "dot-prefixed.tar": lambda: make_tar(
        [member(".", kind=tarfile.DIRTYPE), member("./a.txt", b"a\n")]
    ),
    "zip-dir-mode-file.zip": lambda: make_zip(
        [("evil.py", b"import os\n", stat.S_IFDIR | 0o755), ("ok.txt", b"ok\n")]
    ),
    # Entries that are skipped with a reason.
    "zip-symlink.zip": lambda: make_zip(
        [("link", b"../../etc/passwd", stat.S_IFLNK | 0o777), ("ok.txt", b"ok\n")]
    ),
    "zip-fifo.zip": lambda: make_zip([("pipe", b"", stat.S_IFIFO | 0o644), ("ok.txt", b"ok\n")]),
    "tar-symlink.tar": _symlink_tar,
    "tar-hardlink.tar": lambda: make_tar(
        [member("ok.txt", b"ok\n"), member("hard", kind=tarfile.LNKTYPE, link="../outside")]
    ),
    "tar-device.tar": _device_tar,
    "tar-fifo.tar": lambda: make_tar(
        [member("pipe", kind=tarfile.FIFOTYPE), member("ok.txt", b"ok\n")]
    ),
    # Mode bits that must not survive.
    "zip-setuid.zip": lambda: make_zip([("su", b"#!/bin/sh\n", stat.S_IFREG | 0o6755)]),
    "tar-setuid.tar": lambda: make_tar(
        [
            member("bin", kind=tarfile.DIRTYPE, mode=0o3777),
            member("bin/su", b"#!/bin/sh\n", mode=0o6755),
        ]
    ),
    # Archives that are rejected whole.
    "zip-slip.zip": lambda: make_zip([("ok.txt", b"ok\n"), ("../evil.txt", b"evil\n")]),
    "zip-absolute.zip": lambda: make_zip([("/abs/evil.txt", b"evil\n")]),
    "zip-backslash.zip": lambda: make_zip([("..\\evil.txt", b"evil\n")]),
    "zip-nul-name.zip": lambda: patched(make_zip([("aXb.txt", b"x\n")]), b"aXb.txt", b"a\0b.txt"),
    "zip-duplicate.zip": lambda: make_zip([("a.txt", b"one\n"), ("a.txt", b"two\n")]),
    "zip-file-as-dir.zip": lambda: make_zip([("a", b"file\n"), ("a/b.txt", b"under\n")]),
    "zip-header-mismatch.zip": lambda: patched(
        make_zip([("a.txt", b"data\n")]), b"a.txt", b"b.txt", 1
    ),
    "zip-size-mismatch.zip": lambda: patched(
        make_zip([("a.txt", b"12345")], zipfile.ZIP_STORED),
        struct.pack("<II", 5, 5),
        struct.pack("<II", 5, 4),
        1,
    ),
    "zip-bad-crc.zip": lambda: patched(
        make_zip([("a.txt", b"12345")], zipfile.ZIP_STORED), b"12345", b"12346"
    ),
    "zip-encrypted.zip": lambda: with_zip_flags(make_zip([("secret.txt", b"data\n")]), 0x1),
    "zip-lzma-method.zip": lambda: make_zip([("a.txt", b"data\n")], zipfile.ZIP_LZMA),
    "zip-method-mismatch.zip": lambda: _local_header_zip(8, zipfile.ZIP_DEFLATED),
    "zip-flags-mismatch.zip": lambda: _local_header_zip(6, 0x800),
    "zip-bad-local-signature.zip": _bad_signature_zip,
    "zip-data-past-eof.zip": lambda: raw_zip("a.txt", b"abc", b"abc", packed_size=10_000),
    "zip-deflate-junk.zip": _junk_after_deflate_zip,
    "zip-deflate-ends-early.zip": lambda: raw_zip(
        "a.txt", b"\x03\x00" + bytes(100), method=zipfile.ZIP_DEFLATED
    ),
    "zip-dir-with-data.zip": lambda: raw_zip("evil/", b"import os\n", b"import os\n"),
    "zip-long-name.zip": lambda: make_zip([("a" * 300, b"x\n")]),
    "zip-truncated.zip": lambda: make_zip(GOOD)[:120],
    "zip-truncated-data.zip": _short_data_zip,
    "zip-bomb.zip": lambda: make_zip([("zeros.bin", bytes(1024 * 1024))]),
    "zip-depth.zip": lambda: make_zip([("d/" * 32 + "f.txt", b"deep\n")]),
    "tar-slip.tar": lambda: make_tar([member("ok.txt", b"ok\n"), member("../../evil.txt", b"x")]),
    "tar-absolute.tar": lambda: make_tar([member("/abs/evil.txt", b"evil\n")]),
    "tar-invalid-name.tar": lambda: make_tar([member("bad\udcff.txt", b"x\n")]),
    "tar-duplicate.tar": lambda: make_tar([member("a.txt", b"one\n"), member("a.txt", b"two\n")]),
    "tar-depth.tar": lambda: make_tar([member("d/" * 32 + "f.txt", b"deep\n")]),
    # Writing through a path that an earlier link entry claimed.
    "tar-symlink-write-through.tar": lambda: make_tar(
        [member("escape", kind=tarfile.SYMTYPE, link="../"), member("escape/evil.txt", b"evil\n")]
    ),
    "tar-empty-name.tar": lambda: make_tar([member("./", b"x\n")]),
    "tar-sparse.tar": lambda: make_tar(
        [member("ok.txt", b"ok\n"), member("holes", kind=tarfile.GNUTYPE_SPARSE)]
    ),
    # One member, its data and one zero block; then a second archive nobody would unpack.
    "tar-data-after-end.tar": lambda: (
        make_tar([member("a.txt", b"a\n")])[:1536] + make_tar([member("hidden/evil.py", APP)])
    ),
    # 3 MiB that tarfile reads and drops itself, because the member's type is unknown.
    "tar-skipped-bomb.tar.gz": lambda: gzipped(
        make_tar([member("zz", bytes(3 * 1024 * 1024), kind=b"Z")])
    ),
    "tar-bad-header.tar": _bad_header_tar,
    "tar-truncated.tar": lambda: make_tar([member("big.txt", b"x" * 2000)])[:1500],
    "tar-no-end-marker.tar": lambda: make_tar([member("a.txt", b"a\n")])[:1024],
    "tar-truncated.tar.gz": lambda: gzipped(good_tar())[:-12],
    "tar-bomb.tar.gz": lambda: gzipped(make_tar([member("zeros.bin", bytes(4 * 1024 * 1024))])),
    "not-a-tar.gz": lambda: gzipped(b"just some text, not a tar stream\n" * 40),
    "unknown.bin": lambda: b"MZ\x90\x00 not an archive\n",
}


# No compressor wrote these, so the committed bytes must equal the builder's on any machine.
UNCOMPRESSED = frozenset(name for name in BUILDERS if name.endswith(".tar")) | {
    "ok-stored.zip",
    "zip-size-mismatch.zip",
    "zip-bad-crc.zip",
    "zip-method-mismatch.zip",
    "zip-flags-mismatch.zip",
    "zip-bad-local-signature.zip",
    "zip-data-past-eof.zip",
    "zip-deflate-ends-early.zip",
    "zip-dir-with-data.zip",
    "unknown.bin",
}


def build_corpus() -> dict[str, bytes]:
    return {name: build() for name, build in BUILDERS.items()}


if __name__ == "__main__":
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    for name, data in build_corpus().items():
        (CORPUS_DIR / name).write_bytes(data)
