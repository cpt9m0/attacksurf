"""Unpack one untrusted archive into a fresh directory, inside the sandbox (ADR 0017, #86).

    python -m attacksurf.sandbox_tools.extract <archive> <dest> [--manifest <path>]

Its own loop over entries: `zipfile` and `tarfile` only parse, every byte is copied here and
counted as it is written, and no link is ever created. Links, devices and FIFOs are skipped and
listed in the manifest. Anything that would leave the tree incomplete or ambiguous (unsafe or
duplicate paths, a corrupt archive, differing zip headers, encrypted or unsupported zip entries,
a cap) rejects the whole artifact and removes what was written, because a partial tree would
read as "no findings". Exit status: 0 ok, 3 rejected, 4 the extractor itself failed; each prints
one JSON line.
"""

import argparse
import bz2
import gzip
import hashlib
import json
import lzma
import os
import shutil
import stat
import struct
import sys
import tarfile
import zipfile
import zlib
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import IO, Any, BinaryIO, Protocol, cast

MAX_TOTAL_BYTES = 512 * 1024**2
MAX_FILE_BYTES = 64 * 1024**2
MAX_ENTRIES = 100_000
MAX_PATH_DEPTH = 32
MAX_COMPRESSION_RATIO = 200
# Stdout is capped at 2 MiB by the launcher: the summary lists only this many skipped entries.
SUMMARY_SKIPPED_ENTRIES = 50
SUMMARY_PATH_CHARS = 256

# Not 1 or 2: those are a Python traceback and an argparse usage error.
EXIT_REJECTED = 3
EXIT_ERROR = 4
_CHUNK = 64 * 1024
_MAX_NAME_BYTES = 255
_TAR_BLOCK = 512
_TAIL_BYTES = 2 * tarfile.RECORDSIZE
_TAR_ENTRY_SLACK = 8 * _TAR_BLOCK  # headers and padding a tar may carry per entry
_ZIP_LOCAL = struct.Struct("<4s5H3L2H")
_ZIP_ENCRYPTED = 0x1 | 0x40
_ZIP_DATA_DESCRIPTOR = 0x08
_ZIP_UTF8 = 0x800
_ZIP64_SIZE = 0xFFFFFFFF
_TAR_SKIPS = {
    tarfile.SYMTYPE: "symlink",
    tarfile.LNKTYPE: "hardlink",
    tarfile.CHRTYPE: "device",
    tarfile.BLKTYPE: "device",
    tarfile.FIFOTYPE: "fifo",
}
_MODE_SKIPS = {
    stat.S_IFLNK: "symlink",
    stat.S_IFCHR: "device",
    stat.S_IFBLK: "device",
    stat.S_IFIFO: "fifo",
    stat.S_IFSOCK: "unsupported_type",
}


class ArchiveRejected(Exception):
    """The whole artifact is refused; `reason` is a fixed code, never archive content."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Caps:
    """The ADR 0017 limits. Tests lower them; production code uses the defaults."""

    total_bytes: int = MAX_TOTAL_BYTES
    file_bytes: int = MAX_FILE_BYTES
    entries: int = MAX_ENTRIES  # files, skipped entries and every directory created, together
    depth: int = MAX_PATH_DEPTH
    ratio: int = MAX_COMPRESSION_RATIO  # bytes written per byte of archive


@dataclass(frozen=True)
class FileEntry:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class SkippedEntry:
    path: str
    reason: str


@dataclass(frozen=True)
class Manifest:
    format: str
    files: tuple[FileEntry, ...]
    skipped: tuple[SkippedEntry, ...]
    total_bytes: int

    def summary(self) -> dict[str, Any]:
        """Bounded: counts plus the first skipped entries. The full list is the manifest file."""
        shown = self.skipped[:SUMMARY_SKIPPED_ENTRIES]
        return {
            "status": "ok",
            "format": self.format,
            "files": len(self.files),
            "total_bytes": self.total_bytes,
            "skipped": len(self.skipped),
            "skipped_sample": [
                {"path": entry.path[:SUMMARY_PATH_CHARS], "reason": entry.reason} for entry in shown
            ],
        }


def detect_format(head: bytes) -> str | None:
    """By magic bytes, never by file name."""
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "tar.gz"
    if head.startswith(b"BZh"):
        return "tar.bz2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "tar.xz"
    return "tar" if head[257:262] == b"ustar" else None


def _safe_parts(name: str, max_depth: int) -> tuple[str, ...]:
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        raise ArchiveRejected("invalid_name") from None
    # A backslash is a separator to some tools and a name character to others: refuse it.
    if not name or "\0" in name or "\\" in name:
        raise ArchiveRejected("invalid_name")
    parts = tuple(part for part in name.split("/") if part not in ("", "."))
    if name.startswith("/") or ".." in parts:
        raise ArchiveRejected("unsafe_path")
    if any(len(part.encode("utf-8")) > _MAX_NAME_BYTES for part in parts):
        raise ArchiveRejected("invalid_name")
    if len(parts) > max_depth:
        raise ArchiveRejected("depth_cap")
    return parts


class _Tree:
    """Writes entries under `root` and keeps the counts. Files are 0600, directories 0700."""

    def __init__(self, root: Path, caps: Caps, archive_bytes: int) -> None:
        self._root = root
        self._caps = caps
        self._allowed_bytes = min(caps.total_bytes, caps.ratio * archive_bytes)
        ratio_binds = caps.ratio * archive_bytes < caps.total_bytes
        self.size_reason = "ratio_cap" if ratio_binds else "total_size_cap"
        self._entries = 0
        self._taken: set[tuple[str, ...]] = set()  # files and skipped entries
        self._dirs: set[tuple[str, ...]] = set()
        self.total_bytes = 0
        self.files: list[FileEntry] = []
        self.skipped: list[SkippedEntry] = []

    def add_dir(self, name: str) -> None:
        self._claim(name, is_dir=True)

    def skip(self, name: str, reason: str) -> None:
        self.skipped.append(SkippedEntry("/".join(self._claim(name, is_dir=False)), reason))

    def add_file(self, name: str, chunks: Iterable[bytes]) -> None:
        parts = self._claim(name, is_dir=False)
        digest, size = hashlib.sha256(), 0
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            fd = os.open(self._root.joinpath(*parts), flags, 0o600)
        except OSError as error:
            raise ArchiveRejected(_write_reason(error)) from error
        with os.fdopen(fd, "wb") as out:
            for chunk in chunks:
                size += len(chunk)
                self.total_bytes += len(chunk)
                if size > self._caps.file_bytes:
                    raise ArchiveRejected("file_size_cap")
                if self.total_bytes > self._allowed_bytes:
                    raise ArchiveRejected(self.size_reason)
                digest.update(chunk)
                try:
                    out.write(chunk)
                    out.flush()
                except OSError as error:
                    raise ArchiveRejected("write_failed") from error
        self.files.append(FileEntry("/".join(parts), size, digest.hexdigest()))

    def stream_limit(self) -> int:
        """Decompressed tar bytes allowed so far: what may be written, plus room for headers."""
        return self._allowed_bytes + (self._entries + 1) * _TAR_ENTRY_SLACK + _TAIL_BYTES

    def _count(self) -> None:
        self._entries += 1
        if self._entries > self._caps.entries:
            raise ArchiveRejected("entry_count_cap")

    def _claim(self, name: str, *, is_dir: bool) -> tuple[str, ...]:
        """Validate the name, count the entry and reserve its path, creating parent directories."""
        parts = _safe_parts(name, self._caps.depth)
        self._count()
        if not parts and not is_dir:
            raise ArchiveRejected("invalid_name")
        dirs = [parts[:end] for end in range(1, len(parts) + (1 if is_dir else 0))]
        if self._taken.intersection([*dirs, parts]) or (not is_dir and parts in self._dirs):
            raise ArchiveRejected("duplicate_path")
        for path in dirs:
            if path not in self._dirs:
                if path != parts:  # a parent no entry named still takes an inode
                    self._count()
                try:
                    os.mkdir(self._root.joinpath(*path), 0o700)
                except OSError as error:
                    raise ArchiveRejected(_write_reason(error)) from error
                self._dirs.add(path)
        if not is_dir:
            self._taken.add(parts)
        return parts


def _write_reason(error: OSError) -> str:
    # Names that differ only by case collide on a case-insensitive filesystem.
    return "duplicate_path" if isinstance(error, FileExistsError) else "write_failed"


def _zip_data_offset(source: BinaryIO, info: zipfile.ZipInfo) -> int:
    """Compare the entry's local header with its central record; return where its data starts."""
    if info.flag_bits & _ZIP_ENCRYPTED:
        raise ArchiveRejected("encrypted_entry")
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise ArchiveRejected("unsupported_method")
    source.seek(info.header_offset)
    signature, _, flags, method, _, _, crc, packed, size, name_len, extra_len = _ZIP_LOCAL.unpack(
        source.read(_ZIP_LOCAL.size)
    )
    name = source.read(name_len)
    if signature != b"PK\x03\x04" or len(name) != name_len:
        raise ArchiveRejected("corrupt_archive")
    same = (flags, method) == (info.flag_bits, info.compress_type)
    same = same and name.decode("utf-8" if flags & _ZIP_UTF8 else "cp437") == info.orig_filename
    # With a data descriptor or zip64 the local sizes are placeholders; the bytes read are
    # checked against the central record afterwards either way.
    if not flags & _ZIP_DATA_DESCRIPTOR and _ZIP64_SIZE not in (packed, size):
        same = same and (crc, packed, size) == (info.CRC, info.compress_size, info.file_size)
    if not same:
        raise ArchiveRejected("header_mismatch")
    return info.header_offset + _ZIP_LOCAL.size + name_len + extra_len


def _zip_raw(source: BinaryIO, info: zipfile.ZipInfo, offset: int) -> Iterator[bytes]:
    inflater = zlib.decompressobj(-zlib.MAX_WBITS) if info.compress_type else None
    source.seek(offset)
    remaining = info.compress_size
    while remaining:
        packed = source.read(min(_CHUNK, remaining))
        if not packed:
            raise ArchiveRejected("corrupt_archive")
        remaining -= len(packed)
        if inflater is None:
            yield packed
        while inflater is not None and packed:
            # Never feed a finished inflater: it hands the same tail back forever.
            if inflater.eof:
                raise ArchiveRejected("corrupt_archive")
            yield inflater.decompress(packed, _CHUNK)
            packed = inflater.unconsumed_tail
    while inflater is not None and not inflater.eof:  # output still pending, or a cut stream
        if not (data := inflater.decompress(b"", _CHUNK)):
            raise ArchiveRejected("corrupt_archive")
        yield data
    if inflater is not None and inflater.unused_data:
        raise ArchiveRejected("corrupt_archive")


def _zip_chunks(source: BinaryIO, info: zipfile.ZipInfo, offset: int) -> Iterator[bytes]:
    """Inflate at most a chunk at a time, then hold the real bytes against the central record."""
    crc = size = 0
    for data in _zip_raw(source, info, offset):
        crc, size = zlib.crc32(data, crc), size + len(data)
        yield data
    if (crc, size) != (info.CRC, info.file_size):
        raise ArchiveRejected("corrupt_archive")


def _extract_zip(source: BinaryIO, tree: _Tree) -> None:
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            name = info.orig_filename  # `filename` is already cut at a NUL
            offset = _zip_data_offset(source, info)
            kind = stat.S_IFMT(info.external_attr >> 16)
            if kind in _MODE_SKIPS:
                tree.skip(name, _MODE_SKIPS[kind])
            elif name.endswith("/"):
                # By name only, as other unpackers decide, so a directory mode cannot hide a
                # file; and a directory that carries data is not one.
                if info.file_size or any(_zip_chunks(source, info, offset)):
                    raise ArchiveRejected("corrupt_archive")
                tree.add_dir(name)
            else:
                tree.add_file(name, _zip_chunks(source, info, offset))


class _Reader(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


_DECOMPRESSORS: dict[str, Callable[[BinaryIO], _Reader]] = {
    "tar.gz": lambda source: gzip.GzipFile(fileobj=source),
    "tar.bz2": bz2.BZ2File,
    "tar.xz": lzma.LZMAFile,
}


class _Tail:
    """Hands tarfile its bytes, counted against the caps, and remembers the last ones.

    Counting here covers what tarfile reads and drops itself: skipped members, extension headers.
    """

    def __init__(self, raw: _Reader, tree: _Tree) -> None:
        self._raw = raw
        self._tree = tree
        self._pos = 0
        self._tail = b""

    def read(self, size: int = -1) -> bytes:
        data = self._raw.read(size)
        self._pos += len(data)
        if self._pos > self._tree.stream_limit():
            raise ArchiveRejected(self._tree.size_reason)
        self._tail = (self._tail + data)[-_TAIL_BYTES:]
        return data

    def since(self, offset: int) -> bytes:
        start = len(self._tail) - (self._pos - offset)
        return self._tail[start:] if start >= 0 else b""


class _NoSparse(tarfile.TarInfo):
    """An old-GNU sparse map grows in memory while tarfile parses it, before any cap: refuse it."""

    def _proc_sparse(self, tarfile: object) -> "_NoSparse":
        raise ArchiveRejected("unsupported_type")


def _tar_chunks(reader: IO[bytes] | None, size: int) -> Iterator[bytes]:
    while reader is not None and (chunk := reader.read(_CHUNK)):
        size -= len(chunk)
        yield chunk
    if size:
        raise ArchiveRejected("corrupt_archive")


def _extract_tar(source: BinaryIO, kind: str, tree: _Tree) -> None:
    tail = _Tail(_DECOMPRESSORS[kind](source) if kind in _DECOMPRESSORS else source, tree)
    # "r|" is a forward-only stream of an uncompressed tar: tarfile parses headers, nothing more.
    with tarfile.open(fileobj=cast(IO[bytes], tail), mode="r|", tarinfo=_NoSparse) as archive:
        for info in archive:
            if info.isdir():
                tree.add_dir(info.name)
            elif info.isreg():
                tree.add_file(info.name, _tar_chunks(archive.extractfile(info), info.size))
            else:
                tree.skip(info.name, _TAR_SKIPS.get(info.type, "unsupported_type"))
        # tarfile also stops quietly at a damaged header, a cut-off file or the first zero
        # block. Only zeros up to the end of the stream are a real end; anything else would
        # leave a partial tree.
        rest = tail.since(archive.offset)
        if len(rest) < _TAR_BLOCK:
            raise ArchiveRejected("corrupt_archive")
        while rest:
            if rest.strip(b"\0"):
                raise ArchiveRejected("corrupt_archive")
            rest = tail.read(_CHUNK)


def extract_archive(archive: Path, dest: Path, caps: Caps | None = None) -> Manifest:
    """Unpack `archive` into the new directory `dest`, or raise and leave nothing behind."""
    os.mkdir(dest, 0o700)
    try:
        with open(archive, "rb") as source:
            kind = detect_format(source.read(_TAR_BLOCK))
            source.seek(0)
            tree = _Tree(dest, caps or Caps(), os.fstat(source.fileno()).st_size)
            if kind is None:
                raise ArchiveRejected("unknown_format")
            try:
                if kind == "zip":
                    _extract_zip(source, tree)
                else:
                    _extract_tar(source, kind, tree)
            except ArchiveRejected:
                raise
            except Exception as error:  # whatever a parser raises on hostile input
                raise ArchiveRejected("corrupt_archive") from error
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return Manifest(kind, tuple(tree.files), tuple(tree.skipped), tree.total_bytes)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="extract", description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("dest", type=Path, help="directory to create; must not exist")
    parser.add_argument("--manifest", type=Path, help="default: <dest>.manifest.json")
    args = parser.parse_args(argv)
    manifest_path = args.manifest or args.dest.with_name(args.dest.name + ".manifest.json")
    try:
        manifest = extract_archive(args.archive, args.dest)
        try:
            manifest_path.write_text(json.dumps(asdict(manifest)) + "\n", encoding="utf-8")
        except OSError:
            shutil.rmtree(args.dest, ignore_errors=True)
            raise
    except ArchiveRejected as rejected:
        print(json.dumps({"status": "rejected", "reason": rejected.reason}))
        return EXIT_REJECTED
    except OSError:  # unreadable input, existing destination, manifest not writable
        print(json.dumps({"status": "error", "reason": "io_error"}))
        return EXIT_ERROR
    print(json.dumps(manifest.summary() | {"manifest": str(manifest_path)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
