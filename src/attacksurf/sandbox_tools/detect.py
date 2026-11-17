"""Name the format of one untrusted binary, inside the sandbox (epic #68, #101).

    python -m attacksurf.sandbox_tools.detect <file>

By content, never by file name: ELF, PE, Mach-O (thin or universal), APK, IPA. Only fixed-size
headers are read, plus a zip's central directory up to a cap; nothing is decompressed,
decrypted, executed or followed, and no byte of the file is echoed. Exit status: 0 ok, 3
rejected (not a format we analyse, or a header that contradicts itself), 4 the file could not
be read; each prints one small JSON line.
"""

import argparse
import json
import os
import re
import stat
import struct
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, BinaryIO

# A Java class file starts with the universal Mach-O magic; where that keeps its slice count,
# the class file keeps its version (45 or more), so a small cap also tells the two apart.
MAX_FAT_ARCHS = 16
MAX_CD_BYTES = 4 * 1024**2
MAX_CD_ENTRIES = 50_000
# The same scheme as `extract`: not 1 or 2 (a Python traceback, an argparse usage error).
EXIT_REJECTED = 3
EXIT_ERROR = 4
_ELF_HEADER = {32: 52, 64: 64}
_MACHO = {
    b"\xfe\xed\xfa\xce": (32, ">"),
    b"\xce\xfa\xed\xfe": (32, "<"),
    b"\xfe\xed\xfa\xcf": (64, ">"),
    b"\xcf\xfa\xed\xfe": (64, "<"),
}
_MACHO_HEADER = {32: 28, 64: 32}
# Universal headers are big-endian on disk: (cputype, cpusubtype, offset, size, align).
_FAT = {b"\xca\xfe\xba\xbe": struct.Struct(">5L"), b"\xca\xfe\xba\xbf": struct.Struct(">2L2QL4x")}
_PE_OPTIONAL = {0x10B: 32, 0x20B: 64}
_ZIP_END = struct.Struct("<4s4H2LH")
_ZIP_ENTRY = struct.Struct("<4s6H3L5H2L")
_ZIP_MAX_COMMENT = 0xFFFF
_BYTE_ORDER = {"<": "little", ">": "big"}
_APP_DIR = re.compile(rb"Payload/[^/]+\.app/")


class BinaryRejected(Exception):
    """The file is not something we analyse; `reason` is a fixed code, never file content."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _read(source: BinaryIO, offset: int, size: int) -> bytes:
    source.seek(offset)
    data = source.read(size)
    if len(data) != size:
        raise BinaryRejected("truncated")
    return data


def _elf(source: BinaryIO) -> dict[str, Any]:
    ident = _read(source, 0, 16)
    bits, order = {1: 32, 2: 64}.get(ident[4]), {1: "<", 2: ">"}.get(ident[5])
    if bits is None or order is None or ident[6] != 1:
        raise BinaryRejected("bad_header")
    header = _read(source, 0, _ELF_HEADER[bits])
    _, machine = struct.unpack_from(order + "2H", header, 16)
    return {"format": "elf", "bits": bits, "endianness": _BYTE_ORDER[order], "machine": machine}


def _pe(source: BinaryIO, size: int) -> dict[str, Any]:
    (lfanew,) = struct.unpack_from("<L", _read(source, 0, 64), 60)
    coff = struct.Struct("<4sH18xH")  # signature, machine, rest of COFF, optional-header magic
    if lfanew + coff.size > size:
        raise BinaryRejected("bad_header")
    signature, machine, optional = coff.unpack(_read(source, lfanew, coff.size))
    if signature != b"PE\0\0" or optional not in _PE_OPTIONAL:  # e.g. a plain DOS program
        raise BinaryRejected("bad_header")
    return {"format": "pe", "bits": _PE_OPTIONAL[optional], "machine": machine}


def _macho(source: BinaryIO, size: int, bits: int, order: str) -> dict[str, Any]:
    header = _read(source, 0, _MACHO_HEADER[bits])
    cputype, _, _, _, sizeofcmds = struct.unpack_from(order + "5L", header, 4)
    if len(header) + sizeofcmds > size:
        raise BinaryRejected("bad_header")
    return {
        "format": "macho",
        "bits": bits,
        "endianness": _BYTE_ORDER[order],
        "cputype": cputype,
    }


def _fat(source: BinaryIO, size: int, arch: struct.Struct) -> dict[str, Any]:
    (count,) = struct.unpack(">L", _read(source, 4, 4))
    if not 1 <= count <= MAX_FAT_ARCHS:
        raise BinaryRejected("unknown_format")
    table = _read(source, 8, count * arch.size)
    cputypes: list[int] = []
    for index in range(count):
        cputype, _, offset, length, _ = arch.unpack_from(table, index * arch.size)
        if not length or offset < 8 + len(table) or offset + length > size:
            raise BinaryRejected("bad_header")
        cputypes.append(cputype)
    return {"format": "macho_fat", "slices": count, "cputypes": cputypes}


def _zip_end(tail: bytes) -> int:
    """Where the end record starts: the last one whose comment runs exactly to the end of the
    file, so its signature inside a comment (or inside its own fields) is not taken for it."""
    end = len(tail) - _ZIP_END.size + 1
    while end > 0:
        end = tail.rfind(b"PK\x05\x06", 0, end + 3)
        if end >= 0 and end + _ZIP_END.size + _ZIP_END.unpack_from(tail, end)[7] == len(tail):
            return end
    raise BinaryRejected("no_zip_end")


def _zip(source: BinaryIO, size: int) -> dict[str, Any]:
    """APK or IPA by the names in the central directory; entry data is never touched."""
    tail_start = max(0, size - _ZIP_END.size - _ZIP_MAX_COMMENT)
    tail = _read(source, tail_start, size - tail_start)
    end = _zip_end(tail)
    _, disk, cd_disk, _, total, cd_size, cd_offset, _ = _ZIP_END.unpack_from(tail, end)
    # Also refuses a zip64 end record (0xFFFFFFFF placeholders): no upload under the cap needs it.
    if disk or cd_disk or cd_offset + cd_size > tail_start + end:
        raise BinaryRejected("bad_header")
    # Never judged on part of its directory: a name cut at the cap could pass for another one.
    if cd_size > MAX_CD_BYTES or total > MAX_CD_ENTRIES:
        raise BinaryRejected("zip_too_large")
    directory = _read(source, cd_offset, cd_size)
    seen = position = 0
    apk = ipa = False
    while seen < total and position + _ZIP_ENTRY.size <= len(directory):
        fields = _ZIP_ENTRY.unpack_from(directory, position)
        name_at = position + _ZIP_ENTRY.size
        position = name_at + sum(fields[10:13])  # name, extra field, comment
        if fields[0] != b"PK\x01\x02" or position > len(directory):
            raise BinaryRejected("bad_header")
        name = directory[name_at : name_at + fields[10]]
        apk = apk or name == b"AndroidManifest.xml"
        ipa = ipa or _APP_DIR.match(name) is not None
        seen += 1
    if seen != total or position != cd_size:  # the end record and its directory disagree
        raise BinaryRejected("bad_header")
    if apk and ipa:  # one analyzer is chosen by this answer: a polyglot gets none
        raise BinaryRejected("ambiguous_zip")
    if not (apk or ipa):
        raise BinaryRejected("not_apk_or_ipa")
    return {"format": "apk" if apk else "ipa", "entries": seen}


def _open_no_follow(path: str, flags: int) -> int:
    # Never through a symlink, and never blocking on a FIFO put in the file's place.
    return os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK)


def detect_binary(path: Path) -> dict[str, Any]:
    """The format of `path` and a few header facts (numbers and fixed words only).

    Raises `BinaryRejected`, or `OSError` if `path` can't be read or isn't a regular file.
    """
    with open(path, "rb", opener=_open_no_follow) as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file")
        magic = source.read(4)
        if magic == b"\x7fELF":
            return _elf(source)
        if magic.startswith(b"MZ"):
            return _pe(source, info.st_size)
        if magic in _MACHO:
            return _macho(source, info.st_size, *_MACHO[magic])
        if magic in _FAT:
            return _fat(source, info.st_size, _FAT[magic])
        if magic == b"PK\x03\x04":
            return _zip(source, info.st_size)
    raise BinaryRejected("unknown_format")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="detect", description=__doc__)
    parser.add_argument("file", type=Path)
    args = parser.parse_args(argv)
    try:
        facts = detect_binary(args.file)
    except BinaryRejected as rejected:
        print(json.dumps({"status": "rejected", "reason": rejected.reason}))
        return EXIT_REJECTED
    except OSError:
        print(json.dumps({"status": "error", "reason": "io_error"}))
        return EXIT_ERROR
    print(json.dumps({"status": "ok"} | facts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
