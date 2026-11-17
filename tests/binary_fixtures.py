"""Builds the binary corpus in `tests/fixtures/binaries/` (#101).

Regenerate with `uv run python -m tests.binary_fixtures`. Every file is a few header bytes
written by hand: enough for format detection, never a program that could run. `DETECTED` and
`REJECTED` say what the sandbox detector must make of each one.
"""

import struct
import zipfile
from pathlib import Path

from tests.archive_fixtures import make_zip

CORPUS_DIR = Path(__file__).parent / "fixtures" / "binaries"
MAX_FIXTURE_BYTES = 20 * 1024


def elf(bits: int, order: str) -> bytes:
    """An ELF header and nothing else: e_type ET_EXEC, e_machine x86-64 (62) or 386 (3)."""
    ident = b"\x7fELF" + bytes([bits // 32, 1 if order == "<" else 2, 1]) + bytes(9)
    rest = struct.pack(order + "HHL", 2, 62 if bits == 64 else 3, 1)
    return (ident + rest).ljust(64 if bits == 64 else 52, b"\0")


def pe(optional_magic: int = 0x20B, lfanew: int = 0x80) -> bytes:
    dos = b"MZ".ljust(60, b"\0") + struct.pack("<L", lfanew)
    coff = struct.pack("<4sH18xH", b"PE\0\0", 0x8664, optional_magic)
    return dos.ljust(0x80, b"\0") + coff.ljust(64, b"\0")


def macho(bits: int = 64, order: str = "<", sizeofcmds: int = 0) -> bytes:
    magic = 0xFEEDFACF if bits == 64 else 0xFEEDFACE
    cputype = 0x0100000C if bits == 64 else 7  # arm64 / i386
    header = struct.pack(order + "7L", magic, cputype, 0, 2, 0, sizeofcmds, 0)
    return header + (bytes(4) if bits == 64 else b"")


def fat(slices: list[bytes], *, size_lie: int = 0) -> bytes:
    """A universal binary: big-endian table, then the slices one after the other."""
    offset = 8 + 20 * len(slices)
    table = b""
    for data in slices:
        table += struct.pack(">5L", 0x0100000C, 0, offset, len(data) + size_lie, 0)
        offset += len(data)
    return struct.pack(">2L", 0xCAFEBABE, len(slices)) + table + b"".join(slices)


def stored_zip(*names: str) -> bytes:
    return make_zip([(name, b"") for name in names], zipfile.ZIP_STORED)


APK = stored_zip("AndroidManifest.xml", "classes.dex", "res/")
IPA = stored_zip("Payload/", "Payload/Demo.app/", "Payload/Demo.app/Info.plist")
# Java 8 class file: the same magic as a universal Mach-O, then minor 0 and major 52.
JAVA_CLASS = struct.pack(">LHH", 0xCAFEBABE, 0, 52) + bytes(16)

# name -> (bytes, the format the detector must report)
DETECTED: dict[str, tuple[bytes, str]] = {
    "elf32-le": (elf(32, "<"), "elf"),
    "elf32-be": (elf(32, ">"), "elf"),
    "elf64-le": (elf(64, "<"), "elf"),
    "elf64-be": (elf(64, ">"), "elf"),
    "pe32.exe": (pe(0x10B), "pe"),
    "pe64.exe": (pe(), "pe"),
    "macho64": (macho(), "macho"),
    "macho32-be": (macho(32, ">"), "macho"),
    "macho-fat": (fat([macho(), macho()]), "macho_fat"),
    "app.apk": (APK, "apk"),
    "app.ipa": (IPA, "ipa"),
}
# name -> (bytes, the reason code the detector must reject it with)
REJECTED: dict[str, tuple[bytes, str]] = {
    "java.class": (JAVA_CLASS, "unknown_format"),
    "plain.zip": (stored_zip("README.md", "lib/AndroidManifest.xml"), "not_apk_or_ipa"),
    "text.txt": (b"Just some notes, not a program.\n", "unknown_format"),
    "empty.bin": (b"", "unknown_format"),
    "elf-truncated": (elf(64, "<")[:20], "truncated"),
    "elf-bad-class": (b"\x7fELF\x07\x01\x01".ljust(64, b"\0"), "bad_header"),
    "pe-truncated": (pe()[:32], "truncated"),
    "pe-bad-lfanew": (pe(lfanew=0x4000), "bad_header"),
    "pe-no-signature": (pe().replace(b"PE\0\0", b"NE\0\0"), "bad_header"),
    "macho-truncated": (macho()[:12], "truncated"),
    "macho-bad-commands": (macho(sizeofcmds=4096), "bad_header"),
    "fat-truncated": (fat([macho(), macho()])[:20], "truncated"),
    "fat-out-of-bounds": (fat([macho()], size_lie=64), "bad_header"),
    "zip-truncated": (APK[:40], "no_zip_end"),
}
CORPUS: dict[str, bytes] = {name: data for name, (data, _) in (DETECTED | REJECTED).items()}

if __name__ == "__main__":
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    for name, data in CORPUS.items():
        (CORPUS_DIR / name).write_bytes(data)
