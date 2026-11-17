"""The sandbox binary detector (#101) against the corpus in `tests/fixtures/binaries/`."""

import json
import os
import struct
import subprocess
import sys
import zipfile
from collections.abc import Callable
from io import BytesIO
from pathlib import Path

import pytest

from attacksurf.sandbox_tools import detect as detector
from attacksurf.sandbox_tools.detect import BinaryRejected, detect_binary
from tests.archive_fixtures import make_zip
from tests.binary_fixtures import (
    APK,
    CORPUS,
    CORPUS_DIR,
    DETECTED,
    MAX_FIXTURE_BYTES,
    REJECTED,
    fat,
)

SRC = Path(detector.__file__).parents[2]


def staged(tmp_path: Path, data: bytes) -> Path:
    artifact = tmp_path / "artifact"  # no extension: the name must never matter
    artifact.write_bytes(data)
    return artifact


def test_committed_corpus_is_exactly_what_the_generator_builds() -> None:
    committed = {path.name: path.read_bytes() for path in CORPUS_DIR.iterdir()}

    assert committed == CORPUS
    assert max(map(len, committed.values())) < MAX_FIXTURE_BYTES


@pytest.mark.parametrize("name", sorted(DETECTED))
def test_detect_names_the_format_of_every_supported_fixture(tmp_path: Path, name: str) -> None:
    facts = detect_binary(staged(tmp_path, (CORPUS_DIR / name).read_bytes()))

    assert facts["format"] == DETECTED[name][1]


@pytest.mark.parametrize(
    ("name", "facts"),
    [
        ("elf32-be", {"format": "elf", "bits": 32, "endianness": "big", "machine": 3}),
        ("elf64-le", {"format": "elf", "bits": 64, "endianness": "little", "machine": 62}),
        ("pe32.exe", {"format": "pe", "bits": 32, "machine": 0x8664}),
        ("pe64.exe", {"format": "pe", "bits": 64, "machine": 0x8664}),
        ("macho64", {"format": "macho", "bits": 64, "endianness": "little", "cputype": 0x100000C}),
        ("macho32-be", {"format": "macho", "bits": 32, "endianness": "big", "cputype": 7}),
        ("macho-fat", {"format": "macho_fat", "slices": 2, "cputypes": [0x100000C] * 2}),
        ("app.apk", {"format": "apk", "entries": 3}),
        ("app.ipa", {"format": "ipa", "entries": 3}),
    ],
)
def test_detect_reports_minimal_header_facts(
    tmp_path: Path, name: str, facts: dict[str, object]
) -> None:
    assert detect_binary(staged(tmp_path, (CORPUS_DIR / name).read_bytes())) == facts


@pytest.mark.parametrize("name", sorted(REJECTED))
def test_detect_rejects_everything_else_with_a_fixed_reason(tmp_path: Path, name: str) -> None:
    with pytest.raises(BinaryRejected) as raised:
        detect_binary(staged(tmp_path, (CORPUS_DIR / name).read_bytes()))

    assert raised.value.reason == REJECTED[name][1]


def test_java_class_file_is_not_a_universal_mach_o(tmp_path: Path) -> None:
    java = staged(tmp_path, CORPUS["java.class"])

    with pytest.raises(BinaryRejected):
        detect_binary(java)
    # Every real class-file version word is above the slice cap.
    assert detector.MAX_FAT_ARCHS < 45


def test_fat_slice_that_overlaps_the_table_is_rejected(tmp_path: Path) -> None:
    data = bytearray(fat([b"\0" * 8]))
    data[16:20] = struct.pack(">L", 4)  # the slice claims to start inside the header

    with pytest.raises(BinaryRejected) as raised:
        detect_binary(staged(tmp_path, bytes(data)))

    assert raised.value.reason == "bad_header"


def test_fat64_table_is_read_with_its_wider_entries(tmp_path: Path) -> None:
    table = struct.pack(">2L2QL4x", 0x0100000C, 0, 40, 8, 0)
    data = struct.pack(">2L", 0xCAFEBABF, 1) + table + bytes(8)

    assert detect_binary(staged(tmp_path, data))["format"] == "macho_fat"


def test_apk_manifest_must_be_at_the_top_level_and_ipa_needs_an_app_directory(
    tmp_path: Path,
) -> None:
    nested = make_zip([("lib/AndroidManifest.xml", b""), ("Payload/readme.txt", b"")])

    with pytest.raises(BinaryRejected) as raised:
        detect_binary(staged(tmp_path, nested))

    assert raised.value.reason == "not_apk_or_ipa"


def test_zip_entry_data_is_never_decompressed(tmp_path: Path) -> None:
    """A manifest whose compressed data is garbage still names an APK: only names are read."""
    apk = bytearray(make_zip([("AndroidManifest.xml", b"<manifest/>" * 50)]))
    start = apk.index(b"AndroidManifest.xml") + len(b"AndroidManifest.xml")
    apk[start : start + 8] = b"\xff" * 8

    assert detect_binary(staged(tmp_path, bytes(apk)))["format"] == "apk"


def test_zip_central_directory_is_examined_only_up_to_the_caps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    late = make_zip([(f"pad{i}", b"") for i in range(5)] + [("AndroidManifest.xml", b"")])
    artifact = staged(tmp_path, late)
    assert detect_binary(artifact)["format"] == "apk"

    monkeypatch.setattr(detector, "MAX_CD_ENTRIES", 5)
    with pytest.raises(BinaryRejected) as by_count:
        detect_binary(artifact)
    monkeypatch.setattr(detector, "MAX_CD_ENTRIES", 50_000)
    monkeypatch.setattr(detector, "MAX_CD_BYTES", 100)
    with pytest.raises(BinaryRejected) as by_size:
        detect_binary(artifact)

    assert (by_count.value.reason, by_size.value.reason) == ("zip_too_large", "zip_too_large")


def _end_record(data: bytes, *, total: int | None = None, cd_size: int | None = None) -> bytes:
    """`data` (a zip without a comment) with fields of its end record overwritten."""
    end = bytearray(data[-22:])
    if total is not None:
        end[8:12] = struct.pack("<2H", total, total)
    if cd_size is not None:
        end[12:16] = struct.pack("<L", cd_size)
    return data[:-22] + bytes(end)


@pytest.mark.parametrize("first", ["README.md", "AndroidManifest.xml", "Payload/A.app/x"])
@pytest.mark.parametrize(
    "edit",
    [
        lambda z: z.replace(b"PK\x01\x02", b"PK\x09\x09"),  # no directory entry
        lambda z: _end_record(z, cd_size=0xFFFFFFFF),  # directory size lies
        lambda z: _end_record(z, total=9),  # entry count lies
        lambda z: _end_record(z, total=1),  # more entries than promised are left unread
        lambda z: _end_record(z, cd_size=46 + len("AndroidManifest.xml")),  # a name is cut
        lambda z: z[:-18] + b"\x01\x00" + z[-16:],  # multi-disk
    ],
)
def test_zip_with_an_inconsistent_directory_is_rejected_even_if_it_names_an_app(
    tmp_path: Path, edit: Callable[[bytes], bytes], first: str
) -> None:
    broken = edit(make_zip([(first, b""), ("zz/pad.txt", b"")]))

    with pytest.raises(BinaryRejected) as raised:
        detect_binary(staged(tmp_path, broken))

    assert raised.value.reason == "bad_header"


@pytest.mark.parametrize("name", ["AndroidManifest.xml.bak", "AndroidManifest.xml_not/real.txt"])
def test_entry_name_cut_short_by_a_lying_directory_size_is_not_an_apk(
    tmp_path: Path, name: str
) -> None:
    """Regression: the cut name compared equal to `AndroidManifest.xml` and exit was 0."""
    honest = make_zip([(name, b"")])
    lying = _end_record(honest, cd_size=46 + len("AndroidManifest.xml"))

    reasons = []
    for data in (honest, lying):
        with pytest.raises(BinaryRejected) as raised:
            detect_binary(staged(tmp_path, data))
        reasons.append(raised.value.reason)

    assert reasons == ["not_apk_or_ipa", "bad_header"]


def test_entry_name_straddling_the_directory_cap_is_not_an_apk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: an honest zip whose last name was cut at the cap was reported as an APK."""
    data = make_zip([("pad", b""), ("AndroidManifest.xml.not", b"")])
    cut = data.index(b"PK\x01\x02", data.index(b"PK\x01\x02") + 1) - data.index(b"PK\x01\x02")
    monkeypatch.setattr(detector, "MAX_CD_BYTES", cut + 46 + len("AndroidManifest.xml"))

    with pytest.raises(BinaryRejected) as raised:
        detect_binary(staged(tmp_path, data))

    assert raised.value.reason == "zip_too_large"


def test_app_found_before_a_cap_is_still_refused_rather_than_judged_on_part_of_the_zip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    early = staged(tmp_path, make_zip([("AndroidManifest.xml", b""), ("a", b""), ("b", b"")]))
    monkeypatch.setattr(detector, "MAX_CD_ENTRIES", 2)

    with pytest.raises(BinaryRejected) as raised:
        detect_binary(early)

    assert raised.value.reason == "zip_too_large"


@pytest.mark.parametrize(
    "names",
    [
        ["AndroidManifest.xml", "Payload/A.app/Info.plist"],
        ["Payload/A.app/x", "AndroidManifest.xml"],
    ],
)
def test_zip_that_is_both_an_apk_and_an_ipa_is_rejected_as_ambiguous(
    tmp_path: Path, names: list[str]
) -> None:
    polyglot = make_zip([(name, b"") for name in names])

    with pytest.raises(BinaryRejected) as raised:
        detect_binary(staged(tmp_path, polyglot))

    assert raised.value.reason == "ambiguous_zip"


def _commented_apk(comment: bytes) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"")
        archive.comment = comment
    return buffer.getvalue()


@pytest.mark.parametrize(
    "comment",
    [b"released by ci", b"hello PK\x05\x06", b"xx PK\x05\x06 yy", b"PK\x05\x06" * 2000 + b"!"],
)
def test_end_record_signature_inside_the_zip_comment_does_not_hide_an_apk(
    tmp_path: Path, comment: bytes
) -> None:
    """Regression: a bare `rfind` took the comment's bytes for the record ("truncated")."""
    facts = detect_binary(staged(tmp_path, _commented_apk(comment)))

    assert facts == {"format": "apk", "entries": 1}


def test_end_record_signature_inside_its_own_fields_is_not_taken_for_a_record(
    tmp_path: Path,
) -> None:
    apk = _commented_apk(b"c" * 30)
    looks_like_a_record = apk[:-36] + b"PK\x05\x06" + apk[-32:]  # the directory offset field

    with pytest.raises(BinaryRejected) as raised:
        detect_binary(staged(tmp_path, looks_like_a_record))

    assert raised.value.reason == "bad_header"  # found the real record; its offset is nonsense


@pytest.mark.parametrize("data", [APK[:40], APK[:10], APK + bytes(70_000), APK + b"trailing"])
def test_zip_without_an_end_record_at_its_end_is_rejected(tmp_path: Path, data: bytes) -> None:
    with pytest.raises(BinaryRejected) as raised:
        detect_binary(staged(tmp_path, data))

    assert raised.value.reason == "no_zip_end"


def test_detect_refuses_a_symlink_and_anything_that_is_not_a_regular_file(tmp_path: Path) -> None:
    target = staged(tmp_path, CORPUS["elf64-le"])
    link = tmp_path / "link"
    link.symlink_to(target)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)

    for path in (link, fifo, tmp_path):
        with pytest.raises(OSError):  # noqa: PT011
            detect_binary(path)


def run_cli(*argv: str) -> subprocess.CompletedProcess[str]:
    # -I -S: no site-packages and no environment, like an analyzer image with only this package.
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "from attacksurf.sandbox_tools import detect; "
        "status = detect.main(sys.argv[2:]); "
        "sys.exit(99 if {'flask', 'pydantic', 'attacksurf.domain'} & set(sys.modules) else status)"
    )
    command = [sys.executable, "-I", "-S", "-c", code, str(SRC), *argv]
    return subprocess.run(command, check=False, capture_output=True, text=True)  # noqa: S603


def test_cli_prints_one_json_object_using_only_the_stdlib(tmp_path: Path) -> None:
    result = run_cli(str(staged(tmp_path, CORPUS["elf64-le"])))

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "status": "ok",
        "format": "elf",
        "bits": 64,
        "endianness": "little",
        "machine": 62,
    }
    assert len(result.stdout.splitlines()) == 1


def test_cli_exit_status_tells_a_rejection_from_its_own_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rejected = detector.main([str(staged(tmp_path, CORPUS["text.txt"]))])
    missing = detector.main([str(tmp_path / "nowhere")])

    assert (rejected, missing) == (detector.EXIT_REJECTED, detector.EXIT_ERROR)
    assert [json.loads(line) for line in capsys.readouterr().out.splitlines()] == [
        {"status": "rejected", "reason": "unknown_format"},
        {"status": "error", "reason": "io_error"},
    ]


def test_cli_output_stays_small_for_the_widest_supported_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    widest = fat([bytes(4)] * detector.MAX_FAT_ARCHS)

    assert detector.main([str(staged(tmp_path, widest))]) == 0
    assert len(capsys.readouterr().out) < 1024
