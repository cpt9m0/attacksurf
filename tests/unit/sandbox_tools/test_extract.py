"""The sandbox archive extractor (ADR 0017, #86).

Every extraction goes through `extract`, which also proves that nothing was written outside the
destination, that no link exists inside it and that modes are 0600/0700.
"""

import ast
import hashlib
import io
import json
import os
import stat
import struct
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from attacksurf.sandbox_tools import extract as extractor
from attacksurf.sandbox_tools.extract import ArchiveRejected, Caps, Manifest, extract_archive
from tests.archive_fixtures import (
    APP,
    BUILDERS,
    CORPUS_DIR,
    README,
    UNCOMPRESSED,
    gzipped,
    make_tar,
    make_zip,
    member,
    patched,
)

SRC = Path(extractor.__file__).parents[2]
MAX_FIXTURE_BYTES = 20 * 1024
Builder = Callable[[list[tuple[str, bytes]]], bytes]


def stage(tmp_path: Path, archive: str | bytes) -> tuple[Path, Path]:
    """Lay out `/input/artifact` and an empty scratch directory; `archive` is a corpus name."""
    data = (CORPUS_DIR / archive).read_bytes() if isinstance(archive, str) else archive
    (tmp_path / "input").mkdir()
    (tmp_path / "jail" / "scratch").mkdir(parents=True)
    artifact = tmp_path / "input" / "artifact"
    artifact.write_bytes(data)
    return artifact, tmp_path / "jail" / "scratch" / "out"


def outside(tmp_path: Path, dest: Path) -> set[Path]:
    return {path for path in tmp_path.rglob("*") if dest not in (path, *path.parents)}


def assert_contained(tmp_path: Path, dest: Path, before: set[Path]) -> None:
    assert outside(tmp_path, dest) == before
    for path in [dest, *dest.rglob("*")]:
        mode = path.lstat().st_mode
        assert stat.S_ISDIR(mode) or stat.S_ISREG(mode), path
        assert stat.S_IMODE(mode) == (0o700 if stat.S_ISDIR(mode) else 0o600), path


def extract(tmp_path: Path, archive: str | bytes, caps: Caps | None = None) -> Manifest:
    artifact, dest = stage(tmp_path, archive)
    before = outside(tmp_path, dest)

    manifest = extract_archive(artifact, dest, caps)

    assert_contained(tmp_path, dest, before)
    on_disk = {str(p.relative_to(dest)) for p in dest.rglob("*") if p.is_file()}
    assert on_disk == {entry.path for entry in manifest.files}
    return manifest


def rejection(tmp_path: Path, archive: str | bytes, caps: Caps | None = None) -> str:
    artifact, dest = stage(tmp_path, archive)
    before = outside(tmp_path, dest)

    with pytest.raises(ArchiveRejected) as raised:
        extract_archive(artifact, dest, caps)

    assert not dest.exists()
    assert outside(tmp_path, dest) == before
    return raised.value.reason


def test_committed_corpus_matches_the_generator() -> None:
    committed = {path.name: path.stat().st_size for path in CORPUS_DIR.iterdir()}

    assert set(committed) == set(BUILDERS)
    assert max(committed.values()) < MAX_FIXTURE_BYTES


@pytest.mark.parametrize("name", sorted(UNCOMPRESSED))
def test_committed_fixture_has_the_bytes_its_builder_makes(name: str) -> None:
    assert (CORPUS_DIR / name).read_bytes() == BUILDERS[name]()


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("ok.zip", "zip"),
        ("ok-stored.zip", "zip"),
        ("ok.tar", "tar"),
        ("ok.tar.gz", "tar.gz"),
        ("ok.tar.bz2", "tar.bz2"),
        ("ok.tar.xz", "tar.xz"),
    ],
)
def test_extract_unpacks_a_well_formed_archive(tmp_path: Path, name: str, kind: str) -> None:
    manifest = extract(tmp_path, name)

    dest = tmp_path / "jail" / "scratch" / "out"
    assert manifest.format == kind
    assert {entry.path: (entry.size, entry.sha256) for entry in manifest.files} == {
        "README.md": (len(README), hashlib.sha256(README).hexdigest()),
        "src/app.py": (len(APP), hashlib.sha256(APP).hexdigest()),
    }
    assert manifest.skipped == ()
    assert manifest.total_bytes == len(README) + len(APP)
    assert (dest / "src" / "app.py").read_bytes() == APP


def test_extract_accepts_dot_prefixed_tar_names(tmp_path: Path) -> None:
    assert [entry.path for entry in extract(tmp_path, "dot-prefixed.tar").files] == ["a.txt"]


def test_extract_reads_zip_entries_written_with_data_descriptors(tmp_path: Path) -> None:
    class Unseekable(io.BytesIO):
        def tell(self) -> int:
            raise OSError("a pipe")

    buffer = Unseekable()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", b"streamed\n" * 50)
    assert zipfile.ZipFile(io.BytesIO(buffer.getvalue())).getinfo("a.txt").flag_bits & 0x08

    manifest = extract(tmp_path, buffer.getvalue())

    assert [(entry.path, entry.size) for entry in manifest.files] == [("a.txt", 450)]


def test_extract_keeps_a_nested_archive_as_a_file(tmp_path: Path) -> None:
    manifest = extract(tmp_path, "nested.zip")

    dest = tmp_path / "jail" / "scratch" / "out"
    assert [entry.path for entry in manifest.files] == ["inner.zip", "inner.tar"]
    assert zipfile.is_zipfile(dest / "inner.zip")
    assert sorted(path.name for path in dest.iterdir()) == ["inner.tar", "inner.zip"]


@pytest.mark.parametrize(
    ("name", "skipped"),
    [
        ("zip-symlink.zip", [("link", "symlink")]),
        ("zip-fifo.zip", [("pipe", "fifo")]),
        ("tar-symlink.tar", [("escape", "symlink"), ("passwd", "symlink")]),
        ("tar-hardlink.tar", [("hard", "hardlink")]),
        ("tar-device.tar", [("dev/null", "device"), ("dev/sda", "device")]),
        ("tar-fifo.tar", [("pipe", "fifo")]),
    ],
)
def test_extract_skips_links_and_special_files_with_a_reason(
    tmp_path: Path, name: str, skipped: list[tuple[str, str]]
) -> None:
    manifest = extract(tmp_path, name)

    assert [(entry.path, entry.reason) for entry in manifest.skipped] == skipped
    assert [entry.path for entry in manifest.files] == ["ok.txt"]


def test_extract_keeps_a_zip_file_whose_mode_claims_to_be_a_directory(tmp_path: Path) -> None:
    # Other unpackers write `evil.py` as a file; calling it a directory would hide it.
    manifest = extract(tmp_path, "zip-dir-mode-file.zip")

    assert [(entry.path, entry.size) for entry in manifest.files] == [
        ("evil.py", 10),
        ("ok.txt", 3),
    ]


@pytest.mark.parametrize("name", ["zip-setuid.zip", "tar-setuid.tar"])
def test_extract_strips_setuid_setgid_and_sticky_bits(tmp_path: Path, name: str) -> None:
    manifest = extract(tmp_path, name)  # `extract` checks every mode is exactly 0600/0700

    assert [entry.path.rsplit("/", 1)[-1] for entry in manifest.files] == ["su"]


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("zip-slip.zip", "unsafe_path"),
        ("zip-absolute.zip", "unsafe_path"),
        ("zip-backslash.zip", "invalid_name"),
        ("zip-nul-name.zip", "invalid_name"),
        ("zip-duplicate.zip", "duplicate_path"),
        ("zip-file-as-dir.zip", "duplicate_path"),
        ("zip-header-mismatch.zip", "header_mismatch"),
        ("zip-size-mismatch.zip", "header_mismatch"),
        ("zip-bad-crc.zip", "corrupt_archive"),
        ("zip-encrypted.zip", "encrypted_entry"),
        ("zip-lzma-method.zip", "unsupported_method"),
        ("zip-method-mismatch.zip", "header_mismatch"),
        ("zip-flags-mismatch.zip", "header_mismatch"),
        ("zip-bad-local-signature.zip", "corrupt_archive"),
        ("zip-data-past-eof.zip", "corrupt_archive"),
        ("zip-deflate-junk.zip", "corrupt_archive"),
        ("zip-deflate-ends-early.zip", "corrupt_archive"),
        ("zip-dir-with-data.zip", "corrupt_archive"),
        ("zip-long-name.zip", "invalid_name"),
        ("zip-truncated.zip", "corrupt_archive"),
        ("zip-truncated-data.zip", "corrupt_archive"),
        ("zip-bomb.zip", "ratio_cap"),
        ("zip-depth.zip", "depth_cap"),
        ("tar-slip.tar", "unsafe_path"),
        ("tar-absolute.tar", "unsafe_path"),
        ("tar-invalid-name.tar", "invalid_name"),
        ("tar-duplicate.tar", "duplicate_path"),
        ("tar-symlink-write-through.tar", "duplicate_path"),
        ("tar-depth.tar", "depth_cap"),
        ("tar-empty-name.tar", "invalid_name"),
        ("tar-sparse.tar", "unsupported_type"),
        ("tar-data-after-end.tar", "corrupt_archive"),
        ("tar-skipped-bomb.tar.gz", "ratio_cap"),
        ("tar-bad-header.tar", "corrupt_archive"),
        ("tar-truncated.tar", "corrupt_archive"),
        ("tar-no-end-marker.tar", "corrupt_archive"),
        ("tar-truncated.tar.gz", "corrupt_archive"),
        ("tar-bomb.tar.gz", "ratio_cap"),
        ("not-a-tar.gz", "corrupt_archive"),
        ("unknown.bin", "unknown_format"),
    ],
)
def test_extract_rejects_the_whole_artifact(tmp_path: Path, name: str, reason: str) -> None:
    assert rejection(tmp_path, name) == reason


def test_every_corpus_file_has_an_expected_outcome() -> None:
    covered: set[str] = set()
    for function in (
        test_extract_unpacks_a_well_formed_archive,
        test_extract_skips_links_and_special_files_with_a_reason,
        test_extract_strips_setuid_setgid_and_sticky_bits,
        test_extract_rejects_the_whole_artifact,
    ):
        for mark in function.pytestmark:  # pyright: ignore[reportFunctionMemberAccess]
            covered.update(case if isinstance(case, str) else case[0] for case in mark.args[1])

    others = {"nested.zip", "dot-prefixed.tar", "zip-dir-mode-file.zip"}
    assert covered | others == set(BUILDERS)


def test_extract_detects_the_format_from_magic_bytes_not_the_name(tmp_path: Path) -> None:
    artifact, dest = stage(tmp_path, "ok.zip")
    disguised = artifact.rename(artifact.with_name("artifact.tar.gz"))

    assert extract_archive(disguised, dest).format == "zip"


def many_files(count: int) -> list[tuple[str, bytes]]:
    return [(f"f{index}.txt", b"x") for index in range(count)]


@pytest.mark.parametrize(
    ("archive", "caps", "reason"),
    [
        (make_zip(many_files(3)), Caps(entries=2), "entry_count_cap"),
        (make_tar(member(*file) for file in many_files(3)), Caps(entries=2), "entry_count_cap"),
        # Directories and skipped entries count too, and so does every parent created on the way.
        (
            make_tar(member(f"d{i}", kind=tarfile.DIRTYPE) for i in range(3)),
            Caps(entries=2),
            "entry_count_cap",
        ),
        (
            make_tar(member(f"l{i}", kind=tarfile.SYMTYPE, link="/etc") for i in range(3)),
            Caps(entries=2),
            "entry_count_cap",
        ),
        (make_zip([("a/b/c/d.txt", b"x")]), Caps(entries=3), "entry_count_cap"),
        (make_tar([member("a/b/c/d.txt", b"x")]), Caps(entries=3), "entry_count_cap"),
        # Bytes tarfile reads and drops itself (a member of unknown type) are counted as well.
        (
            make_tar([member("zz", bytes(100_000), kind=b"Z")]),
            Caps(total_bytes=1000, entries=5),
            "total_size_cap",
        ),
        (make_zip([("a.bin", b"x" * 1001)]), Caps(file_bytes=1000), "file_size_cap"),
        (make_tar([member("a.bin", b"x" * 1001)]), Caps(file_bytes=1000), "file_size_cap"),
        (make_zip(many_files(11)), Caps(total_bytes=10), "total_size_cap"),
        (
            make_tar(member(*file) for file in many_files(11)),
            Caps(total_bytes=10),
            "total_size_cap",
        ),
        (make_zip([("a/b/c.txt", b"x")]), Caps(depth=2), "depth_cap"),
        (make_zip([("zeros", bytes(60_000))]), Caps(ratio=100), "ratio_cap"),
    ],
)
def test_extract_rejects_an_archive_over_a_cap(
    tmp_path: Path, archive: bytes, caps: Caps, reason: str
) -> None:
    assert rejection(tmp_path, archive, caps) == reason


@pytest.mark.parametrize(
    ("archive", "caps"),
    [
        (make_zip(many_files(2)), Caps(entries=2, total_bytes=2, file_bytes=1)),
        (make_zip([("a/b.txt", b"x")]), Caps(depth=2)),
        (make_zip([("a/", b""), ("a/b/", b""), ("a/b/c.txt", b"x")]), Caps(entries=3)),
        (make_tar([member("a/b/c.txt", b"x"), member("a/b/d.txt", b"y")]), Caps(entries=4)),
    ],
)
def test_extract_allows_an_archive_exactly_at_the_caps(
    tmp_path: Path, archive: bytes, caps: Caps
) -> None:
    assert extract(tmp_path, archive, caps).files


def test_caps_default_to_the_adr_values() -> None:
    assert Caps() == Caps(
        total_bytes=512 * 1024**2, file_bytes=64 * 1024**2, entries=100_000, depth=32, ratio=200
    )


def test_extract_counts_written_bytes_not_declared_sizes(tmp_path: Path) -> None:
    # Both zip headers claim 10 bytes; the deflate stream really holds 100,000.
    real, declared = 100_000, 10
    honest = make_zip([("a.bin", bytes(real))])
    packed = zipfile.ZipFile(io.BytesIO(honest)).getinfo("a.bin").compress_size
    lying = patched(honest, struct.pack("<II", packed, real), struct.pack("<II", packed, declared))

    reason = rejection(tmp_path, lying, Caps(file_bytes=1000, ratio=10**6))

    assert reason == "file_size_cap"


@pytest.mark.parametrize("build", [make_zip, lambda files: make_tar(member(*f) for f in files)])
def test_extract_copies_a_file_larger_than_one_chunk(tmp_path: Path, build: Builder) -> None:
    data = b"".join(hashlib.sha256(bytes([i])).digest() for i in range(256)) * 40

    manifest = extract(tmp_path, build([("big.bin", data)]))

    assert manifest.files[0].sha256 == hashlib.sha256(data).hexdigest()
    assert manifest.total_bytes == len(data) > 4 * 64 * 1024


def test_extract_inflates_output_that_outlasts_its_input(tmp_path: Path) -> None:
    # 300,000 zeros deflate to a few hundred bytes: most chunks come after the input is used up.
    manifest = extract(tmp_path, make_zip([("zeros.bin", bytes(300_000))]), Caps(ratio=10**6))

    assert manifest.files[0].sha256 == hashlib.sha256(bytes(300_000)).hexdigest()


def test_extract_rejects_a_tar_hidden_behind_a_leading_zero_block(tmp_path: Path) -> None:
    hidden = gzipped(bytes(512) + make_tar([member("hidden/evil.py", b"import os\n")]))

    assert rejection(tmp_path, hidden) == "corrupt_archive"


def test_extract_reports_any_parser_exception_as_a_corrupt_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: object) -> None:
        raise IndexError("index out of range")  # what tarfile raised on a cut sparse map

    monkeypatch.setattr(extractor, "_extract_tar", broken)

    assert rejection(tmp_path, "ok.tar") == "corrupt_archive"


@pytest.mark.parametrize("reader", [None, io.BytesIO(b"abc")])
def test_tar_chunks_reject_a_member_shorter_than_its_header_says(reader: io.BytesIO | None) -> None:
    with pytest.raises(ArchiveRejected, match="corrupt_archive"):
        list(extractor._tar_chunks(reader, 5))  # pyright: ignore[reportPrivateUsage]


def test_extract_refuses_an_existing_destination_and_leaves_it_alone(tmp_path: Path) -> None:
    artifact, dest = stage(tmp_path, "ok.zip")
    dest.mkdir()
    (dest / "keep.txt").write_text("keep\n")

    with pytest.raises(FileExistsError):
        extract_archive(artifact, dest)

    assert [path.name for path in dest.iterdir()] == ["keep.txt"]


def test_extract_reports_a_failed_write_as_a_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_open = os.open

    def full_disk(path: Path, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        if flags & os.O_EXCL:
            raise OSError(28, "No space left on device")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(extractor.os, "open", full_disk)

    assert rejection(tmp_path, make_tar([member("a.txt", b"a\n")])) == "write_failed"


def test_extract_reports_a_write_that_fails_midway_as_a_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FullDisk(io.BytesIO):
        def write(self, data: object, /) -> int:
            raise OSError(28, "No space left on device")

    def fdopen(fd: int, mode: str) -> FullDisk:
        os.close(fd)
        return FullDisk()

    monkeypatch.setattr(extractor.os, "fdopen", fdopen)

    assert rejection(tmp_path, make_zip([("a.txt", b"a\n")])) == "write_failed"


def test_extract_creates_files_exclusively_and_rejects_a_path_already_on_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_open = os.open
    created: list[int] = []

    def taken(path: Path, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        if flags & os.O_CREAT:
            created.append(flags)
            if Path(path).name == "b.txt":  # as if a name differing only by case were there
                raise FileExistsError(17, "File exists")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(extractor.os, "open", taken)

    assert rejection(tmp_path, make_zip([("a.txt", b"a\n"), ("b.txt", b"b\n")])) == "duplicate_path"
    assert len(created) == 2
    assert all(flags & os.O_EXCL and flags & os.O_NOFOLLOW for flags in created)


def test_extract_never_overwrites_names_that_differ_only_by_case(tmp_path: Path) -> None:
    artifact, dest = stage(tmp_path, make_zip([("a.txt", b"one\n"), ("A.TXT", b"two\n")]))

    try:
        outcome = sorted(entry.path for entry in extract_archive(artifact, dest).files)
    except ArchiveRejected as rejected:  # a case-insensitive filesystem
        outcome = rejected.reason

    if dest.exists():
        assert outcome == ["A.TXT", "a.txt"]
        assert (dest / "a.txt").read_bytes() == b"one\n"
        assert (dest / "A.TXT").read_bytes() == b"two\n"
    else:
        assert outcome == "duplicate_path"


def run_cli(*argv: str) -> subprocess.CompletedProcess[str]:
    # -I -S: no site-packages and no environment, like an analyzer image with only this package.
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "from attacksurf.sandbox_tools import extract; "
        "status = extract.main(sys.argv[2:]); "
        "sys.exit(99 if {'flask', 'pydantic', 'attacksurf.domain'} & set(sys.modules) else status)"
    )
    command = [sys.executable, "-I", "-S", "-c", code, str(SRC), *argv]
    return subprocess.run(command, check=False, capture_output=True, text=True)  # noqa: S603


def test_cli_writes_the_manifest_and_prints_a_summary_using_only_the_stdlib(tmp_path: Path) -> None:
    artifact, dest = stage(tmp_path, "tar-device.tar")

    result = run_cli(str(artifact), str(dest))

    manifest_path = dest.with_name("out.manifest.json")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "status": "ok",
        "format": "tar",
        "files": 1,
        "total_bytes": 3,
        "skipped": 2,
        "skipped_sample": [
            {"path": "dev/null", "reason": "device"},
            {"path": "dev/sda", "reason": "device"},
        ],
        "manifest": str(manifest_path),
    }
    assert json.loads(manifest_path.read_text()) == {
        "format": "tar",
        "files": [{"path": "ok.txt", "size": 3, "sha256": hashlib.sha256(b"ok\n").hexdigest()}],
        "skipped": [
            {"path": "dev/null", "reason": "device"},
            {"path": "dev/sda", "reason": "device"},
        ],
        "total_bytes": 3,
    }


def test_cli_exits_non_zero_with_a_reason_code_when_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    artifact, dest = stage(tmp_path, "zip-slip.zip")
    manifest_path = tmp_path / "jail" / "scratch" / "m.json"

    status = extractor.main([str(artifact), str(dest), "--manifest", str(manifest_path)])

    assert status == extractor.EXIT_REJECTED
    assert json.loads(capsys.readouterr().out) == {"status": "rejected", "reason": "unsafe_path"}
    assert list((tmp_path / "jail" / "scratch").iterdir()) == []


def test_cli_reports_its_own_failures_apart_from_a_rejection(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    artifact, dest = stage(tmp_path, "ok.zip")
    failed = {"status": "error", "reason": "io_error"}

    missing_input = extractor.main([str(tmp_path / "nowhere"), str(dest)])
    unwritable = extractor.main([str(artifact), str(dest), "--manifest", str(dest / "no" / "m")])
    dest.mkdir()
    (dest / "keep.txt").write_text("keep\n")
    existing_dest = extractor.main([str(artifact), str(dest)])

    assert (missing_input, unwritable, existing_dest) == (extractor.EXIT_ERROR,) * 3
    assert [json.loads(line) for line in capsys.readouterr().out.splitlines()] == [failed] * 3
    # A manifest that cannot be written leaves no tree; an existing destination is untouched.
    assert [path.name for path in dest.iterdir()] == ["keep.txt"]
    assert len({0, 1, 2, extractor.EXIT_REJECTED, extractor.EXIT_ERROR}) == 5


def test_cli_summary_is_bounded_while_the_manifest_file_is_complete(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    count = extractor.SUMMARY_SKIPPED_ENTRIES + 5
    links = [
        member("n" * 200 + "/" + "m" * 200 + f"/l{i}", kind=tarfile.SYMTYPE, link="/etc")
        for i in range(count)
    ]
    artifact, dest = stage(tmp_path, make_tar(links))
    manifest_path = tmp_path / "jail" / "scratch" / "m.json"

    assert extractor.main([str(artifact), str(dest), "--manifest", str(manifest_path)]) == 0

    summary = json.loads(capsys.readouterr().out)
    assert summary["skipped"] == count
    assert len(summary["skipped_sample"]) == extractor.SUMMARY_SKIPPED_ENTRIES
    assert len(json.loads(manifest_path.read_text())["skipped"]) == count
    assert {len(e["path"]) for e in summary["skipped_sample"]} == {extractor.SUMMARY_PATH_CHARS}


def test_sandbox_tools_import_only_the_standard_library() -> None:
    imported: set[str] = set()
    for source in Path(extractor.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(source.read_text())):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert node.level == 0
                imported.add((node.module or "").split(".")[0])

    assert imported <= sys.stdlib_module_names
