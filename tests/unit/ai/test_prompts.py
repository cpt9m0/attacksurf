"""Versioned prompt files (ADR 0029): parsed, rendered, loaded and pinned."""

import hashlib
from collections.abc import Iterator
from importlib.resources.abc import Traversable
from pathlib import Path

import pytest

from attacksurf.ai import prompts
from attacksurf.ai.prompts import PromptError, load_prompt, parse_prompt
from attacksurf.domain.llm import Message

# Every prompt file in `ai/prompts/` and its SHA-256. A released prompt is never edited: change
# it by adding v<N+1> (and its hash here) and switching its callers.
RELEASED: dict[str, str] = {}

VALID = "<!-- system -->\nYou judge findings.\n\n<!-- user -->\nJudge these:\n$scan_data\n"


def _prompt_files(root: Traversable, prefix: str = "") -> Iterator[tuple[str, Traversable]]:
    for entry in root.iterdir():
        if entry.is_dir():
            yield from _prompt_files(entry, f"{prefix}{entry.name}/")
        elif entry.name.endswith(".md"):
            yield f"{prefix}{entry.name.removesuffix('.md')}", entry


@pytest.fixture
def prompt_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setattr(prompts, "_ROOT", tmp_path)
    load_prompt.cache_clear()
    yield tmp_path
    load_prompt.cache_clear()


# --- Parsing -------------------------------------------------------------------------------


def test_a_prompt_has_a_system_and_a_user_part() -> None:
    prompt = parse_prompt("triage/v1", VALID)

    assert prompt.version == "triage/v1"
    assert prompt.system == "You judge findings."
    assert prompt.placeholders == frozenset({"scan_data"})


def test_the_system_part_is_literal() -> None:
    prompt = parse_prompt("triage/v1", VALID.replace("You judge findings.", "Costs $5."))

    assert prompt.system == "Costs $5."


@pytest.mark.parametrize(
    "text",
    [
        "You judge.\n<!-- user -->\n$scan_data",  # no system marker
        "<!-- system -->\nYou judge.\n$scan_data",  # no user marker
        "<!-- user -->\n$scan_data\n<!-- system -->\nYou judge.",  # out of order
        VALID + "<!-- user -->\nmore",  # two user parts
        "Preamble\n" + VALID,  # text before the system part
        "<!-- system -->\n\n<!-- user -->\n$scan_data",  # empty system part
        "<!-- system -->\nYou judge.\n<!-- user -->\n  \n",  # empty user part
        "<!-- system -->\nYou judge.\n<!-- user -->\nCosts $ 5",  # invalid placeholder
    ],
)
def test_malformed_prompts_are_rejected(text: str) -> None:
    with pytest.raises(PromptError):
        parse_prompt("triage/v1", text)


@pytest.mark.parametrize(
    "version",
    ["triage", "triage/v0", "Triage/v1", "triage/V1", "triage/v1.md", "../secrets/v1", "a/v1/x"],
)
def test_malformed_version_ids_are_rejected(version: str) -> None:
    with pytest.raises(PromptError):
        parse_prompt(version, VALID)


# --- Rendering -----------------------------------------------------------------------------


def test_messages_fill_the_user_part() -> None:
    prompt = parse_prompt("triage/v1", VALID)

    assert prompt.messages(scan_data="DATA") == [
        Message("system", "You judge findings."),
        Message("user", "Judge these:\nDATA"),
    ]


def test_a_value_is_filled_in_once() -> None:
    # Scan data that looks like a placeholder must stay text.
    prompt = parse_prompt("triage/v1", VALID.replace("$scan_data", "$scan_data and $$"))

    messages = prompt.messages(scan_data="$scan_data costs ${scan_data}")

    assert messages[1].content == "Judge these:\n$scan_data costs ${scan_data} and $"


def test_a_missing_value_is_rejected() -> None:
    with pytest.raises(PromptError):
        parse_prompt("triage/v1", VALID).messages()


def test_an_unknown_value_is_rejected() -> None:
    with pytest.raises(PromptError):
        parse_prompt("triage/v1", VALID).messages(scan_data="DATA", extra="x")


# --- Loading -------------------------------------------------------------------------------


def test_load_reads_the_purpose_and_version_file(prompt_dir: Path) -> None:
    (prompt_dir / "demo").mkdir()
    (prompt_dir / "demo" / "v1.md").write_text(VALID, encoding="utf-8")

    prompt = load_prompt("demo/v1")

    assert prompt.version == "demo/v1"
    assert prompt.system == "You judge findings."


def test_loading_a_missing_prompt_is_rejected(prompt_dir: Path) -> None:
    with pytest.raises(PromptError):
        load_prompt("demo/v9")


def test_loading_a_malformed_version_id_is_rejected(prompt_dir: Path) -> None:
    (prompt_dir / "secrets.md").write_text(VALID, encoding="utf-8")

    with pytest.raises(PromptError):
        load_prompt("../secrets/v1")


# --- Released prompts never change ---------------------------------------------------------


def test_every_prompt_file_is_pinned() -> None:
    found = {version for version, _ in _prompt_files(prompts._ROOT)}

    assert found == set(RELEASED)


def test_released_prompts_are_unchanged() -> None:
    files = dict(_prompt_files(prompts._ROOT))

    for version, digest in RELEASED.items():
        assert hashlib.sha256(files[version].read_bytes()).hexdigest() == digest, version


def test_every_released_prompt_parses() -> None:
    load_prompt.cache_clear()

    for version in RELEASED:
        assert load_prompt(version).version == version
