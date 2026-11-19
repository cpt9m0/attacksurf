"""Versioned prompt files (ADR 0029): `ai/prompts/<purpose>/v<N>.md`.

A file holds a system part and a user part, each after its marker line (`<!-- system -->`, then
`<!-- user -->`). Only the user part takes `$placeholders` (`string.Template`; `$$` is a literal
`$`). Values are filled in once, so a value that looks like a placeholder stays text. A released
file is never edited (a test pins each file's SHA-256): a change adds `v<N+1>`. The version id
(`<purpose>/v<N>`) is stored with every result the prompt produces.
"""

import re
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from importlib.resources.abc import Traversable
from string import Template

from attacksurf.domain.llm import Message

SYSTEM_MARKER = "<!-- system -->"
USER_MARKER = "<!-- user -->"
_VERSION_ID = re.compile(r"[a-z][a-z_]*/v[1-9][0-9]*")
_ROOT: Traversable = files(__name__)


class PromptError(ValueError):
    """A prompt file, or a call that renders one, is wrong: a bug to fix, never input's fault."""


@dataclass(frozen=True)
class Prompt:
    version: str
    system: str
    user: Template

    @property
    def placeholders(self) -> frozenset[str]:
        return frozenset(self.user.get_identifiers())

    def messages(self, **values: str) -> list[Message]:
        """The system and user messages, with every placeholder filled from `values`."""
        if set(values) != self.placeholders:
            raise PromptError(f"prompt {self.version} takes exactly {sorted(self.placeholders)}")
        return [Message("system", self.system), Message("user", self.user.substitute(values))]


def parse_prompt(version: str, text: str) -> Prompt:
    """The prompt in `text`, checked: one non-empty system part, then one non-empty user part."""
    _check_version(version)
    lines = text.splitlines()
    system_at = [index for index, line in enumerate(lines) if line.strip() == SYSTEM_MARKER]
    user_at = [index for index, line in enumerate(lines) if line.strip() == USER_MARKER]
    if len(system_at) != 1 or len(user_at) != 1 or system_at[0] > user_at[0]:
        raise PromptError(f"prompt {version} needs one system marker, then one user marker")
    if any(line.strip() for line in lines[: system_at[0]]):
        raise PromptError(f"prompt {version} has text before its system marker")
    system = "\n".join(lines[system_at[0] + 1 : user_at[0]]).strip()
    user = Template("\n".join(lines[user_at[0] + 1 :]).strip())
    if not system or not user.template:
        raise PromptError(f"prompt {version} has an empty part")
    if not user.is_valid():
        raise PromptError(f"prompt {version} has an invalid placeholder (write $$ for a $)")
    return Prompt(version, system, user)


@cache
def load_prompt(version: str) -> Prompt:
    """The prompt file for `version` (e.g. `triage/v1`), parsed once per process."""
    _check_version(version)
    purpose, number = version.split("/")
    try:
        text = _ROOT.joinpath(purpose, f"{number}.md").read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise PromptError(f"no prompt file for {version}") from exc
    return parse_prompt(version, text)


def _check_version(version: str) -> None:
    # Also keeps a version id from naming any path outside `ai/prompts/`.
    if not _VERSION_ID.fullmatch(version):
        raise PromptError("a prompt version id looks like triage/v1")
