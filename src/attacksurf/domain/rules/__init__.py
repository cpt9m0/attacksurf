"""Rule catalog: what each `rule_id` means (title, default severity, remediation).

Scanners report findings by `rule_id`; the catalog supplies the human-facing text. Each target
type adds its rules in its own module here (e.g. `dns.py`) and lists them in `_ALL_RULES`.
"""

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from string import Template
from types import MappingProxyType

from attacksurf.domain.findings import Severity

MAX_RULE_ID_LENGTH = 100
# <target>.<area>.<issue>, e.g. dns.email.dmarc_missing
_RULE_ID = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,}$")


class UnknownRule(LookupError):
    """A scanner reported a `rule_id` that isn't in the catalog (a bug, not user input)."""


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    description: str
    default_severity: Severity
    remediation: str  # `$name` placeholders, filled by `render_remediation`
    references: tuple[str, ...] = ()

    def render_remediation(self, context: Mapping[str, str]) -> str:
        """Fill `$name` placeholders; unknown ones stay as they are.

        `string.Template`, not `str.format`: context values come from scans, and format
        syntax in them (`{0.__class__}`) must never be interpreted.
        """
        return Template(self.remediation).safe_substitute(context)


def is_valid_rule_id(rule_id: str) -> bool:
    return len(rule_id) <= MAX_RULE_ID_LENGTH and _RULE_ID.fullmatch(rule_id) is not None


def build_catalog(rules: Iterable[Rule]) -> dict[str, Rule]:
    catalog: dict[str, Rule] = {}
    for rule in rules:
        if not is_valid_rule_id(rule.id):
            raise ValueError(f"invalid rule id {rule.id!r}: expected <target>.<area>.<issue>")
        if rule.id in catalog:
            raise ValueError(f"duplicate rule id {rule.id!r}")
        catalog[rule.id] = rule
    return catalog


_ALL_RULES: tuple[Rule, ...] = ()  # filled as scanners land (#15-#19)
RULES: Mapping[str, Rule] = MappingProxyType(build_catalog(_ALL_RULES))


def get_rule(rule_id: str, catalog: Mapping[str, Rule] = RULES) -> Rule:
    try:
        return catalog[rule_id]
    except KeyError:
        raise UnknownRule(rule_id) from None
