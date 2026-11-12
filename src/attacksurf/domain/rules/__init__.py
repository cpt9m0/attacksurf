"""Rule catalog: what each `rule_id` means (title, default severity, remediation).

Scanners report findings by `rule_id`; the catalog supplies the human-facing text. Each target
type adds its rules in its own module here (e.g. `dns.py`); `_ALL_RULES` is the shipped catalog.
"""

from collections.abc import Mapping
from types import MappingProxyType

from attacksurf.domain.rules.catalog import (
    MAX_RULE_ID_LENGTH,
    Rule,
    UnknownRule,
    build_catalog,
    is_valid_rule_id,
)
from attacksurf.domain.rules.catalog import (
    get_rule as _get_rule,
)
from attacksurf.domain.rules.dns import DNS_RULES

_ALL_RULES: tuple[Rule, ...] = (*DNS_RULES,)  # filled as scanners land (#15-#19)
RULES: Mapping[str, Rule] = MappingProxyType(build_catalog(_ALL_RULES))


def get_rule(rule_id: str, catalog: Mapping[str, Rule] = RULES) -> Rule:
    return _get_rule(rule_id, catalog)


__all__ = [
    "MAX_RULE_ID_LENGTH",
    "RULES",
    "Rule",
    "UnknownRule",
    "build_catalog",
    "get_rule",
    "is_valid_rule_id",
]
