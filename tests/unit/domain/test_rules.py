import pytest

from attacksurf.domain.findings import Severity
from attacksurf.domain.rules import (
    MAX_RULE_ID_LENGTH,
    RULES,
    Rule,
    UnknownRule,
    build_catalog,
    get_rule,
    is_valid_rule_id,
)


def _rule(rule_id: str = "dns.email.dmarc_missing", remediation: str = "Fix it.") -> Rule:
    return Rule(
        id=rule_id,
        title="No DMARC record",
        description="The domain publishes no DMARC policy.",
        default_severity=Severity.MEDIUM,
        remediation=remediation,
        references=("https://www.rfc-editor.org/rfc/rfc7489",),
    )


@pytest.mark.parametrize(
    "rule_id", ["dns.email.dmarc_missing", "dns.takeover.dangling_cname", "web.tls.a.b"]
)
def test_valid_rule_ids(rule_id: str) -> None:
    assert is_valid_rule_id(rule_id)


@pytest.mark.parametrize(
    "rule_id",
    [
        "",
        "dns.email",  # needs <target>.<area>.<issue>
        "DNS.email.dmarc_missing",
        "dns..dmarc",
        "dns.email.dmarc-missing",
        "dns.email.dmarc_missing.",
        "1dns.email.x",
        "dns.email." + "a" * MAX_RULE_ID_LENGTH,
    ],
)
def test_invalid_rule_ids(rule_id: str) -> None:
    assert not is_valid_rule_id(rule_id)


def test_build_catalog_indexes_rules_by_id() -> None:
    rule = _rule()

    assert build_catalog([rule]) == {"dns.email.dmarc_missing": rule}


def test_build_catalog_rejects_duplicates() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        build_catalog([_rule(), _rule()])


def test_build_catalog_rejects_invalid_ids() -> None:
    with pytest.raises(ValueError, match="invalid rule id"):
        build_catalog([_rule("dmarc")])


def test_get_rule_returns_the_rule() -> None:
    rule = _rule()

    assert get_rule(rule.id, build_catalog([rule])) is rule


def test_get_rule_raises_for_unknown_rule() -> None:
    with pytest.raises(UnknownRule):
        get_rule("dns.email.nope", build_catalog([_rule()]))


def test_shipped_catalog_is_valid_and_read_only() -> None:
    assert all(rule_id == rule.id and is_valid_rule_id(rule_id) for rule_id, rule in RULES.items())
    with pytest.raises(TypeError):
        RULES["dns.x.y"] = _rule("dns.x.y")  # type: ignore[index]


def test_render_remediation_fills_placeholders() -> None:
    rule = _rule(remediation="Publish a DMARC record at _dmarc.$domain.")

    assert rule.render_remediation({"domain": "example.com"}) == (
        "Publish a DMARC record at _dmarc.example.com."
    )


def test_render_remediation_leaves_unknown_placeholders() -> None:
    rule = _rule(remediation="Ask $owner to fix $domain.")

    assert rule.render_remediation({"domain": "example.com"}) == "Ask $owner to fix example.com."


def test_render_remediation_never_interprets_values() -> None:
    rule = _rule(remediation="Fix $domain.")
    hostile = "{0.__class__} ${domain} $$"

    assert rule.render_remediation({"domain": hostile}) == f"Fix {hostile}."
