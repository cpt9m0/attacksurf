"""Evaluate email-authentication records for spoofability (#17).

A passive check on root domains: one `lookup_many` round reads TXT records
(apex, `_dmarc`, `_mta-sts`, and common `<selector>._domainkey` names) and evaluates SPF,
DMARC, DKIM and MTA-STS publication. The scanner reports findings only; it emits no assets,
relations or observations (`dns.resolve` owns `details["dns"]`).

MX presence is deliberately not consulted: a parked domain (no MX) hardens with
`v=spf1 -all` plus a `p=reject` DMARC record, which is exactly what the missing-record
findings and their remediation recommend, so the evaluation is identical with or without
MX answers.

DNS answers are untrusted data: values are stripped, deduplicated and truncated before they
reach evidence, and NUL bytes are escaped because PostgreSQL JSONB cannot store U+0000.
A failed query fails open (that check is skipped); only a run where every query errored is
retryable (`TransientJobError`). DKIM probing covers common selectors only, so its finding
is low confidence.
"""

import re
from collections.abc import Sequence

from attacksurf.domain.findings import Confidence, EvidenceKind, Severity
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError, DnsLookup, DnsQuery, DnsRecordType, DnsStatus
from attacksurf.domain.scanners import (
    AssetRef,
    AssetType,
    RawEvidence,
    RawFinding,
    ScanContext,
    ScannerError,
    ScannerGrant,
    ScanOutput,
)
from attacksurf.scanners.registry import register_scanner

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "mail")
DNS_LOOKUPS = 3 + len(DKIM_SELECTORS)  # apex + _dmarc + _mta-sts + one TXT per selector
MAX_EVIDENCE_VALUES = 5
MAX_VALUE_LENGTH = 256
SPF_LOOKUP_LIMIT = 10
# Terms that cost a DNS query when SPF is evaluated (RFC 7208 section 4.6.4).
SPF_DNS_TERMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})
_SPF_PREFIX = "v=spf1"
_DMARC_PREFIX = "v=dmarc1"
_MTA_STS_PREFIX = "v=stsv1"
_DMARC_FULL_PCT = 100


@register_scanner
class DnsEmail:
    name = "dns.email"
    # Email authentication is published for the mail domain (the registered root), not for
    # every discovered host: `_dmarc.www.…` and friends would be noise on subdomains, and
    # the root's DMARC policy already covers them via `sp=`.
    asset_types = frozenset({AssetType.DOMAIN})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 60.0
    grant = ScannerGrant(dns_lookups=DNS_LOOKUPS)

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        runtime = ctx.runtime
        if runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        queries = _queries(asset.value)
        try:
            results = runtime.dns.lookup_many(queries)
        except DnsError:
            raise TransientJobError("Email security check failed.") from None
        if all(result.status is DnsStatus.ERROR for result in results):
            raise TransientJobError("Email security check failed.")
        by_name = {result.query.name: result for result in results}
        return ScanOutput(findings=tuple(_evaluate(asset.value, by_name)))


def _queries(domain: str) -> tuple[DnsQuery, ...]:
    names = (
        (domain, DnsRecordType.TXT),
        (f"_dmarc.{domain}", DnsRecordType.TXT),
        (f"_mta-sts.{domain}", DnsRecordType.TXT),
        *((f"{selector}._domainkey.{domain}", DnsRecordType.TXT) for selector in DKIM_SELECTORS),
    )
    return tuple(DnsQuery(name, record_type) for name, record_type in names)


def _evaluate(domain: str, by_name: dict[str, DnsLookup]) -> list[RawFinding]:
    findings: list[RawFinding] = []
    findings.extend(_spf_findings(domain, by_name.get(domain.lower())))
    dmarc = by_name.get(f"_dmarc.{domain.lower()}")
    findings.extend(_dmarc_findings(domain, dmarc))
    dkim_lookups = [by_name.get(f"{s}._domainkey.{domain.lower()}") for s in DKIM_SELECTORS]
    dkim_finding = _dkim_finding(domain, dkim_lookups)
    if dkim_finding is not None:
        findings.append(dkim_finding)
    mta_sts = by_name.get(f"_mta-sts.{domain.lower()}")
    mta_finding = _mta_sts_finding(domain, mta_sts)
    if mta_finding is not None:
        findings.append(mta_finding)
    return findings


def _spf_findings(domain: str, apex_txt: DnsLookup | None) -> list[RawFinding]:
    if apex_txt is None or apex_txt.status is DnsStatus.ERROR:
        return []
    records = _spf_records(_values(apex_txt))
    if not records:
        return [
            RawFinding(
                rule_id="dns.email.spf_missing",
                evidence=(_evidence("TXT", domain, _values(apex_txt)),),
                remediation_context={"domain": domain},
            )
        ]
    if len(records) > 1:
        return [
            RawFinding(
                rule_id="dns.email.spf_multiple_records",
                evidence=(_evidence("TXT", domain, records),),
                remediation_context={"domain": domain},
            )
        ]
    record = next(iter(records))
    findings: list[RawFinding] = []
    ending = _spf_all_ending(record)
    if ending is not None and ending in {"+all", "?all"}:
        findings.append(
            RawFinding(
                rule_id="dns.email.spf_permissive",
                # `?all` (neutral) is weaker than `-all` but less dangerous than `+all`
                # (pass): report it a notch lower than the rule default.
                severity=Severity.MEDIUM if ending == "?all" else None,
                evidence=(_evidence("TXT", domain, (record,)),),
                remediation_context={"domain": domain, "ending": ending},
            )
        )
    count = _spf_lookup_count(record)
    if count > SPF_LOOKUP_LIMIT:
        findings.append(
            RawFinding(
                rule_id="dns.email.spf_too_many_lookups",
                evidence=(_evidence("TXT", domain, (record,)),),
                remediation_context={"domain": domain, "count": str(count)},
            )
        )
    return findings


def _dmarc_findings(domain: str, dmarc_txt: DnsLookup | None) -> list[RawFinding]:
    if dmarc_txt is None or dmarc_txt.status is DnsStatus.ERROR:
        return []
    records = _dmarc_records(_values(dmarc_txt))
    name = f"_dmarc.{domain}"
    if len(records) != 1:
        # Zero records, or several (receivers then apply no policy at all): the domain has
        # no usable DMARC policy either way, and #17 defines no dedicated multiple-record rule.
        return [
            RawFinding(
                rule_id="dns.email.dmarc_missing",
                evidence=(_evidence("TXT", name, _values(dmarc_txt)),),
                remediation_context={"domain": domain},
            )
        ]
    tags = _tags(records[0])
    if tags.get("p", "") not in {"none", "quarantine", "reject"}:
        # A record without a usable policy tag is ignored by receivers: no policy at all.
        return [
            RawFinding(
                rule_id="dns.email.dmarc_missing",
                evidence=(_evidence("TXT", name, records),),
                remediation_context={"domain": domain},
            )
        ]
    findings: list[RawFinding] = []
    if tags["p"] == "none":
        findings.append(
            RawFinding(
                rule_id="dns.email.dmarc_policy_none",
                evidence=(_evidence("TXT", name, records),),
                remediation_context={"domain": domain},
            )
        )
    if "rua" not in tags and "ruf" not in tags:
        findings.append(
            RawFinding(
                rule_id="dns.email.dmarc_no_reporting",
                evidence=(_evidence("TXT", name, records),),
                remediation_context={"domain": domain},
            )
        )
    try:
        pct = int(tags.get("pct", str(_DMARC_FULL_PCT)))
    except ValueError:
        pct = _DMARC_FULL_PCT
    if pct < _DMARC_FULL_PCT:
        findings.append(
            RawFinding(
                rule_id="dns.email.dmarc_pct_partial",
                evidence=(_evidence("TXT", name, records),),
                remediation_context={"domain": domain, "pct": str(pct)},
            )
        )
    return findings


def _dkim_finding(domain: str, lookups: Sequence[DnsLookup | None]) -> RawFinding | None:
    if all(lookup is None or lookup.status is DnsStatus.ERROR for lookup in lookups):
        # Every selector query failed: absence of evidence, not evidence of absence.
        return None
    for lookup in lookups:
        if lookup is not None and any(_dkim_key_valid(value) for value in _values(lookup)):
            return None
    return RawFinding(
        rule_id="dns.email.dkim_not_found",
        confidence=Confidence.LOW,
        evidence=(
            _evidence(
                "TXT",
                f"<selector>._domainkey.{domain}",
                tuple(f"{s}._domainkey.{domain}" for s in DKIM_SELECTORS),
            ),
        ),
        remediation_context={"domain": domain},
    )


def _mta_sts_finding(domain: str, lookup: DnsLookup | None) -> RawFinding | None:
    if lookup is None or lookup.status is DnsStatus.ERROR:
        return None
    name = f"_mta-sts.{domain}"
    if any(_mta_sts_valid(value) for value in _values(lookup)):
        return None
    return RawFinding(
        rule_id="dns.email.mta_sts_missing",
        evidence=(_evidence("TXT", name, _values(lookup)),),
        remediation_context={"domain": domain},
    )


def _spf_records(values: Sequence[str]) -> tuple[str, ...]:
    records = []
    for value in values:
        text = value.strip()
        if text[: len(_SPF_PREFIX)].lower() == _SPF_PREFIX and (
            len(text) == len(_SPF_PREFIX) or text[len(_SPF_PREFIX)] in " \t"
        ):
            records.append(text)
    return tuple(records)


def _spf_all_ending(record: str) -> str | None:
    """Effective `all` qualifier, or None when a `redirect=` modifier makes `all` moot.

    With neither an `all` mechanism nor a redirect, SPF evaluation falls through to a
    neutral result, which is an implicit `?all` (RFC 7208 section 4.7).
    """
    terms = record.split()[1:]
    if any(term.lower().startswith("redirect=") for term in terms):
        return None
    for raw_term in terms:
        term = raw_term.lower()
        qualifier = term[0] if term[:1] in "+-~?" else "+"
        mechanism = term[1:] if term[:1] in "+-~?" else term
        if mechanism == "all" or mechanism.startswith("all/"):
            return f"{qualifier}all"
    return "?all"


def _spf_lookup_count(record: str) -> int:
    """Count SPF terms that trigger DNS queries (RFC 7208 section 10.1)."""
    count = 0
    for raw_term in record.split()[1:]:
        term = raw_term.lstrip("+-~?")
        name = re.split(r"[:/=]", term, maxsplit=1)[0].lower()
        if name in SPF_DNS_TERMS:
            count += 1
    return count


def _dmarc_records(values: Sequence[str]) -> tuple[str, ...]:
    records = []
    for value in values:
        text = value.strip()
        if text[: len(_DMARC_PREFIX)].lower() == _DMARC_PREFIX and (
            len(text) == len(_DMARC_PREFIX) or text[len(_DMARC_PREFIX)] in " \t;"
        ):
            records.append(text)
    return tuple(records)


def _tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";")[1:]:
        name, separator, value = part.partition("=")
        if not separator:
            continue
        tags[name.strip().lower()] = value.strip().lower()
    return tags


def _dkim_key_valid(value: str) -> bool:
    """A selector TXT holding a usable public key (`v=DKIM1` with a non-empty `p=`)."""
    tags: dict[str, str] = {}
    for part in value.split(";"):
        name, separator, tag_value = part.partition("=")
        if separator:
            tags[name.strip().lower()] = tag_value.strip()
    # An empty `p=` is a revoked key, not a usable one. The `v=` tag is optional in key
    # records, but when present it must name DKIM1.
    version = tags.get("v")
    return (version is None or version.lower() == "dkim1") and bool(tags.get("p", ""))


def _mta_sts_valid(value: str) -> bool:
    text = value.strip()
    return text[: len(_MTA_STS_PREFIX)].lower() == _MTA_STS_PREFIX and (
        len(text) == len(_MTA_STS_PREFIX) or text[len(_MTA_STS_PREFIX)] in " \t;"
    )


def _values(lookup: DnsLookup) -> tuple[str, ...]:
    if lookup.status is not DnsStatus.OK:
        return ()
    seen: set[str] = set()
    result: list[str] = []
    for raw in lookup.values:
        # PostgreSQL JSONB cannot store U+0000; keep TXT content visible as an escape.
        value = raw.strip().replace("\x00", "\\0")
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return tuple(result)


def _evidence(record: str, name: str, values: Sequence[str]) -> RawEvidence:
    return RawEvidence(
        kind=EvidenceKind.DNS_RECORD,
        data={
            "record": record,
            "name": name,
            "values": [value[:MAX_VALUE_LENGTH] for value in values[:MAX_EVIDENCE_VALUES]],
        },
    )
