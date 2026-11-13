"""Evaluate email-authentication records for spoofability (#17).

A passive check on root domains: one `lookup_many` round reads TXT records
(apex, `_dmarc`, `_mta-sts`, and common `<selector>._domainkey` names) and evaluates SPF,
DMARC, DKIM and MTA-STS publication. The scanner reports findings only; it emits no assets,
relations or observations (`dns.resolve` owns `details["dns"]`). When the scanned name has
no usable DMARC record, the organizational domain's record (via `runtime.org_domain`) is
evaluated instead, with its `sp` policy applying to the subdomain.

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

import base64
import binascii
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
# apex + own _dmarc + organizational _dmarc fallback + _mta-sts + one TXT per selector
DNS_LOOKUPS = 4 + len(DKIM_SELECTORS)
MAX_EVIDENCE_VALUES = 5
MAX_VALUE_LENGTH = 256
SPF_LOOKUP_LIMIT = 10
# Terms that cost a DNS query when SPF is evaluated (RFC 7208 section 4.6.4).
SPF_DNS_TERMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})
_SPF_PREFIX = "v=spf1"
_DMARC_PREFIX = "v=dmarc1"
_MTA_STS_PREFIX = "v=stsv1"
_MTA_STS_ID = re.compile(r"[a-z0-9]{1,32}")
_ED25519_KEY_BYTES = 32
_DER_SEQUENCE_TAG = 0x30
_DER_LONG_LENGTH = 0x80  # length byte at/above this encodes the byte count of the length
_DER_LENGTH_MASK = 0x7F
_DER_MAX_LENGTH_BYTES = 2
_DER_MIN_BYTES = 2  # tag byte + at least one length byte
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
        org_domain = runtime.org_domain(asset.value) if runtime.org_domain else None
        if org_domain == asset.value:
            org_domain = None  # already the organizational domain: no fallback to resolve
        queries = _queries(asset.value, org_domain)
        try:
            results = runtime.dns.lookup_many(queries)
        except DnsError:
            raise TransientJobError("Email security check failed.") from None
        if all(result.status is DnsStatus.ERROR for result in results):
            raise TransientJobError("Email security check failed.")
        by_name = {result.query.name: result for result in results}
        return ScanOutput(findings=tuple(_evaluate(asset.value, by_name, org_domain)))


def _queries(domain: str, org_domain: str | None) -> tuple[DnsQuery, ...]:
    names = [
        (domain, DnsRecordType.TXT),
        (f"_dmarc.{domain}", DnsRecordType.TXT),
        (f"_mta-sts.{domain}", DnsRecordType.TXT),
        *((f"{selector}._domainkey.{domain}", DnsRecordType.TXT) for selector in DKIM_SELECTORS),
    ]
    if org_domain is not None:
        names.append((f"_dmarc.{org_domain}", DnsRecordType.TXT))
    return tuple(DnsQuery(name, record_type) for name, record_type in names)


def _evaluate(
    domain: str, by_name: dict[str, DnsLookup], org_domain: str | None
) -> list[RawFinding]:
    findings: list[RawFinding] = []
    findings.extend(_spf_findings(domain, by_name.get(domain.lower())))
    dmarc = by_name.get(f"_dmarc.{domain.lower()}")
    org_dmarc = by_name.get(f"_dmarc.{org_domain.lower()}") if org_domain else None
    findings.extend(_dmarc_findings(domain, dmarc, org_dmarc, org_domain))
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


_DMARC_POLICIES = frozenset({"none", "quarantine", "reject"})


def _dmarc_findings(
    domain: str,
    dmarc_txt: DnsLookup | None,
    org_dmarc_txt: DnsLookup | None,
    org_domain: str | None,
) -> list[RawFinding]:
    if dmarc_txt is None or dmarc_txt.status is DnsStatus.ERROR:
        return []
    records = _dmarc_records(_values(dmarc_txt))
    if len(records) > 1:
        # Several records at one name terminate discovery (RFC 7489 section 6.6.3): no
        # policy applies, and the organizational fallback is only for an empty set.
        return [
            RawFinding(
                rule_id="dns.email.dmarc_missing",
                evidence=(_evidence("TXT", f"_dmarc.{domain}", _values(dmarc_txt)),),
                remediation_context={"domain": domain},
            )
        ]
    if len(records) == 1:
        return _dmarc_record_findings(domain, f"_dmarc.{domain}", records[0], inherited=False)
    # An empty record set falls back to the organizational domain's record (RFC 7489
    # section 6.6.3).
    if org_domain is not None and org_dmarc_txt is not None:
        if org_dmarc_txt.status is DnsStatus.ERROR:
            return []  # the fallback could not be read; absence is not proven
        org_records = _dmarc_records(_values(org_dmarc_txt))
        if len(org_records) == 1:
            return _dmarc_record_findings(
                domain, f"_dmarc.{org_domain}", org_records[0], inherited=True
            )
    return [
        RawFinding(
            rule_id="dns.email.dmarc_missing",
            evidence=(_evidence("TXT", f"_dmarc.{domain}", _values(dmarc_txt)),),
            remediation_context={"domain": domain},
        )
    ]


def _dmarc_record_findings(
    domain: str, name: str, record: str, *, inherited: bool
) -> list[RawFinding]:
    """Findings for one DMARC record; `inherited` records apply their `sp` policy here."""
    tags = _tags(record)
    policy = tags.get("p", "")
    subdomain_policy = tags.get("sp")
    if policy not in _DMARC_POLICIES or (
        subdomain_policy is not None and subdomain_policy not in _DMARC_POLICIES
    ):
        # An unusable policy tag ends DMARC processing, unless a valid reporting URI
        # makes receivers act as if `p=none` had been published (RFC 7489 section 6.6.3).
        if _has_valid_reporting_uri(tags):
            return [
                RawFinding(
                    rule_id="dns.email.dmarc_policy_none",
                    evidence=(_evidence("TXT", name, (record,)),),
                    remediation_context={"domain": domain},
                )
            ]
        return [
            RawFinding(
                rule_id="dns.email.dmarc_missing",
                evidence=(_evidence("TXT", name, (record,)),),
                remediation_context={"domain": domain},
            )
        ]
    effective = subdomain_policy if (inherited and subdomain_policy is not None) else policy
    findings: list[RawFinding] = []
    if effective == "none":
        findings.append(
            RawFinding(
                rule_id="dns.email.dmarc_policy_none",
                evidence=(_evidence("TXT", name, (record,)),),
                remediation_context={"domain": domain},
            )
        )
    if not _has_valid_reporting_uri(tags):
        findings.append(
            RawFinding(
                rule_id="dns.email.dmarc_no_reporting",
                evidence=(_evidence("TXT", name, (record,)),),
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
                evidence=(_evidence("TXT", name, (record,)),),
                remediation_context={"domain": domain, "pct": str(pct)},
            )
        )
    return findings


def _has_valid_reporting_uri(tags: dict[str, str]) -> bool:
    """At least one `mailto:` reporting URI with an address (RFC 7489 section 6.2)."""
    for key in ("rua", "ruf"):
        for raw_uri in tags.get(key, "").split(","):
            uri = raw_uri.strip()
            if not uri.startswith("mailto:"):
                continue
            local, at, host = uri.removeprefix("mailto:").split("!", maxsplit=1)[0].partition("@")
            if at and local and host:
                return True
    return False


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
    candidates = [value for value in _values(lookup) if _is_mta_sts_record(value)]
    # Senders use the record only when exactly one carries the version prefix
    # (RFC 8461 section 3.1); zero or several mean no discoverable policy.
    if len(candidates) == 1 and _mta_sts_valid(candidates[0]):
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
    """Effective `all` qualifier, or None when a lone `redirect=` decides the outcome.

    An explicit `all` mechanism takes precedence over `redirect` regardless of position
    (RFC 7208 section 5.1). With neither, evaluation falls through to a neutral result,
    which is an implicit `?all` (RFC 7208 section 4.7).
    """
    terms = record.split()[1:]
    for raw_term in terms:
        if _term_name(raw_term) == "all":
            qualifier = raw_term[0] if raw_term[:1] in "+-~?" else "+"
            return f"{qualifier}all"
    if any(_term_name(term) == "redirect" for term in terms):
        return None
    return "?all"


def _term_name(term: str) -> str:
    """SPF term name without qualifier or argument (`-mx/24` -> `mx`)."""
    text = term.lower()
    if text[:1] in "+-~?":
        text = text[1:]
    return re.split(r"[:/=]", text, maxsplit=1)[0]


def _spf_lookup_count(record: str) -> int:
    """Count SPF terms a receiver would actually query DNS for (RFC 7208 section 4.6.4).

    Terms after the `all` mechanism are never evaluated, and `redirect` is ignored when
    an `all` mechanism exists (section 5.1), so neither counts in those positions.
    """
    terms = record.split()[1:]
    has_all = any(_term_name(term) == "all" for term in terms)
    count = 0
    for raw_term in terms:
        name = _term_name(raw_term)
        if name == "all":
            break
        if name == "redirect":
            continue  # counted below, and only when no `all` makes it ineffective
        if name in SPF_DNS_TERMS:
            count += 1
    if not has_all and any(_term_name(term) == "redirect" for term in terms):
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
    """A selector TXT holding a usable public key (RFC 6376 sections 3.6.1, 6.1.2).

    The `v=` tag is optional in key records, but when present it must name DKIM1. An
    empty `p=` is a revoked key; otherwise `p=` must be well-formed base64 of key data
    suitable for the declared key type (a DER RSAPublicKey for `rsa`, 32 raw bytes for
    `ed25519`). Placeholder text is not a key.
    """
    tags: dict[str, str] = {}
    for part in value.split(";"):
        name, separator, tag_value = part.partition("=")
        if separator:
            tags[name.strip().lower()] = tag_value.strip()
    version = tags.get("v")
    if version is not None and version.lower() != "dkim1":
        return False
    try:
        decoded = base64.b64decode("".join(tags.get("p", "").split()), validate=True)
    except (binascii.Error, ValueError):
        return False
    if not decoded:
        return False
    key_type = tags.get("k", "rsa").lower()
    if key_type == "ed25519":
        return len(decoded) == _ED25519_KEY_BYTES
    if key_type != "rsa":
        return False
    return _is_der_sequence(decoded)


def _is_der_sequence(data: bytes) -> bool:
    """True when `data` is exactly one DER SEQUENCE (tag + declared length + content)."""
    if len(data) < _DER_MIN_BYTES or data[0] != _DER_SEQUENCE_TAG:
        return False
    if data[1] < _DER_LONG_LENGTH:
        header, declared = 2, data[1]
    else:
        length_bytes = data[1] & _DER_LENGTH_MASK
        if length_bytes == 0 or length_bytes > _DER_MAX_LENGTH_BYTES:
            return False
        header = 2 + length_bytes
        if len(data) < header:
            return False
        declared = int.from_bytes(data[2:header], "big")
    return header + declared == len(data)


def _is_mta_sts_record(value: str) -> bool:
    text = value.strip()
    return text[: len(_MTA_STS_PREFIX)].lower() == _MTA_STS_PREFIX and (
        len(text) == len(_MTA_STS_PREFIX) or text[len(_MTA_STS_PREFIX)] in " \t;"
    )


def _mta_sts_valid(value: str) -> bool:
    """A usable MTA-STS discovery record: `v=STSv1` plus a 1-32 char alphanumeric `id`
    (RFC 8461 section 3.1). The HTTPS policy itself is deliberately not fetched."""
    text = value.strip()
    if not _is_mta_sts_record(text):
        return False
    return _MTA_STS_ID.fullmatch(_tags(text).get("id", "")) is not None


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
