"""Match fingerprinted web components against local CVE/KEV/EPSS intelligence (#75)."""

from collections.abc import Mapping, Sequence
from types import MappingProxyType

from pydantic import JsonValue

from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Confidence, EvidenceKind, Severity
from attacksurf.domain.scanners import (
    AssetRef,
    RawEvidence,
    RawFinding,
    ScanContext,
    ScannerError,
    ScannerGrant,
    ScanOutput,
)
from attacksurf.domain.vulnintel import ProductVulnerability, is_valid_version
from attacksurf.scanners.registry import register_scanner

MAX_EVIDENCE_CVES = 20
MAX_CVE_DESCRIPTION_EVIDENCE_CHARS = 240
MAX_SUMMARY_CVES = 3
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0

# Lowercased fingerprinted product name -> NVD CPE `(vendor, product)` candidates.
# Only curated entries here are checked; aliases cover upstream vendor renames (e.g. f5/nginx).
TECHNOLOGY_CPES: Mapping[str, tuple[tuple[str, str], ...]] = MappingProxyType(
    {
        "apache http server": (("apache", "http_server"),),
        "apache tomcat": (("apache", "tomcat"),),
        "atlassian confluence": (
            ("atlassian", "confluence_server"),
            ("atlassian", "confluence_data_center"),
            ("atlassian", "confluence"),
        ),
        "atlassian jira": (
            ("atlassian", "jira_server"),
            ("atlassian", "jira_data_center"),
            ("atlassian", "jira"),
        ),
        "bootstrap": (("getbootstrap", "bootstrap"), ("twitter", "bootstrap")),
        "caddy": (("caddyserver", "caddy"),),
        "django": (("djangoproject", "django"),),
        "dokuwiki": (("dokuwiki", "dokuwiki"),),
        "drupal": (("drupal", "drupal"),),
        "envoy": (("envoyproxy", "envoy"),),
        "express": (("expressjs", "express"),),
        "flask": (("palletsprojects", "flask"),),
        "ghost": (("ghost", "ghost"),),
        "gitlab": (("gitlab", "gitlab"),),
        "grafana": (("grafana", "grafana"),),
        "gunicorn": (("gunicorn", "gunicorn"),),
        "hugo": (("gohugo", "hugo"),),
        "iis": (
            ("microsoft", "internet_information_services"),
            ("microsoft", "iis"),
        ),
        "jenkins": (("jenkins", "jenkins"),),
        "jetty": (("eclipse", "jetty"),),
        "joomla": (("joomla", "joomla!"), ("joomla", "joomla")),
        "jquery": (("jquery", "jquery"),),
        "kestrel": (("microsoft", "kestrel"),),
        "kibana": (("elastic", "kibana"),),
        "laravel": (("laravel", "laravel"),),
        "litespeed": (
            ("litespeedtech", "litespeed_web_server"),
            ("litespeedtech", "openlitespeed"),
        ),
        "lodash": (("lodash", "lodash"),),
        "magento": (("magento", "magento"), ("adobe", "magento")),
        "matomo analytics": (("matomo", "matomo"),),
        "mediawiki": (("mediawiki", "mediawiki"),),
        "microsoft asp.net": (("microsoft", "asp.net"),),
        "moment.js": (("momentjs", "moment"),),
        "moodle": (("moodle", "moodle"),),
        "next.js": (("vercel", "next.js"),),
        "nginx": (("f5", "nginx"), ("nginx", "nginx")),
        "node.js": (("nodejs", "node.js"),),
        "nuxt.js": (("nuxt", "nuxt"), ("nuxtjs", "nuxt.js")),
        "openresty": (("openresty", "openresty"),),
        "outlook web app": (("microsoft", "exchange_server"),),
        "php": (("php", "php"),),
        "phpmyadmin": (("phpmyadmin", "phpmyadmin"),),
        "prestashop": (("prestashop", "prestashop"),),
        "python": (("python", "python"),),
        "react": (("facebook", "react"),),
        "roundcube": (("roundcube", "webmail"),),
        "ruby": (("ruby-lang", "ruby"),),
        "ruby on rails": (("rubyonrails", "rails"),),
        "sonarqube": (("sonarsource", "sonarqube"),),
        "spring": (("vmware", "spring_framework"), ("pivotal_software", "spring_framework")),
        "symfony": (("sensiolabs", "symfony"),),
        "typo3 cms": (("typo3", "typo3"),),
        "uvicorn": (("encode", "uvicorn"),),
        "varnish": (("varnish-cache", "varnish_cache"), ("varnish_cache_project", "varnish_cache")),
        "vue.js": (("vuejs", "vue"),),
        "woocommerce": (("woocommerce", "woocommerce"), ("automattic", "woocommerce")),
        "wordpress": (("wordpress", "wordpress"),),
    }
)


def lookup_cpes(tech_name: str) -> tuple[tuple[str, str], ...]:
    """Return curated `(vendor, product)` pairs for a fingerprinted technology name."""
    return TECHNOLOGY_CPES.get(tech_name.strip().lower(), ())


def _bump_severity(severity: Severity) -> Severity:
    order = (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
    idx = order.index(severity) if severity in order else 0
    return order[min(idx + 1, len(order) - 1)]


def severity_for_vulnerabilities(vulns: Sequence[ProductVulnerability]) -> Severity:
    """Derive severity from peak CVSS score, bumping one level when any CVE is in CISA KEV."""
    max_cvss = max((v.max_cvss for v in vulns if v.max_cvss is not None), default=None)
    if max_cvss is not None and max_cvss >= CVSS_CRITICAL:
        severity = Severity.CRITICAL
    elif max_cvss is not None and max_cvss >= CVSS_HIGH:
        severity = Severity.HIGH
    elif max_cvss is not None and max_cvss >= CVSS_MEDIUM:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW
    if any(v.in_kev for v in vulns):
        return _bump_severity(severity)
    return severity


def _extract_versioned_technologies(details: Mapping[str, JsonValue]) -> list[tuple[str, str]]:
    raw = details.get("technologies")
    if not isinstance(raw, list):
        return []
    extracted: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        version = item.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        clean_name = name.strip()
        clean_version = version.strip()
        key = clean_name.lower()
        if not key or key in seen or not is_valid_version(clean_version):
            continue
        if not lookup_cpes(clean_name):
            continue
        seen.add(key)
        extracted.append((clean_name, clean_version))
    return extracted


def _serialize_cve(vuln: ProductVulnerability) -> dict[str, JsonValue]:
    return {
        "cve_id": vuln.cve_id,
        "cvss": vuln.max_cvss,
        "in_kev": vuln.in_kev,
        "kev_date_added": vuln.kev_date_added.isoformat() if vuln.kev_date_added else None,
        "epss_score": round(vuln.epss_score, 4) if vuln.epss_score is not None else None,
        "epss_percentile": (
            round(vuln.epss_percentile, 4) if vuln.epss_percentile is not None else None
        ),
        "description": vuln.description[:MAX_CVE_DESCRIPTION_EVIDENCE_CHARS],
    }


def _match_component(
    ctx: ScanContext, name: str, version: str
) -> tuple[tuple[tuple[str, str], ...], list[ProductVulnerability]]:
    runtime = ctx.runtime
    if runtime is None:
        raise ScannerError("Scanner runtime is not configured.")
    cpes = lookup_cpes(name)
    by_cve: dict[str, ProductVulnerability] = {}
    for vendor, product in cpes:
        for vuln in runtime.vuln_intel.match_product(vendor, product, version):
            by_cve.setdefault(vuln.cve_id, vuln)
    vulns = sorted(
        by_cve.values(),
        key=lambda v: (
            not v.in_kev,
            -(v.max_cvss if v.max_cvss is not None else -1.0),
            -(v.epss_score if v.epss_score is not None else -1.0),
            v.cve_id,
        ),
    )
    return cpes, vulns


def _component_finding(
    asset: AssetRef,
    name: str,
    version: str,
    cpes: tuple[tuple[str, str], ...],
    vulns: Sequence[ProductVulnerability],
) -> RawFinding:
    capped = vulns[:MAX_EVIDENCE_CVES]
    top_ids = [v.cve_id for v in capped[:MAX_SUMMARY_CVES]]
    extra_count = len(vulns) - len(top_ids)
    cve_summary = ", ".join(top_ids)
    if extra_count > 0:
        cve_summary = f"{cve_summary} (+{extra_count} more)"
    max_cvss = max((v.max_cvss for v in vulns if v.max_cvss is not None), default=None)
    kev_count = sum(1 for v in vulns if v.in_kev)
    evidence_data: dict[str, JsonValue] = {
        "product": name,
        "version": version,
        "cpe_targets": [f"{vendor}:{product}" for vendor, product in cpes],
        "max_cvss": max_cvss,
        "kev_count": kev_count,
        "total_cves": len(vulns),
        "cves_truncated": len(vulns) > MAX_EVIDENCE_CVES,
        "cves": [_serialize_cve(v) for v in capped],
    }
    return RawFinding(
        asset=asset,
        rule_id="web.components.known_vulnerable",
        severity=severity_for_vulnerabilities(vulns),
        confidence=Confidence.MEDIUM,
        location=name.lower(),
        remediation_context={
            "product": name,
            "version": version,
            "url": asset.value,
            "cve_summary": cve_summary,
        },
        evidence=(RawEvidence(kind=EvidenceKind.RAW, data=evidence_data),),
    )


@register_scanner
class WebComponents:
    """Flag fingerprinted URL technologies whose versions match known CVEs."""

    name = "web.components"
    asset_types = frozenset({AssetType.URL})
    queue = "passive"
    requires_verification = False
    timeout_seconds = 30.0
    grant = ScannerGrant()

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        if ctx.runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        findings: list[RawFinding] = []
        for name, version in _extract_versioned_technologies(ctx.target_details):
            cpes, vulns = _match_component(ctx, name, version)
            if not vulns:
                continue
            findings.append(_component_finding(asset, name, version, cpes, vulns))
        return ScanOutput(findings=tuple(findings))
