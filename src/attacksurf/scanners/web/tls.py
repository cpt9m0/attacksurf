"""Active TLS certificate and protocol configuration scanner (`web.tls`, #76)."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from pydantic import JsonValue

from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Confidence, EvidenceKind, Severity
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError, TlsCertificate, TlsError, TlsInspection
from attacksurf.domain.scanners import (
    AssetObservation,
    AssetRef,
    RawEvidence,
    RawFinding,
    ScanContext,
    ScannerError,
    ScannerGrant,
    ScanOutput,
)
from attacksurf.domain.scope import ScopeError
from attacksurf.scanners.registry import register_scanner

TLS_PORTS = frozenset({443, 8000, 8080, 8443, 8888})
DEFAULT_HTTPS_PORT = 443
DNS_LOOKUPS = 4
EXPIRING_SOON_DAYS = 30
EXPIRING_CRITICAL_DAYS = 7
MIN_RSA_KEY_BITS = 2048
MIN_EC_KEY_BITS = 256
STRONG_EC_CURVES = frozenset({"secp256r1", "prime256v1", "secp384r1", "secp521r1"})
WEAK_SIGNATURE_HASHES = frozenset({"md2", "md4", "md5", "sha1", "sha-1"})
WEAK_SIG_SUBSTRINGS = ("sha1", "md5", "md4", "md2")
LEGACY_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"})
MAX_EVIDENCE_SANS = 20
MAX_DETAILS_SANS = 10
MAX_DETAIL_DN_CHARS = 256


def _serialize_cert(cert: TlsCertificate, *, san_limit: int) -> dict[str, JsonValue]:
    return {
        "subject": cert.subject[:MAX_DETAIL_DN_CHARS],
        "issuer": cert.issuer[:MAX_DETAIL_DN_CHARS],
        "not_before": cert.not_before.isoformat(),
        "not_after": cert.not_after.isoformat(),
        "key_type": cert.key_type,
        "key_size": cert.key_size,
        "key_curve": cert.key_curve,
        "signature_algorithm": cert.signature_algorithm,
        "signature_hash": cert.signature_hash,
        "serial_number": cert.serial_number,
        "is_self_signed": cert.is_self_signed,
        "sans": list(cert.sans[:san_limit]),
    }


def build_tls_evidence(inspection: TlsInspection) -> RawEvidence:
    """Build deterministic parsed-chain summary evidence (omits IP address & private data)."""
    return RawEvidence(
        kind=EvidenceKind.RAW,
        data={
            "host": inspection.host,
            "port": inspection.port,
            "protocol": inspection.protocol,
            "cipher": inspection.cipher,
            "cipher_bits": inspection.cipher_bits,
            "validation": {
                "trusted_chain": inspection.validation.trusted_chain,
                "hostname_matches": inspection.validation.hostname_matches,
                "error_code": inspection.validation.error_code,
            },
            "legacy_protocols_accepted": list(inspection.legacy_protocols_accepted),
            "legacy_protocols_untested": list(inspection.legacy_protocols_untested),
            "chain_truncated": inspection.chain_truncated,
            "chain": [
                _serialize_cert(cert, san_limit=MAX_EVIDENCE_SANS) for cert in inspection.chain
            ],
        },
    )


def _tls_details(inspection: TlsInspection) -> dict[str, JsonValue]:
    leaf = inspection.chain[0] if inspection.chain else None
    details: dict[str, JsonValue] = {
        "host": inspection.host,
        "port": inspection.port,
        "protocol": inspection.protocol,
        "cipher": inspection.cipher,
        "cipher_bits": inspection.cipher_bits,
        "trusted_chain": inspection.validation.trusted_chain,
        "hostname_matches": inspection.validation.hostname_matches,
        "error_code": inspection.validation.error_code,
        "legacy_protocols_accepted": list(inspection.legacy_protocols_accepted),
        "legacy_protocols_untested": list(inspection.legacy_protocols_untested),
        "chain_length": len(inspection.chain),
        "chain_truncated": inspection.chain_truncated,
    }
    if leaf is not None:
        details.update(
            {
                "subject": leaf.subject[:MAX_DETAIL_DN_CHARS],
                "issuer": leaf.issuer[:MAX_DETAIL_DN_CHARS],
                "not_before": leaf.not_before.isoformat(),
                "not_after": leaf.not_after.isoformat(),
                "key_type": leaf.key_type,
                "key_size": leaf.key_size,
                "key_curve": leaf.key_curve,
                "signature_hash": leaf.signature_hash,
                "sans": list(leaf.sans[:MAX_DETAILS_SANS]),
            }
        )
    return details


def _weak_key_reason(cert: TlsCertificate) -> str | None:
    if cert.key_type == "RSA":
        if cert.key_size is not None and cert.key_size < MIN_RSA_KEY_BITS:
            return f"RSA-{cert.key_size}"
        return None
    if cert.key_type == "DSA":
        return f"DSA-{cert.key_size}" if cert.key_size else "DSA"
    if cert.key_type == "EC":
        curve = (cert.key_curve or "").lower()
        if cert.key_size is not None and cert.key_size < MIN_EC_KEY_BITS:
            return f"EC {cert.key_curve or cert.key_size}"
        if curve and curve not in STRONG_EC_CURVES:
            return f"EC {cert.key_curve}"
    return None


def _weak_signature_reason(cert: TlsCertificate) -> str | None:
    sig_hash = (cert.signature_hash or "").strip().lower()
    if sig_hash in WEAK_SIGNATURE_HASHES:
        return cert.signature_hash or sig_hash
    sig_alg = cert.signature_algorithm.strip().lower()
    if any(token in sig_alg for token in WEAK_SIG_SUBSTRINGS):
        return cert.signature_algorithm
    return None


def _checked_chain_certs(inspection: TlsInspection) -> list[tuple[int, TlsCertificate]]:
    """Leaf always checked; intermediates checked unless self-signed root CA."""
    return [
        (idx, cert)
        for idx, cert in enumerate(inspection.chain)
        if idx == 0 or not cert.is_self_signed
    ]


def _expiry_finding(
    asset: AssetRef,
    inspection: TlsInspection,
    evidence: RawEvidence,
    *,
    now: datetime,
) -> RawFinding | None:
    port_str = str(inspection.port)
    expired_certs = [cert for cert in inspection.chain if cert.not_after <= now]
    if expired_certs:
        return RawFinding(
            asset=asset,
            rule_id="web.tls.cert_expired",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            remediation_context={
                "host": inspection.host,
                "port": port_str,
                "not_after": expired_certs[0].not_after.isoformat(),
            },
            evidence=(evidence,),
        )
    leaf = inspection.chain[0] if inspection.chain else None
    if leaf is None:
        if inspection.validation.error_code == "certificate_expired":
            return RawFinding(
                asset=asset,
                rule_id="web.tls.cert_expired",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                remediation_context={
                    "host": inspection.host,
                    "port": port_str,
                    "not_after": "unknown",
                },
                evidence=(evidence,),
            )
        return None
    remaining = leaf.not_after - now
    if remaining <= timedelta(days=EXPIRING_SOON_DAYS):
        severity = (
            Severity.HIGH
            if remaining <= timedelta(days=EXPIRING_CRITICAL_DAYS)
            else Severity.MEDIUM
        )
        return RawFinding(
            asset=asset,
            rule_id="web.tls.cert_expiring",
            severity=severity,
            confidence=Confidence.HIGH,
            remediation_context={
                "host": inspection.host,
                "port": port_str,
                "days_remaining": str(max(0, remaining.days)),
                "not_after": leaf.not_after.isoformat(),
            },
            evidence=(evidence,),
        )
    return None


def _chain_trust_findings(
    asset: AssetRef,
    inspection: TlsInspection,
    evidence: RawEvidence,
    *,
    cert_expired_emitted: bool,
) -> list[RawFinding]:
    findings: list[RawFinding] = []
    port_str = str(inspection.port)
    leaf = inspection.chain[0] if inspection.chain else None
    if not inspection.validation.hostname_matches and (
        leaf is not None or inspection.validation.error_code == "hostname_mismatch"
    ):
        findings.append(
            RawFinding(
                asset=asset,
                rule_id="web.tls.hostname_mismatch",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                remediation_context={"host": inspection.host, "port": port_str},
                evidence=(evidence,),
            )
        )
    suppressed_by_expiry = (
        inspection.validation.error_code == "certificate_expired"
        and cert_expired_emitted
        and not (leaf is not None and leaf.is_self_signed)
    )
    if not inspection.validation.trusted_chain and not suppressed_by_expiry:
        findings.append(
            RawFinding(
                asset=asset,
                rule_id="web.tls.untrusted_chain",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                remediation_context={
                    "host": inspection.host,
                    "port": port_str,
                    "error_code": inspection.validation.error_code or "untrusted_chain",
                },
                evidence=(evidence,),
            )
        )
    return findings


def _crypto_findings(
    asset: AssetRef, inspection: TlsInspection, evidence: RawEvidence
) -> list[RawFinding]:
    findings: list[RawFinding] = []
    port_str = str(inspection.port)
    weak_keys = [
        f"cert[{idx}] ({reason})"
        for idx, cert in _checked_chain_certs(inspection)
        if (reason := _weak_key_reason(cert)) is not None
    ]
    if weak_keys:
        findings.append(
            RawFinding(
                asset=asset,
                rule_id="web.tls.weak_key",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                remediation_context={
                    "host": inspection.host,
                    "port": port_str,
                    "details": ", ".join(weak_keys),
                },
                evidence=(evidence,),
            )
        )
    weak_sigs = [
        f"cert[{idx}] ({reason})"
        for idx, cert in _checked_chain_certs(inspection)
        if (reason := _weak_signature_reason(cert)) is not None
    ]
    if weak_sigs:
        findings.append(
            RawFinding(
                asset=asset,
                rule_id="web.tls.weak_signature",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                remediation_context={
                    "host": inspection.host,
                    "port": port_str,
                    "details": ", ".join(weak_sigs),
                },
                evidence=(evidence,),
            )
        )
    return findings


def evaluate_tls_inspection(
    asset: AssetRef,
    inspection: TlsInspection,
    *,
    now: datetime | None = None,
) -> tuple[RawFinding, ...]:
    """Evaluate all TLS rules against a completed `TlsInspection`."""
    current = (now or datetime.now(UTC)).astimezone(UTC)
    evidence = build_tls_evidence(inspection)
    findings: list[RawFinding] = []

    expiry = _expiry_finding(asset, inspection, evidence, now=current)
    cert_expired_emitted = expiry is not None and expiry.rule_id == "web.tls.cert_expired"
    if expiry is not None:
        findings.append(expiry)
    findings.extend(
        _chain_trust_findings(
            asset, inspection, evidence, cert_expired_emitted=cert_expired_emitted
        )
    )
    findings.extend(_crypto_findings(asset, inspection, evidence))

    legacy = list(inspection.legacy_protocols_accepted)
    if inspection.protocol in LEGACY_PROTOCOLS and inspection.protocol not in legacy:
        legacy.append(inspection.protocol)
    if legacy:
        findings.append(
            RawFinding(
                asset=asset,
                rule_id="web.tls.legacy_protocol",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                remediation_context={
                    "host": inspection.host,
                    "port": str(inspection.port),
                    "protocols": ", ".join(legacy),
                },
                evidence=(evidence,),
            )
        )
    return tuple(findings)


def _target_host_port(asset: AssetRef, allowed_ports: frozenset[int]) -> tuple[str, int] | None:
    if asset.type in {AssetType.DOMAIN, AssetType.SUBDOMAIN}:
        host = asset.value.strip().lower().rstrip(".")
        return (host, DEFAULT_HTTPS_PORT) if host else None
    if asset.type is AssetType.URL:
        parts = urlsplit(asset.value)
        if parts.scheme != "https" or not parts.hostname:
            return None
        try:
            port = parts.port if parts.port is not None else DEFAULT_HTTPS_PORT
        except ValueError:
            return None
        if port not in allowed_ports:
            return None
        return parts.hostname.strip().lower().rstrip("."), port
    return None


@register_scanner
class WebTls:
    """Inspect TLS certificates, chain trust, and legacy protocols on verified web hosts."""

    name = "web.tls"
    asset_types = frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.URL})
    queue = "active"
    requires_verification = True
    timeout_seconds = 30.0
    grant = ScannerGrant(tls=True, tls_ports=TLS_PORTS, dns_lookups=DNS_LOOKUPS)

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        if ctx.runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        target = _target_host_port(asset, self.grant.tls_ports)
        if target is None:
            return ScanOutput()
        host, port = target
        try:
            inspection = ctx.runtime.tls.inspect(host, port, probe_legacy=True)
        except (TlsError, DnsError, ScopeError) as exc:
            # Preserve existing findings on failure: raise a retryable error whenever TLS was
            # expected (URL asset, prior `tls` details, DNS error, or handshake timeout) so
            # `scan_diff._fix` never closes prior findings without a completed inspection.
            prior_tls = bool(ctx.target_details.get("tls"))
            timed_out = isinstance(exc, ScopeError) and "timed out" in str(exc).lower()
            if asset.type is AssetType.URL or prior_tls or isinstance(exc, DnsError) or timed_out:
                raise TransientJobError("TLS inspection failed.") from None
            return ScanOutput()

        findings = evaluate_tls_inspection(asset, inspection, now=self._clock())
        observation = AssetObservation(asset=asset, details={"tls": _tls_details(inspection)})
        return ScanOutput(observations=(observation,), findings=findings)
