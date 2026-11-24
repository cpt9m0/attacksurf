"""Unit tests for `web.tls` certificate and protocol scanner (#76)."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Confidence, EvidenceKind, Severity
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import (
    ScannerRuntime,
    TlsCertificate,
    TlsError,
    TlsInspection,
    TlsValidation,
)
from attacksurf.domain.scanners import AssetRef, ScanContext, ScannerError
from attacksurf.domain.scope import ScopeError
from attacksurf.scanners.web.tls import WebTls, evaluate_tls_inspection
from attacksurf.services.scan_results import _evidence_digest

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


class _StubDns:
    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        return ("93.184.216.34",)

    def resolve_name(self, host: str) -> tuple[str, ...]:
        return ("93.184.216.34",)

    def lookup_many(self, queries: object) -> tuple[()]:
        return ()


class _StubHttp:
    def get(self, url: str, *, limit: int) -> object:
        raise AssertionError("web.tls must not make HTTP requests")

    def close(self) -> None:
        pass


class _StubTls:
    def __init__(self, outcome: TlsInspection | Exception) -> None:
        self._outcome = outcome
        self.calls: list[tuple[str, int, bool]] = []

    def inspect(self, host: str, port: int = 443, *, probe_legacy: bool = False) -> TlsInspection:
        self.calls.append((host, port, probe_legacy))
        if isinstance(self._outcome, Exception):
            raise self._outcome
        return self._outcome


def _cert(
    *,
    subject: str = "CN=acme.example",
    issuer: str = "CN=Example CA",
    sans: tuple[str, ...] = ("acme.example",),
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    key_type: str = "RSA",
    key_size: int | None = 2048,
    key_curve: str | None = None,
    signature_algorithm: str = "sha256WithRSAEncryption",
    signature_hash: str | None = "sha256",
    serial_number: str = "abc123",
    is_self_signed: bool = False,
) -> TlsCertificate:
    return TlsCertificate(
        subject=subject,
        issuer=issuer,
        sans=sans,
        not_before=not_before or (NOW - timedelta(days=30)),
        not_after=not_after or (NOW + timedelta(days=90)),
        key_type=key_type,
        key_size=key_size,
        key_curve=key_curve,
        signature_algorithm=signature_algorithm,
        signature_hash=signature_hash,
        serial_number=serial_number,
        is_self_signed=is_self_signed,
    )


def _inspection(
    *,
    host: str = "acme.example",
    port: int = 443,
    address: str = "93.184.216.34",
    protocol: str = "TLSv1.3",
    cipher: str = "TLS_AES_256_GCM_SHA384",
    cipher_bits: int | None = 256,
    trusted_chain: bool = True,
    hostname_matches: bool = True,
    error_code: str | None = None,
    chain: tuple[TlsCertificate, ...] | None = None,
    legacy_protocols_accepted: tuple[str, ...] = (),
) -> TlsInspection:
    return TlsInspection(
        host=host,
        port=port,
        address=address,
        protocol=protocol,
        cipher=cipher,
        cipher_bits=cipher_bits,
        chain=(_cert(),) if chain is None else chain,
        chain_truncated=False,
        validation=TlsValidation(
            trusted_chain=trusted_chain,
            hostname_matches=hostname_matches,
            error_code=error_code,
        ),
        legacy_protocols_accepted=legacy_protocols_accepted,
        legacy_protocols_untested=(),
    )


def _ctx(tls: _StubTls | None) -> ScanContext:
    runtime = ScannerRuntime(_StubDns(), _StubHttp(), tls=tls) if tls is not None else None  # type: ignore[arg-type]
    return ScanContext(
        org_id=uuid4(),
        scan_id=uuid4(),
        root_asset=AssetRef(type=AssetType.DOMAIN, value="acme.example"),
        profile="web_active",
        runtime=runtime,
    )


def test_web_tls_requires_runtime() -> None:
    with pytest.raises(ScannerError, match="runtime"):
        WebTls().run(_ctx(None), AssetRef(type=AssetType.URL, value="https://acme.example/"))


def test_web_tls_clean_fixture_emits_no_findings_and_records_tls_details() -> None:
    tls = _StubTls(_inspection(chain=(_cert(key_type="EC", key_size=256, key_curve="secp256r1"),)))
    url_ref = AssetRef(type=AssetType.URL, value="https://acme.example/app")

    out = WebTls(clock=lambda: NOW).run(_ctx(tls), url_ref)

    assert tls.calls == [("acme.example", 443, True)]
    assert out.findings == ()
    assert len(out.observations) == 1
    tls_details = out.observations[0].details["tls"]
    assert isinstance(tls_details, dict)
    assert tls_details["protocol"] == "TLSv1.3"
    assert tls_details["trusted_chain"] is True
    assert tls_details["hostname_matches"] is True
    assert tls_details["key_type"] == "EC"


def test_web_tls_flags_expired_ca_cert_without_false_untrusted_finding() -> None:
    expired = _cert(not_after=NOW - timedelta(days=2), is_self_signed=False)
    insp = _inspection(trusted_chain=False, error_code="certificate_expired", chain=(expired,))

    findings = evaluate_tls_inspection(
        AssetRef(type=AssetType.URL, value="https://acme.example/"), insp, now=NOW
    )

    assert [f.rule_id for f in findings] == ["web.tls.cert_expired"]
    assert findings[0].severity is Severity.HIGH
    assert findings[0].confidence is Confidence.HIGH
    assert findings[0].evidence[0].kind is EvidenceKind.RAW
    ev_json = findings[0].evidence[0].model_dump_json()
    assert "BEGIN " + "PRIVATE KEY" not in ev_json
    assert set(findings[0].evidence[0].data) == {
        "host",
        "port",
        "protocol",
        "cipher",
        "cipher_bits",
        "validation",
        "legacy_protocols_accepted",
        "legacy_protocols_untested",
        "chain_truncated",
        "chain",
    }


@pytest.mark.parametrize(
    ("days_left", "expected_severity"),
    [(20, Severity.MEDIUM), (7, Severity.HIGH), (2, Severity.HIGH)],
)
def test_web_tls_flags_cert_expiring_with_critical_threshold(
    days_left: int, expected_severity: Severity
) -> None:
    expiring = _cert(not_after=NOW + timedelta(days=days_left))
    insp = _inspection(chain=(expiring,))

    findings = evaluate_tls_inspection(
        AssetRef(type=AssetType.URL, value="https://acme.example/"), insp, now=NOW
    )

    assert [(f.rule_id, f.severity) for f in findings] == [
        ("web.tls.cert_expiring", expected_severity)
    ]
    assert findings[0].remediation_context["days_remaining"] == str(days_left)


def test_web_tls_flags_hostname_mismatch() -> None:
    insp = _inspection(
        trusted_chain=True,
        hostname_matches=False,
        error_code="hostname_mismatch",
        chain=(_cert(sans=("other.example",)),),
    )

    findings = evaluate_tls_inspection(
        AssetRef(type=AssetType.URL, value="https://acme.example/"), insp, now=NOW
    )

    assert [(f.rule_id, f.severity) for f in findings] == [
        ("web.tls.hostname_mismatch", Severity.HIGH)
    ]


@pytest.mark.parametrize(
    ("error_code", "self_signed"),
    [("self_signed_certificate", True), ("untrusted_chain", False)],
)
def test_web_tls_flags_untrusted_chain(error_code: str, self_signed: bool) -> None:
    insp = _inspection(
        trusted_chain=False,
        hostname_matches=True,
        error_code=error_code,
        chain=(_cert(is_self_signed=self_signed),),
    )

    findings = evaluate_tls_inspection(
        AssetRef(type=AssetType.URL, value="https://acme.example/"), insp, now=NOW
    )

    assert [(f.rule_id, f.severity) for f in findings] == [
        ("web.tls.untrusted_chain", Severity.HIGH)
    ]


@pytest.mark.parametrize(
    ("cert_kwargs", "expected_weak"),
    [
        ({"key_type": "RSA", "key_size": 1024}, True),
        ({"key_type": "DSA", "key_size": 2048}, True),
        ({"key_type": "EC", "key_size": 192, "key_curve": "secp192r1"}, True),
        ({"key_type": "Ed25519", "key_size": 256, "key_curve": None}, False),
        ({"key_type": "RSA", "key_size": 2048}, False),
    ],
)
def test_web_tls_flags_weak_keys(cert_kwargs: dict[str, object], expected_weak: bool) -> None:
    insp = _inspection(chain=(_cert(**cert_kwargs),))  # type: ignore[arg-type]

    findings = evaluate_tls_inspection(
        AssetRef(type=AssetType.URL, value="https://acme.example/"), insp, now=NOW
    )

    rule_ids = [f.rule_id for f in findings]
    if expected_weak:
        assert rule_ids == ["web.tls.weak_key"]
        assert findings[0].severity is Severity.HIGH
    else:
        assert rule_ids == []


def test_web_tls_flags_weak_signature_on_leaf_or_intermediate_but_ignores_root_ca() -> None:
    sha1_leaf = _cert(signature_algorithm="sha1WithRSAEncryption", signature_hash="sha1")
    leaf_findings = evaluate_tls_inspection(
        AssetRef(type=AssetType.URL, value="https://acme.example/"),
        _inspection(chain=(sha1_leaf,)),
        now=NOW,
    )
    assert [(f.rule_id, f.severity) for f in leaf_findings] == [
        ("web.tls.weak_signature", Severity.HIGH)
    ]

    # SHA-1 self-signed root CA at index 1 is ignored per RFC/browser practice.
    strong_leaf = _cert()
    sha1_root = _cert(
        subject="CN=Legacy Root CA",
        issuer="CN=Legacy Root CA",
        is_self_signed=True,
        signature_algorithm="sha1WithRSAEncryption",
        signature_hash="sha1",
    )
    root_findings = evaluate_tls_inspection(
        AssetRef(type=AssetType.URL, value="https://acme.example/"),
        _inspection(chain=(strong_leaf, sha1_root)),
        now=NOW,
    )
    assert root_findings == ()


def test_web_tls_flags_legacy_protocol() -> None:
    insp = _inspection(legacy_protocols_accepted=("TLSv1", "TLSv1.1"))

    findings = evaluate_tls_inspection(
        AssetRef(type=AssetType.URL, value="https://acme.example/"), insp, now=NOW
    )

    assert [(f.rule_id, f.severity) for f in findings] == [
        ("web.tls.legacy_protocol", Severity.MEDIUM)
    ]
    assert findings[0].remediation_context["protocols"] == "TLSv1, TLSv1.1"


def test_web_tls_skips_http_or_unreachable_and_keeps_digest_stable_across_ip_and_days() -> None:
    tls = _StubTls(_inspection())
    assert WebTls(clock=lambda: NOW).run(
        _ctx(tls), AssetRef(type=AssetType.URL, value="http://acme.example/")
    ) == WebTls(clock=lambda: NOW).run(
        _ctx(tls), AssetRef(type=AssetType.URL, value="https://acme.example:9443/")
    )
    assert tls.calls == []

    err_out = WebTls(clock=lambda: NOW).run(
        _ctx(_StubTls(TlsError("reset"))),
        AssetRef(type=AssetType.URL, value="https://acme.example/"),
    )
    assert err_out.observations == ()
    assert err_out.findings == ()

    with pytest.raises(TransientJobError, match="rate"):
        WebTls(clock=lambda: NOW).run(
            _ctx(_StubTls(TransientJobError("rate"))),
            AssetRef(type=AssetType.URL, value="https://acme.example/"),
        )

    expiring = _cert(not_after=NOW + timedelta(days=20))
    f1 = evaluate_tls_inspection(
        AssetRef(type=AssetType.URL, value="https://acme.example/"),
        _inspection(address="93.184.216.34", chain=(expiring,)),
        now=NOW,
    )
    f2 = evaluate_tls_inspection(
        AssetRef(type=AssetType.URL, value="https://acme.example/"),
        _inspection(address="203.0.113.99", chain=(expiring,)),
        now=NOW + timedelta(days=1),
    )
    assert _evidence_digest(f1[0].evidence) == _evidence_digest(f2[0].evidence)
    with pytest.raises(ScannerError):
        WebTls().run(
            ScanContext(
                uuid4(),
                uuid4(),
                AssetRef(type=AssetType.DOMAIN, value="acme.example"),
                "web_active",
            ),
            AssetRef(type=AssetType.URL, value="https://acme.example/"),
        )
    # ScopeError on handshake is also swallowed cleanly.
    assert (
        WebTls(clock=lambda: NOW)
        .run(
            _ctx(_StubTls(ScopeError("timeout"))),
            AssetRef(type=AssetType.URL, value="https://acme.example/"),
        )
        .findings
        == ()
    )
