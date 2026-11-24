"""Guarded TLS adapter tests: pinning, SNI, non-raising validation, chain caps, legacy probes."""

from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import ssl
import tempfile
import threading
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import TlsError
from attacksurf.domain.scope import AddressError, ScopeError
from attacksurf.infra.rate_limit import InMemoryTargetRateLimiter, TargetRateLimitPolicy
from attacksurf.infra.tls import (
    MAX_CHAIN_CERTS,
    MAX_CHAIN_DER_BYTES,
    LegacyProbeUnsupported,
    RawTlsHandshake,
    SafeTlsClient,
    SocketTlsConnector,
)


class StaticResolver:
    def __init__(self, *answers: str) -> None:
        self.answers = answers
        self.calls: list[str] = []

    def resolve_name(self, host: str) -> tuple[str, ...]:
        self.calls.append(host)
        return self.answers


class FakeTlsConnector:
    def __init__(self, outcomes: list[RawTlsHandshake | Exception] | None = None) -> None:
        self.outcomes = list(outcomes or [])
        self.calls: list[dict[str, object]] = []

    def handshake(
        self,
        *,
        address: str,
        port: int,
        server_hostname: str,
        verify: bool,
        timeout: float,
        min_version: ssl.TLSVersion | None = None,
        max_version: ssl.TLSVersion | None = None,
    ) -> RawTlsHandshake:
        self.calls.append(
            {
                "address": address,
                "port": port,
                "server_hostname": server_hostname,
                "verify": verify,
                "timeout": timeout,
                "min_version": min_version,
                "max_version": max_version,
            }
        )
        assert self.outcomes, "FakeTlsConnector had no queued outcome"
        item = self.outcomes.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _make_cert(
    *,
    cn: str = "acme.example",
    issuer_cn: str = "Example CA",
    sans: tuple[str, ...] = ("acme.example", "www.acme.example"),
    ip_sans: tuple[str, ...] = (),
    days_before: int = -1,
    days_after: int = 90,
    key_kind: str = "rsa2048",
) -> tuple[bytes, bytes, bytes]:
    """Return (der_bytes, pem_cert_bytes, pem_key_bytes)."""
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
    if key_kind == "rsa1024":
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 - fixture tests weak key detection
    elif key_kind == "ec256":
        key = ec.generate_private_key(ec.SECP256R1())
    elif key_kind == "ed25519":
        key = ed25519.Ed25519PrivateKey.generate()
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = dt.datetime.now(dt.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + dt.timedelta(days=days_before))
        .not_valid_after(now + dt.timedelta(days=days_after))
    )
    san_entries: list[x509.GeneralName] = [x509.DNSName(name) for name in sans]
    san_entries.extend(x509.IPAddress(ipaddress.ip_address(ip)) for ip in ip_sans)
    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    if isinstance(key, ed25519.Ed25519PrivateKey):
        signed = builder.sign(key, None)
    else:
        signed = builder.sign(key, hashes.SHA256())

    der = signed.public_bytes(serialization.Encoding.DER)
    pem_cert = signed.public_bytes(serialization.Encoding.PEM)
    pem_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return der, pem_cert, pem_key


def test_valid_certificate_pins_ipv4_preserves_sni_and_parses_metadata() -> None:
    leaf_der, _, _ = _make_cert(
        cn="acme.example",
        issuer_cn="Trusted Root",
        sans=("acme.example", "*.acme.example"),
        ip_sans=("93.184.216.34",),
        key_kind="ec256",
    )
    intermediate_der, _, _ = _make_cert(
        cn="Trusted Intermediate", issuer_cn="Trusted Root", sans=()
    )
    connector = FakeTlsConnector(
        [
            RawTlsHandshake(
                protocol="TLSv1.3",
                cipher_name="TLS_AES_256_GCM_SHA384",
                cipher_bits=256,
                chain_der=(leaf_der, intermediate_der),
                verified=True,
            )
        ]
    )
    resolver = StaticResolver("2606:4700::1111", "93.184.216.34")
    client = SafeTlsClient(resolver, connector=connector, timeout_seconds=4.0)

    info = client.inspect("Acme.EXAMPLE.", port=8443)

    assert resolver.calls == ["acme.example"]
    assert len(connector.calls) == 1
    assert connector.calls[0]["address"] == "93.184.216.34"
    assert connector.calls[0]["port"] == 8443
    assert connector.calls[0]["server_hostname"] == "acme.example"
    assert connector.calls[0]["verify"] is True
    assert connector.calls[0]["timeout"] == 4.0

    assert info.protocol == "TLSv1.3"
    assert info.cipher == "TLS_AES_256_GCM_SHA384"
    assert info.cipher_bits == 256
    assert info.validation.trusted_chain is True
    assert info.validation.hostname_matches is True
    assert info.validation.error_code is None
    assert info.chain_truncated is False
    assert len(info.chain) == 2
    assert info.chain[0].key_type == "EC"
    assert info.chain[0].key_size == 256
    assert info.chain[0].key_curve == "secp256r1"
    assert info.chain[0].signature_hash == "sha256"
    assert "acme.example" in info.chain[0].sans
    assert "93.184.216.34" in info.chain[0].sans
    assert info.chain[0].is_self_signed is False


@pytest.mark.parametrize(
    ("verify_code", "verify_reason", "expected_error", "expected_trusted", "expected_host_match"),
    [
        (10, "certificate has expired", "certificate_expired", False, True),
        (9, "certificate is not yet valid", "certificate_not_yet_valid", False, True),
        (18, "self-signed certificate", "self_signed_certificate", False, True),
        (20, "unable to get local issuer certificate", "untrusted_chain", False, True),
        (62, "Hostname mismatch", "hostname_mismatch", True, False),
        (None, "certificate has expired", "certificate_expired", False, True),
        (None, "unknown failure", "verification_failed", False, True),
    ],
)
def test_bad_certificates_are_reported_not_raised(
    verify_code: int | None,
    verify_reason: str | None,
    expected_error: str,
    expected_trusted: bool,
    expected_host_match: bool,
) -> None:
    der, _, _ = _make_cert(
        cn="acme.example",
        issuer_cn="acme.example",
        sans=("acme.example",),
        key_kind="rsa1024",
    )
    connector = FakeTlsConnector(
        [
            RawTlsHandshake(
                protocol="",
                cipher_name="",
                cipher_bits=None,
                chain_der=(),
                verified=False,
                verify_code=verify_code,
                verify_reason=verify_reason,
            ),
            RawTlsHandshake(
                protocol="TLSv1.2",
                cipher_name="ECDHE-RSA-AES128-GCM-SHA256",
                cipher_bits=128,
                chain_der=(der,),
                verified=False,
            ),
        ]
    )
    client = SafeTlsClient(StaticResolver("93.184.216.34"), connector=connector)

    info = client.inspect("acme.example")

    assert [c["verify"] for c in connector.calls] == [True, False]
    assert info.validation.trusted_chain is expected_trusted
    assert info.validation.hostname_matches is expected_host_match
    assert info.validation.error_code == expected_error
    assert info.chain[0].key_type == "RSA"
    assert info.chain[0].key_size == 1024
    assert info.chain[0].signature_hash == "sha256"
    assert info.chain[0].is_self_signed is True


@pytest.mark.parametrize(
    ("sans", "cn", "host", "expected_match"),
    [
        (("*.acme.example",), "ignored", "www.acme.example", True),
        (("*.acme.example",), "ignored", "a.b.acme.example", False),
        (("*.acme.example",), "ignored", "acme.example", False),
        (("other.example",), "acme.example", "acme.example", False),  # SAN takes precedence over CN
        ((), "acme.example", "acme.example", True),
        ((), "other.example", "acme.example", False),
    ],
)
def test_hostname_matching_follows_rfc_6125(
    sans: tuple[str, ...], cn: str, host: str, expected_match: bool
) -> None:
    der, _, _ = _make_cert(cn=cn, issuer_cn=cn, sans=sans)
    connector = FakeTlsConnector(
        [
            RawTlsHandshake("", "", None, (), verified=False, verify_code=18),
            RawTlsHandshake("TLSv1.3", "TLS_AES_128_GCM_SHA256", 128, (der,), verified=False),
        ]
    )
    client = SafeTlsClient(StaticResolver("93.184.216.34"), connector=connector)

    info = client.inspect(host)

    assert info.validation.hostname_matches is expected_match


def test_chain_exceeding_cert_count_or_bytes_is_truncated_safely() -> None:
    der, _, _ = _make_cert(key_kind="ed25519")
    many_certs = tuple(der for _ in range(MAX_CHAIN_CERTS + 3))
    connector = FakeTlsConnector(
        [RawTlsHandshake("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, many_certs, verified=True)]
    )
    client = SafeTlsClient(StaticResolver("93.184.216.34"), connector=connector)

    info = client.inspect("acme.example")

    assert info.chain_truncated is True
    assert len(info.chain) == MAX_CHAIN_CERTS
    assert info.chain[0].key_type == "Ed25519"

    # Also test cumulative DER byte cap.
    big_count = (MAX_CHAIN_DER_BYTES // len(der)) + 2
    if big_count <= MAX_CHAIN_CERTS:
        connector2 = FakeTlsConnector(
            [
                RawTlsHandshake(
                    "TLSv1.3",
                    "TLS_AES_256_GCM_SHA384",
                    256,
                    tuple(der for _ in range(big_count)),
                    verified=True,
                )
            ]
        )
        info2 = SafeTlsClient(StaticResolver("93.184.216.34"), connector=connector2).inspect(
            "acme.example"
        )
        assert info2.chain_truncated is True


def test_invalid_der_raises_tls_error() -> None:
    connector = FakeTlsConnector(
        [RawTlsHandshake("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, (b"not-der",), verified=True)]
    )
    client = SafeTlsClient(StaticResolver("93.184.216.34"), connector=connector)

    with pytest.raises(TlsError, match="parsed"):
        client.inspect("acme.example")


def test_legacy_protocol_probing_records_accepted_and_untested_versions() -> None:
    der, _, _ = _make_cert()
    connector = FakeTlsConnector(
        [
            RawTlsHandshake("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, (der,), verified=True),
            RawTlsHandshake("TLSv1", "ECDHE-RSA-AES128-SHA", 128, (der,), verified=False),
            LegacyProbeUnsupported(),
        ]
    )
    client = SafeTlsClient(StaticResolver("93.184.216.34"), connector=connector)

    info = client.inspect("acme.example", probe_legacy=True)

    assert info.legacy_protocols_accepted == ("TLSv1",)
    assert info.legacy_protocols_untested == ("TLSv1.1",)
    assert connector.calls[1]["min_version"] == ssl.TLSVersion.TLSv1
    assert connector.calls[2]["min_version"] == ssl.TLSVersion.TLSv1_1


def test_rate_limiter_is_enforced_per_handshake_and_propagates_transient_error() -> None:
    der, _, _ = _make_cert()
    limiter = InMemoryTargetRateLimiter(
        TargetRateLimitPolicy(rps=1.0, burst=1, max_concurrency=1, max_wait_seconds=0.0)
    )
    connector = FakeTlsConnector(
        [
            RawTlsHandshake("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, (der,), verified=True),
            RawTlsHandshake("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, (der,), verified=True),
        ]
    )
    client = SafeTlsClient(
        StaticResolver("93.184.216.34"),
        connector=connector,
        rate_limiter=limiter,
        rate_limit_org_id=uuid4(),
    )

    client.inspect("acme.example")
    with pytest.raises(TransientJobError, match="rate limit"):
        client.inspect("acme.example")


def test_empty_or_unresolved_host_is_rejected() -> None:
    client = SafeTlsClient(StaticResolver(), connector=FakeTlsConnector())
    with pytest.raises(ScopeError, match="no host"):
        client.inspect("   ")
    with pytest.raises(AddressError, match="did not resolve"):
        client.inspect("acme.example")


def test_socket_tls_connector_reports_self_signed_and_reads_unverified_leaf() -> None:
    _der, pem_cert, pem_key = _make_cert(cn="localhost", issuer_cn="localhost", sans=("localhost",))
    with tempfile.TemporaryDirectory() as tmp:
        cert_file = Path(tmp) / "cert.pem"
        key_file = Path(tmp) / "key.pem"
        cert_file.write_bytes(pem_cert)
        key_file.write_bytes(pem_key)

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        port = listener.getsockname()[1]
        stop = threading.Event()

        def serve() -> None:
            listener.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except TimeoutError:
                    continue
                try:
                    with server_ctx.wrap_socket(conn, server_side=True) as tls_conn:
                        tls_conn.recv(1)
                except OSError:
                    pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            client = SafeTlsClient(StaticResolver("127.0.0.1"), connector=SocketTlsConnector())
            info = client.inspect("localhost", port=port)
            assert info.validation.trusted_chain is False
            assert info.validation.error_code == "self_signed_certificate"
            assert info.validation.hostname_matches is True
            assert len(info.chain) == 1
            assert info.chain[0].is_self_signed is True
            assert info.protocol.startswith("TLS")
        finally:
            stop.set()
            thread.join(timeout=2)
            listener.close()
