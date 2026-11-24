"""Guarded TLS handshake adapter: IP pinning, SNI, bounded chain reading, non-raising validation."""

from __future__ import annotations

import socket
import ssl
import warnings
from collections.abc import Callable, Iterable
from contextlib import nullcontext, suppress
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from attacksurf.domain.net import (
    TargetRateLimiter,
    TlsCertificate,
    TlsError,
    TlsInspection,
    TlsInspector,
    TlsValidation,
)
from attacksurf.domain.scope import ScopeError
from attacksurf.infra.http import AddressResolver, connection_address

DEFAULT_TLS_TIMEOUT_SECONDS = 5.0
MAX_CHAIN_CERTS = 10
MAX_CHAIN_DER_BYTES = 64 * 1024
MAX_SANS_PER_CERT = 100
MAX_DN_LENGTH = 512

_LEGACY_PROBE_VERSIONS: tuple[tuple[ssl.TLSVersion, str], ...] = (
    (ssl.TLSVersion.TLSv1, "TLSv1"),
    (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
)
_UNSUPPORTED_PROTOCOL_REASONS = frozenset(
    {"UNSUPPORTED_PROTOCOL", "NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE"}
)

# OpenSSL verify error codes (crypto/x509/x509_vfy.h) mapped to stable domain tokens.
_VERIFY_ERROR_CODES: dict[int, str] = {
    9: "certificate_not_yet_valid",
    10: "certificate_expired",
    18: "self_signed_certificate",
    19: "self_signed_certificate",
    20: "untrusted_chain",
    21: "untrusted_chain",
    27: "untrusted_chain",
    62: "hostname_mismatch",
    64: "hostname_mismatch",
}


class LegacyProbeUnsupported(Exception):
    """Raised when the local OpenSSL build refuses to configure or offer a legacy TLS version."""


@dataclass(frozen=True)
class RawTlsHandshake:
    protocol: str
    cipher_name: str
    cipher_bits: int | None
    chain_der: tuple[bytes, ...]
    verified: bool
    verify_code: int | None = None
    verify_reason: str | None = None


class TlsConnector(Protocol):
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
    ) -> RawTlsHandshake: ...


class SocketTlsConnector:
    """Real socket + ssl connector that dials a pinned IP while preserving SNI."""

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
        ctx = _build_ssl_context(verify=verify, min_version=min_version, max_version=max_version)
        raw_sock: socket.socket | None = None
        tls_sock: ssl.SSLSocket | None = None
        try:
            raw_sock = socket.create_connection((address, port), timeout=timeout)
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=server_hostname)
            cipher = tls_sock.cipher()
            chain_der = _read_chain_der(tls_sock, verified=verify)
            return RawTlsHandshake(
                protocol=tls_sock.version() or "",
                cipher_name=cipher[0] if cipher else "",
                cipher_bits=cipher[2] if cipher else None,
                chain_der=chain_der,
                verified=verify,
            )
        except ssl.SSLCertVerificationError as exc:
            if verify:
                return RawTlsHandshake(
                    protocol="",
                    cipher_name="",
                    cipher_bits=None,
                    chain_der=(),
                    verified=False,
                    verify_code=exc.verify_code,
                    verify_reason=exc.reason,
                )
            raise TlsError("The TLS handshake failed.") from None
        except TimeoutError:
            raise ScopeError("The TLS handshake timed out.") from None
        except ssl.SSLError as exc:
            if (
                min_version is not None
                and getattr(exc, "reason", None) in _UNSUPPORTED_PROTOCOL_REASONS
            ):
                raise LegacyProbeUnsupported() from None
            raise TlsError("The TLS handshake failed.") from None
        except OSError:
            raise TlsError("The TLS handshake failed.") from None
        finally:
            if tls_sock is not None:
                with suppress(OSError):
                    tls_sock.close()
            elif raw_sock is not None:
                with suppress(OSError):
                    raw_sock.close()


def _build_ssl_context(
    *,
    verify: bool,
    min_version: ssl.TLSVersion | None,
    max_version: ssl.TLSVersion | None,
) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        # Intentional: only used when inspecting untrusted/expired chains or probing legacy TLS
        # versions so findings can be reported instead of crashing the check.
        ctx.verify_mode = ssl.CERT_NONE
    if min_version is not None or max_version is not None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            try:
                if min_version is not None:
                    ctx.minimum_version = min_version
                if max_version is not None:
                    ctx.maximum_version = max_version
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except (ssl.SSLError, ValueError, NotImplementedError):
                raise LegacyProbeUnsupported() from None
    return ctx


def _read_chain_der(tls_sock: ssl.SSLSocket, *, verified: bool) -> tuple[bytes, ...]:
    # Python 3.13+ exposes get_verified_chain / get_unverified_chain; 3.12 yields the leaf only.
    getter_name = "get_verified_chain" if verified else "get_unverified_chain"
    getter: Callable[[], Iterable[bytes | bytearray] | None] | None = getattr(
        tls_sock, getter_name, None
    )
    raw_items: list[bytes] = []
    if callable(getter):
        chain_objs = getter() or ()
        for item in chain_objs:
            if isinstance(item, (bytes, bytearray)):
                raw_items.append(bytes(item))
            if len(raw_items) > MAX_CHAIN_CERTS:
                break
    else:
        leaf = tls_sock.getpeercert(binary_form=True)
        if leaf:
            raw_items.append(leaf)
    return tuple(raw_items)


class SafeTlsClient(TlsInspector):
    """Run-scoped TLS inspector: pins resolved public IPs, enforces limits, reports bad certs."""

    def __init__(
        self,
        resolver: AddressResolver,
        *,
        connector: TlsConnector | None = None,
        timeout_seconds: float = DEFAULT_TLS_TIMEOUT_SECONDS,
        rate_limiter: TargetRateLimiter | None = None,
        rate_limit_org_id: UUID | None = None,
    ) -> None:
        self._resolver = resolver
        self._connector: TlsConnector = connector or SocketTlsConnector()
        self._timeout = timeout_seconds
        self._rate_limiter = rate_limiter
        self._rate_limit_org_id = rate_limit_org_id

    def inspect(self, host: str, port: int = 443, *, probe_legacy: bool = False) -> TlsInspection:
        norm_host = host.strip().lower().rstrip(".")
        if not norm_host:
            raise ScopeError("The TLS target has no host.")
        address = connection_address(self._resolver.resolve_name(norm_host))

        verified_res = self._handshake(
            address=address,
            port=port,
            server_hostname=norm_host,
            verify=True,
            rate_host=norm_host,
        )
        if verified_res.verified:
            raw = verified_res
            chain, truncated, parsed_certs = _parse_chain(raw.chain_der)
            validation = TlsValidation(trusted_chain=True, hostname_matches=True, error_code=None)
        else:
            raw = self._handshake(
                address=address,
                port=port,
                server_hostname=norm_host,
                verify=False,
                rate_host=norm_host,
            )
            chain, truncated, parsed_certs = _parse_chain(raw.chain_der)
            error_code = _classify_verify_error(
                verified_res.verify_code, verified_res.verify_reason
            )
            if error_code == "hostname_mismatch":
                validation = TlsValidation(
                    trusted_chain=True,
                    hostname_matches=False,
                    error_code=error_code,
                )
            else:
                matches = (
                    _cert_matches_hostname(parsed_certs[0], norm_host) if parsed_certs else False
                )
                validation = TlsValidation(
                    trusted_chain=False,
                    hostname_matches=matches,
                    error_code=error_code,
                )

        accepted_legacy: list[str] = []
        untested_legacy: list[str] = []
        if probe_legacy:
            for version, label in _LEGACY_PROBE_VERSIONS:
                try:
                    self._handshake(
                        address=address,
                        port=port,
                        server_hostname=norm_host,
                        verify=False,
                        rate_host=norm_host,
                        min_version=version,
                        max_version=version,
                    )
                except LegacyProbeUnsupported:
                    untested_legacy.append(label)
                except (TlsError, ScopeError):
                    continue
                else:
                    accepted_legacy.append(label)

        return TlsInspection(
            host=norm_host,
            port=port,
            address=address,
            protocol=raw.protocol,
            cipher=raw.cipher_name,
            cipher_bits=raw.cipher_bits,
            chain=chain,
            chain_truncated=truncated,
            validation=validation,
            legacy_protocols_accepted=tuple(accepted_legacy),
            legacy_protocols_untested=tuple(untested_legacy),
        )

    def _handshake(
        self,
        *,
        address: str,
        port: int,
        server_hostname: str,
        verify: bool,
        rate_host: str,
        min_version: ssl.TLSVersion | None = None,
        max_version: ssl.TLSVersion | None = None,
    ) -> RawTlsHandshake:
        limiter_ctx = (
            self._rate_limiter.acquire(self._rate_limit_org_id, rate_host)
            if self._rate_limiter is not None and self._rate_limit_org_id is not None
            else nullcontext()
        )
        with limiter_ctx:
            return self._connector.handshake(
                address=address,
                port=port,
                server_hostname=server_hostname,
                verify=verify,
                timeout=self._timeout,
                min_version=min_version,
                max_version=max_version,
            )


_VERIFY_REASON_MATCHES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("expired",), "certificate_expired"),
    (("not yet valid",), "certificate_not_yet_valid"),
    (("self-signed", "self signed"), "self_signed_certificate"),
    (("hostname", "mismatch"), "hostname_mismatch"),
    (("issuer", "unable to verify", "untrusted"), "untrusted_chain"),
)


def _classify_verify_error(code: int | None, reason: str | None) -> str:
    if code is not None and code in _VERIFY_ERROR_CODES:
        return _VERIFY_ERROR_CODES[code]
    text = (reason or "").lower()
    for needles, token in _VERIFY_REASON_MATCHES:
        if any(needle in text for needle in needles):
            return token
    return "verification_failed"


def _parse_chain(
    chain_der: tuple[bytes, ...],
) -> tuple[tuple[TlsCertificate, ...], bool, tuple[x509.Certificate, ...]]:
    certs: list[TlsCertificate] = []
    parsed_x509: list[x509.Certificate] = []
    total_bytes = 0
    truncated = False

    for raw in chain_der:
        if len(certs) >= MAX_CHAIN_CERTS or total_bytes + len(raw) > MAX_CHAIN_DER_BYTES:
            truncated = True
            break
        try:
            cert = x509.load_der_x509_certificate(raw)
        except ValueError:
            raise TlsError("Peer certificate could not be parsed.") from None
        total_bytes += len(raw)
        parsed_x509.append(cert)
        certs.append(_to_tls_certificate(cert))

    return tuple(certs), truncated, tuple(parsed_x509)


def _to_tls_certificate(cert: x509.Certificate) -> TlsCertificate:
    key_type, key_size, key_curve = _extract_public_key(cert)
    sig_hash = (
        cert.signature_hash_algorithm.name.lower()
        if cert.signature_hash_algorithm is not None
        else None
    )
    sig_alg = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
    return TlsCertificate(
        subject=cert.subject.rfc4514_string()[:MAX_DN_LENGTH],
        issuer=cert.issuer.rfc4514_string()[:MAX_DN_LENGTH],
        sans=_extract_sans(cert),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        key_type=key_type,
        key_size=key_size,
        key_curve=key_curve,
        signature_algorithm=sig_alg,
        signature_hash=sig_hash,
        serial_number=format(cert.serial_number, "x"),
        is_self_signed=cert.issuer == cert.subject,
    )


def _extract_public_key(cert: x509.Certificate) -> tuple[str, int | None, str | None]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size, None
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "EC", pub.curve.key_size, pub.curve.name
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, None
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", 448, None
    if isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size, None
    return "unknown", None, None


def _extract_sans(cert: x509.Certificate) -> tuple[str, ...]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return ()
    values: list[str] = []
    for name in ext.value:
        if isinstance(name, x509.DNSName):
            values.append(name.value[:MAX_DN_LENGTH])
        elif isinstance(name, x509.IPAddress):
            values.append(str(name.value))
        if len(values) >= MAX_SANS_PER_CERT:
            break
    return tuple(values)


def _cert_matches_hostname(cert: x509.Certificate, host: str) -> bool:
    norm_host = host.strip().lower().rstrip(".")
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = [
            name.lower().rstrip(".") for name in ext.value.get_values_for_type(x509.DNSName)
        ]
    except x509.ExtensionNotFound:
        dns_names = []

    if dns_names:
        return any(_match_pattern(pattern, norm_host) for pattern in dns_names)

    common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return any(
        isinstance(attr.value, str) and _match_pattern(attr.value.lower().rstrip("."), norm_host)
        for attr in common_names
    )


def _match_pattern(pattern: str, host: str) -> bool:
    if not pattern or not host:
        return False
    if pattern == host:
        return True
    if not pattern.startswith("*."):
        return False
    suffix = pattern[2:]
    if "*" in suffix or "." not in suffix:
        return False
    host_head, dot, host_tail = host.partition(".")
    return bool(dot and host_head and host_tail == suffix)
