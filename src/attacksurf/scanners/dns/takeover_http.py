"""Confirm takeover candidates whose service still resolves (#18).

The verified companion to `dns.takeover`: when a name CNAMEs to a known-claimable service
that keeps resolving, only the service's own "not found" answer proves the instance is gone.
This plugin makes exactly one passive GET of the scanned asset through the safe client and
matches the response against the pinned fingerprint dataset. Status signatures are limited
to non-redirect codes by the dataset loader: the client follows redirects before a scanner
sees a response, and a redirect alone does not prove an unclaimed instance. Plain HTTP is
deliberate: a
deprovisioned instance usually has no valid TLS certificate for the victim's name, so HTTPS
would fail before the signature could be read. The GET is still an active (target) check —
ScopeGuard only runs this plugin on assets whose root proved ownership — and nothing is
ever registered, claimed or probed beyond that single request.

Importing this module also registers `dns.takeover` (the chain helper lives there); both
plugins are listed explicitly in the app/worker plugin imports regardless.
"""

from attacksurf.domain.findings import Confidence, EvidenceKind
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError, DnsQuery, DnsRecordType, DnsStatus
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
from attacksurf.domain.scope import HttpPermission, ScopeError
from attacksurf.scanners.dns.fingerprints import load_fingerprints, match_service
from attacksurf.scanners.dns.takeover import MAX_EVIDENCE_VALUES, MAX_VALUE_LENGTH, cname_chain
from attacksurf.scanners.registry import register_scanner

MAX_BODY_BYTES = 64 * 1024
MAX_SNIPPET_LENGTH = 1024
_SNIPPET_CONTEXT = 128
# CNAME chain follows plus the safe client's own resolve per request/redirect hop.
DNS_LOOKUPS = 16


@register_scanner
class DnsTakeoverHttp:
    name = "dns.takeover.http"
    asset_types = frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN})
    queue = "passive"
    requires_verification = True
    timeout_seconds = 60.0
    grant = ScannerGrant(http=HttpPermission.TARGET, dns_lookups=DNS_LOOKUPS)

    def run(self, ctx: ScanContext, asset: AssetRef) -> ScanOutput:
        runtime = ctx.runtime
        if runtime is None:
            raise ScannerError("Scanner runtime is not configured.")
        try:
            first = runtime.dns.lookup_many((DnsQuery(asset.value, DnsRecordType.CNAME),))[0]
        except DnsError:
            raise TransientJobError("Subdomain takeover check failed.") from None
        if first.status is DnsStatus.ERROR:
            raise TransientJobError("Subdomain takeover check failed.")
        chain, chain_error = cname_chain(runtime.dns, asset.value, first)
        if chain_error or len(chain) == 1:
            return ScanOutput()
        terminal = chain[-1]
        service = match_service(load_fingerprints(), terminal)
        if service is None or service.nxdomain:
            return ScanOutput()  # unknown claimability, or the DNS check owns NXDOMAIN
        if service.fingerprint is None and service.http_status is None:
            return ScanOutput()
        url = f"http://{asset.value}/"
        try:
            body = runtime.http.get(url, limit=MAX_BODY_BYTES)
        except (DnsError, ScopeError):
            return ScanOutput()  # unreachable is not evidence of an unclaimed instance
        text = body.content.decode("utf-8", errors="replace").replace("\x00", "\\0")
        snippet = _match_snippet(text, service.fingerprint, body.status_code, service.http_status)
        if snippet is None:
            return ScanOutput()
        finding = RawFinding(
            rule_id="dns.takeover.fingerprint_match",
            location=terminal,
            confidence=Confidence.HIGH,
            evidence=(
                RawEvidence(
                    kind=EvidenceKind.DNS_RECORD,
                    data={
                        "record": "CNAME",
                        "name": asset.value,
                        "values": [
                            value[:MAX_VALUE_LENGTH] for value in chain[:MAX_EVIDENCE_VALUES]
                        ],
                    },
                ),
                RawEvidence(
                    kind=EvidenceKind.HTTP_RESPONSE,
                    data={"url": url, "status_code": body.status_code, "body_snippet": snippet},
                ),
            ),
            remediation_context={
                "domain": asset.value,
                "target": terminal,
                "service": service.service,
            },
        )
        return ScanOutput(findings=(finding,))


def _match_snippet(
    text: str, fingerprint: str | None, status_code: int, http_status: int | None
) -> str | None:
    """Response excerpt proving the match, or None when the signature is absent.

    A truncated body can still match: the client caps what it reads, and the signature of a
    deprovisioned instance is the start of its error page, not the tail. `http_status` is
    never a redirect code: the loader rejects those, since the client follows them first.
    """
    if fingerprint:
        index = text.find(fingerprint)
        if index < 0:
            return None
        start = max(0, index - _SNIPPET_CONTEXT)
        end = min(len(text), index + len(fingerprint) + _SNIPPET_CONTEXT)
        return text[start:end][:MAX_SNIPPET_LENGTH]
    if http_status is not None and status_code == http_status:
        return text[:MAX_SNIPPET_LENGTH]
    return None
