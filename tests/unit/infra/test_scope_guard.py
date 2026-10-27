"""ScopeGuard: target validation, ownership gating and the per-run network allowlists."""

from uuid import uuid4

import pytest

from attacksurf.domain.assets import AssetType
from attacksurf.domain.net import HttpBody, ScannerRuntime
from attacksurf.domain.scanners import (
    AssetRef,
    ScanContext,
    ScannerGrant,
    ScanOutput,
    UnconfiguredGate,
)
from attacksurf.domain.scope import HttpPermission, PublicSuffix, ScopeError, ScopePolicyError
from attacksurf.infra.http import SafeHttpClient
from attacksurf.infra.scope_guard import (
    MAX_DNS_LOOKUPS,
    ScopeGuard,
    UnverifiedOwnership,
    _GuardedDns,
    _GuardedHttp,
    request_host,
)
from tests.scanner_fixtures import FakeCheck


class StubDns:
    def __init__(self, answers: dict[str, tuple[str, ...]] | None = None) -> None:
        self.answers = answers or {}
        self.calls: list[tuple[str, str]] = []

    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        self.calls.append(("A", host))
        return self.answers.get(host, ("93.184.216.34",))

    def resolve_name(self, host: str) -> tuple[str, ...]:
        self.calls.append(("A+AAAA", host))
        return self.answers.get(host, ("93.184.216.34",))


class StubHttp:
    def __init__(self) -> None:
        self.requests: list[tuple[str, int]] = []
        self.policies: list[tuple[object, object, int]] = []
        self.response = HttpBody(200, b"[]")
        self.closed = False

    def get(self, url: str, *, limit: int) -> HttpBody:
        self.requests.append((url, limit))
        return self.response

    def with_redirect_policy(
        self, resolver: object, *, redirect_allowed: object, max_redirects: int
    ) -> "_RunHttp":
        self.policies.append((resolver, redirect_allowed, max_redirects))
        return _RunHttp(self, redirect_allowed)

    def close(self) -> None:
        self.closed = True


class _RunHttp(StubHttp):
    """What a run gets: the redirect hook is enforced before every request."""

    def __init__(self, inner: StubHttp, redirect_allowed: object) -> None:
        super().__init__()
        self._inner = inner
        self._allowed = redirect_allowed

    def get(self, url: str, *, limit: int) -> HttpBody:
        assert callable(self._allowed)
        if not self._allowed(url):
            raise ScopePolicyError("Redirect target is out of scope.")
        self._inner.requests.append((url, limit))
        return self._inner.response


class EverythingVerified:
    def is_verified(self, org_id: object, asset: AssetRef) -> bool:
        return True


class ClassifiedAsPublicSuffix:
    """Fake PSL: every name is a subdomain of a registrable domain."""

    def __call__(self, host: str) -> PublicSuffix:
        return PublicSuffix.SUBDOMAIN


def scanner(**overrides: object) -> FakeCheck:
    instance = FakeCheck()
    for name, value in overrides.items():
        setattr(instance, name, value)
    return instance


def context() -> ScanContext:
    return ScanContext(
        uuid4(), uuid4(), AssetRef(type=AssetType.DOMAIN, value="acme.com"), "fixture"
    )


def target(value: str = "acme.com", asset_type: AssetType = AssetType.DOMAIN) -> AssetRef:
    return AssetRef(type=asset_type, value=value)


def make_guard(
    *,
    dns: StubDns | None = None,
    http: StubHttp | None = None,
    verified: bool = False,
) -> tuple[ScopeGuard, StubHttp]:
    http = http or StubHttp()
    scope = ScopeGuard(dns=dns or StubDns(), http=http, ownership=UnverifiedOwnership())
    scope._classify = ClassifiedAsPublicSuffix()  # type: ignore[assignment]
    return scope, http


def verify_all(scope: ScopeGuard) -> ScopeGuard:
    scope._ownership = EverythingVerified()  # type: ignore[assignment]
    return scope


def test_passive_scanner_gets_run_scoped_adapters_and_no_lookups_at_planning() -> None:
    scope, http = make_guard()
    runtime = scope.check(context(), target(), scanner())

    assert isinstance(runtime, ScannerRuntime)
    assert http.policies
    assert http.policies[0][2] >= 1  # redirect hook installed for the run


@pytest.mark.parametrize("host", ["nothing.corp", "printer.internal", "x.local"])
def test_out_of_scope_targets_are_denied(host: str) -> None:
    scope, _ = make_guard()
    host_scanner = scanner(asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}))
    with pytest.raises(ScopeError):
        scope.check(context(), target(host, AssetType.SUBDOMAIN), host_scanner)


def test_blocked_ip_assets_are_denied() -> None:
    scope, _ = make_guard()
    ip_scanner = scanner(asset_types=frozenset({AssetType.IP}))
    with pytest.raises(ScopeError, match="private"):
        scope.check(context(), target("169.254.169.254", AssetType.IP), ip_scanner)


def test_active_checks_are_denied_until_ownership_is_verified() -> None:
    active = scanner(asset_types=frozenset({AssetType.DOMAIN}), requires_verification=True)
    with pytest.raises(ScopeError, match="verified"):
        make_guard()[0].check(context(), target(), active)
    verify_all(make_guard()[0]).check(context(), target(), active)
    assert UnverifiedOwnership().is_verified(uuid4(), target()) is False


def test_scanner_must_support_the_asset_type() -> None:
    ip_scanner = scanner(asset_types=frozenset({AssetType.IP}))
    with pytest.raises(ScopePolicyError, match="asset type"):
        make_guard()[0].check(context(), target(), ip_scanner)


def test_non_network_asset_types_are_rejected() -> None:
    url_scanner = scanner(asset_types=frozenset({AssetType.URL}))
    with pytest.raises(ScopeError, match="network"):
        make_guard()[0].check(context(), target("https://acme.com/", AssetType.URL), url_scanner)


def test_services_grant_is_planned_without_network_io() -> None:
    dns = StubDns()
    scope, _ = make_guard(dns=dns)
    busy = scanner(
        grant=ScannerGrant(
            http=HttpPermission.SERVICES, http_hosts=frozenset({"crt.example.org"}), dns_lookups=1
        )
    )
    scope.check(context(), target(), busy)
    assert dns.calls == []  # answers are validated when the client pins, not when planning


def test_services_grant_needs_a_dns_lookup_per_service() -> None:
    busy = scanner(
        grant=ScannerGrant(http=HttpPermission.SERVICES, http_hosts=frozenset({"crt.example.org"}))
    )
    with pytest.raises(ScopePolicyError, match="DNS lookup"):
        make_guard()[0].check(context(), target(), busy)


def test_services_grant_with_an_internal_service_is_a_policy_error() -> None:
    scope = ScopeGuard(
        dns=StubDns(),
        http=StubHttp(),
        ownership=UnverifiedOwnership(),
        classify=lambda h: PublicSuffix.SUBDOMAIN,
    )
    busy = scanner(
        grant=ScannerGrant(
            http=HttpPermission.SERVICES, http_hosts=frozenset({"metadata.internal"}), dns_lookups=1
        )
    )
    with pytest.raises(ScopePolicyError, match="data service"):
        scope.check(context(), target(), busy)


def test_service_answers_are_validated_when_the_client_pins() -> None:
    """A service that resolves privately is caught inside the guarded resolver, per request."""
    answers = StaticAnswers({"crt.example.org": ("127.0.0.1",)})
    scope = ScopeGuard(
        dns=answers,
        http=SafeHttpClient(answers),
        ownership=UnverifiedOwnership(),
        classify=ClassifiedAsPublicSuffix(),
    )
    busy = scanner(
        grant=ScannerGrant(
            http=HttpPermission.SERVICES, http_hosts=frozenset({"crt.example.org"}), dns_lookups=1
        )
    )
    runtime = scope.check(context(), target(), busy)
    with pytest.raises(ScopeError, match="private"):
        runtime.http.get("https://crt.example.org/", limit=10)
    assert answers.calls == ["crt.example.org"]


class StaticAnswers:
    def __init__(self, answers: dict[str, tuple[str, ...]]) -> None:
        self.answers = answers
        self.calls: list[str] = []

    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        self.calls.append(host)
        return self.answers[host]

    def resolve_name(self, host: str) -> tuple[str, ...]:
        self.calls.append(host)
        return self.answers[host]


def test_dns_only_grant_denies_http_entirely() -> None:
    scope, _ = make_guard()
    runtime = scope.check(context(), target(), scanner())
    with pytest.raises(ScopePolicyError):
        runtime.http.get("https://acme.com/", limit=10)


def test_services_only_grant_cannot_reach_the_scanned_target() -> None:
    scope, http = make_guard()
    busy = scanner(
        grant=ScannerGrant(
            http=HttpPermission.SERVICES,
            http_hosts=frozenset({"crt.example.org"}),
            dns_lookups=1,
        )
    )
    runtime = scope.check(context(), target(), busy)
    with pytest.raises(ScopePolicyError):
        runtime.http.get("https://acme.com/", limit=10)
    runtime.http.get("https://api.crt.example.org/?q=acme.com", limit=10)
    assert http.requests == [("https://api.crt.example.org/?q=acme.com", 10)]


def test_target_grant_allows_only_the_scanned_host() -> None:
    scope = verify_all(make_guard()[0])
    active = scanner(
        requires_verification=True, grant=ScannerGrant(http=HttpPermission.TARGET, dns_lookups=1)
    )
    runtime = scope.check(context(), target(), active)
    runtime.http.get("https://acme.com/robots.txt", limit=10)
    with pytest.raises(ScopePolicyError):
        runtime.http.get("https://other.example.com/", limit=10)


def test_redirect_hook_uses_the_same_allowlist_as_the_first_hop() -> None:
    scope, http = make_guard()
    active = scanner(
        requires_verification=True, grant=ScannerGrant(http=HttpPermission.TARGET, dns_lookups=1)
    )
    verify_all(scope).check(context(), target(), active)
    redirect_hook = http.policies[0][1]
    assert callable(redirect_hook)
    assert redirect_hook("https://acme.com/next") is True
    assert redirect_hook("https://attacker.example.net/") is False


def test_guarded_dns_validates_every_answer_and_enforces_the_budget() -> None:
    dns = StubDns({"split.example": ("93.184.216.34", "10.0.0.1")})
    guarded = _GuardedDns(dns, max_lookups=2)
    assert guarded.resolve_ipv4("ok.example") == ("93.184.216.34",)
    with pytest.raises(ScopeError, match="private"):
        guarded.resolve_name("split.example")
    with pytest.raises(ScopeError, match="budget"):
        guarded.resolve_ipv4("ok.example")


def test_guarded_dns_caps_a_scanner_declared_budget() -> None:
    assert _GuardedDns(StubDns(), max_lookups=10_000)._remaining == MAX_DNS_LOOKUPS


def test_guarded_http_bounds_the_response_limit() -> None:
    inner = StubHttp()
    guarded = _GuardedHttp(
        inner, target=None, services=frozenset({"crt.example.org"}), check_host=lambda h: h
    )
    guarded.get("https://api.crt.example.org/", limit=10**9)
    guarded.get("https://api.crt.example.org/", limit=0)
    assert inner.requests[0][1] == 1024 * 1024
    assert inner.requests[1][1] == 1


@pytest.mark.parametrize(
    ("url", "error"),
    [
        ("ftp://crt.example.org/", "http and https"),
        ("https://user:pass@crt.example.org/", "credentials"),
        ("https:///no-host", "no host"),
        ("http://[::1", "malformed"),
        ("https://crt.example.org:notaport/", "malformed"),
    ],
)
def test_scanner_urls_are_validated(url: str, error: str) -> None:
    with pytest.raises(ScopeError, match=error):
        request_host(url)


def test_fixture_scanner_runs_and_runtime_closes_its_clients() -> None:
    http = StubHttp()
    runtime = ScannerRuntime(StubDns(), http)
    output = FakeCheck().run(context(), target())
    assert isinstance(output, ScanOutput)
    runtime.close()
    assert http.closed is True


def test_unconfigured_gate_fails_closed() -> None:
    with pytest.raises(ScopeError, match="disabled"):
        UnconfiguredGate().check(context(), target(), scanner())
