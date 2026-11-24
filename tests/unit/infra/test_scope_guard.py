"""ScopeGuard: target validation, ownership gating and the per-run network allowlists."""

from collections.abc import Mapping, Sequence
from uuid import uuid4

import pytest

from attacksurf.domain.assets import AssetType
from attacksurf.domain.cache import NullCache
from attacksurf.domain.net import (
    DnsError,
    DnsLookup,
    DnsQuery,
    DnsRecordType,
    HttpBody,
    ScannerRuntime,
)
from attacksurf.domain.sandbox import SandboxError
from attacksurf.domain.scanners import (
    AssetRef,
    ScanContext,
    ScannerGrant,
    ScanOutput,
    UnconfiguredGate,
)
from attacksurf.domain.scope import HttpPermission, PublicSuffix, ScopeError, ScopePolicyError
from attacksurf.infra import public_suffix
from attacksurf.infra.http import MAX_BODY_BYTES, SafeHttpClient
from attacksurf.infra.rate_limit import InMemoryTargetRateLimiter
from attacksurf.infra.scope_guard import (
    MAX_DNS_LOOKUPS,
    ScopeGuard,
    UnverifiedOwnership,
    _GuardedDns,
    _GuardedHttp,
    request_host,
    validate_llm_base_url,
)
from attacksurf.infra.tls import RawTlsHandshake
from tests.fakes import FakeCache
from tests.scanner_fixtures import FakeCheck, FakeSandboxRunner


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

    def lookup_many(self, queries: Sequence[DnsQuery]) -> tuple[DnsLookup, ...]:
        self.calls.extend((query.record_type.value, query.name) for query in queries)
        return tuple(DnsLookup(query, self.answers.get(query.name, ())) for query in queries)

    def lookup_records(self, name: str, rdtype: str) -> tuple[str, tuple[str, ...]]:
        self.calls.append((rdtype, name))
        return name, self.answers.get(name, ())

    def lookup_records_checking_disabled(
        self, name: str, rdtype: str
    ) -> tuple[str, tuple[str, ...]]:
        return self.lookup_records(name, rdtype)


class StubHttp:
    def __init__(self) -> None:
        self.requests: list[tuple[str, int]] = []
        self.headers_seen: list[dict[str, str] | None] = []
        self.policies: list[tuple[object, object, int]] = []
        self.response = HttpBody(200, b"[]")
        self.closed = False

    def head(self, url: str, *, headers: Mapping[str, str] | None = None) -> HttpBody:
        self.requests.append((url, 0))
        self.headers_seen.append(dict(headers) if headers is not None else None)
        return self.response

    def get(self, url: str, *, limit: int, headers: Mapping[str, str] | None = None) -> HttpBody:
        self.requests.append((url, limit))
        self.headers_seen.append(dict(headers) if headers is not None else None)
        return self.response

    def with_redirect_policy(
        self,
        resolver: object,
        *,
        redirect_allowed: object,
        request_allowed: object = None,
        max_redirects: int,
        stop_on_out_of_scope_redirect: bool = False,
        rate_limiter: object = None,
        rate_limit_org_id: object = None,
        user_agent: str | None = None,
    ) -> "_RunHttp":
        del stop_on_out_of_scope_redirect, rate_limiter, rate_limit_org_id, user_agent
        self.policies.append((resolver, redirect_allowed, max_redirects))
        return _RunHttp(self, redirect_allowed, request_allowed)

    def close(self) -> None:
        self.closed = True


class _RunHttp(StubHttp):
    """What a run gets from `with_redirect_policy`, mirroring the real client exactly.
    The real `SafeHttpClient` consults its policy hook before the first request and every hop,
    so this fake must too: a permissive fake would hide a guard bypass (see
    `test_run_client_enforces_the_allowlist_before_the_first_request`).
    """

    def __init__(
        self,
        inner: StubHttp,
        redirect_allowed: object,
        request_allowed: object = None,
    ) -> None:
        super().__init__()
        self._inner = inner
        self._allowed = redirect_allowed
        self._request_allowed = request_allowed

    def head(self, url: str, *, headers: Mapping[str, str] | None = None) -> HttpBody:
        assert callable(self._allowed)
        if not self._allowed(url):
            raise ScopeError("The target is out of scope.")
        if self._request_allowed is not None:
            assert callable(self._request_allowed)
            if not self._request_allowed("HEAD", url):
                raise ScopePolicyError("The request method or path is outside the scanner grant.")
        self._inner.requests.append((url, 0))
        self._inner.headers_seen.append(dict(headers) if headers is not None else None)
        return self._inner.response

    def get(self, url: str, *, limit: int, headers: Mapping[str, str] | None = None) -> HttpBody:
        assert callable(self._allowed)
        if not self._allowed(url):
            raise ScopeError("The target is out of scope.")
        if self._request_allowed is not None:
            assert callable(self._request_allowed)
            if not self._request_allowed("GET", url):
                raise ScopePolicyError("The request method or path is outside the scanner grant.")
        self._inner.requests.append((url, limit))
        self._inner.headers_seen.append(dict(headers) if headers is not None else None)
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
    active_scans_enabled: bool = True,
    rate_limiter: object = None,
    user_agent: str | None = None,
) -> tuple[ScopeGuard, StubHttp]:
    http = http or StubHttp()
    scope = ScopeGuard(
        dns=dns or StubDns(),
        http=http,
        ownership=UnverifiedOwnership(),
        active_scans_enabled=active_scans_enabled,
        rate_limiter=rate_limiter,  # type: ignore[arg-type]
        user_agent=user_agent,
    )
    scope._classify = ClassifiedAsPublicSuffix()  # type: ignore[assignment]
    return scope, http


def verify_all(scope: ScopeGuard) -> ScopeGuard:
    scope._ownership = EverythingVerified()  # type: ignore[assignment]
    return scope


def test_gate_passes_its_cache_to_the_run() -> None:
    cache = FakeCache()
    scope = ScopeGuard(
        dns=StubDns(),
        http=StubHttp(),
        ownership=UnverifiedOwnership(),
        cache=cache,
    )
    scope._classify = ClassifiedAsPublicSuffix()  # type: ignore[assignment]

    runtime = scope.check(context(), target(), scanner())

    assert runtime.cache is cache


def test_gate_defaults_to_a_null_cache() -> None:
    scope, _ = make_guard()

    runtime = scope.check(context(), target(), scanner())

    assert isinstance(runtime.cache, NullCache)


def test_gate_passes_the_registrable_domain_classifier_to_the_run() -> None:
    scope, _ = make_guard()

    runtime = scope.check(context(), target(), scanner())

    assert runtime.org_domain is public_suffix.registrable
    assert runtime.org_domain is not None
    assert runtime.org_domain("eng.example.com") == "example.com"


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


def test_active_scans_are_disabled_by_default_and_denied_even_when_verified() -> None:
    scope = ScopeGuard(
        dns=StubDns(),
        http=StubHttp(),
        ownership=EverythingVerified(),
        classify=ClassifiedAsPublicSuffix(),
    )
    active = scanner(
        queue="active",
        requires_verification=True,
        grant=ScannerGrant(http=HttpPermission.TARGET, dns_lookups=1),
    )

    with pytest.raises(ScopeError, match="disabled"):
        scope.check(context(), target(), active)


def test_active_queue_scanner_requires_verification_even_if_flag_is_false() -> None:
    active = scanner(queue="active", requires_verification=False)

    with pytest.raises(ScopeError, match="verified"):
        make_guard()[0].check(context(), target(), active)


def test_target_http_binds_rate_limiter_and_user_agent_but_services_does_not() -> None:
    limiter = InMemoryTargetRateLimiter()
    answers = StaticAnswers({"acme.com": ("93.184.216.34",), "crt.example.org": ("93.184.216.34",)})
    http = RecordingSafeHttp(answers)
    scope = ScopeGuard(
        dns=answers,
        http=http,
        ownership=EverythingVerified(),
        classify=ClassifiedAsPublicSuffix(),
        active_scans_enabled=True,
        rate_limiter=limiter,
        user_agent="attacksurf/0.1.0 (+https://example.org)",
    )
    ctx = context()

    target_runtime = scope.check(
        ctx,
        target(),
        scanner(
            queue="active",
            requires_verification=True,
            grant=ScannerGrant(http=HttpPermission.TARGET, dns_lookups=1),
        ),
    )
    assert isinstance(target_runtime.http, RecordingSafeHttp)
    assert target_runtime.http._rate_limiter is limiter
    assert target_runtime.http._rate_limit_org_id == ctx.org_id
    assert target_runtime.http._user_agent == "attacksurf/0.1.0 (+https://example.org)"

    service_runtime = scope.check(
        ctx,
        target(),
        scanner(
            grant=ScannerGrant(
                http=HttpPermission.SERVICES,
                http_hosts=frozenset({"crt.example.org"}),
                dns_lookups=1,
            ),
        ),
    )
    assert isinstance(service_runtime.http, RecordingSafeHttp)
    assert service_runtime.http._rate_limiter is None
    assert service_runtime.http._rate_limit_org_id is None
    assert service_runtime.http._user_agent is None


def test_active_checks_need_verified_ownership() -> None:
    active = scanner(asset_types=frozenset({AssetType.DOMAIN}), requires_verification=True)
    with pytest.raises(ScopeError, match="verified"):
        make_guard()[0].check(context(), target(), active)
    verify_all(make_guard()[0]).check(context(), target(), active)
    # Nothing is verified without a proof (#14): the gate's default checker denies everything.
    assert UnverifiedOwnership().is_verified(uuid4(), target()) is False


def test_target_http_requires_verification_even_if_the_plugin_flag_is_false() -> None:
    """Regression: a TARGET grant is an active check, whatever `requires_verification` says."""
    active = scanner(
        requires_verification=False,  # inconsistent metadata the gate must not trust
        grant=ScannerGrant(http=HttpPermission.TARGET, dns_lookups=1),
    )
    with pytest.raises(ScopeError, match="verified"):
        make_guard()[0].check(context(), target(), active)


def test_scanner_must_support_the_asset_type() -> None:
    ip_scanner = scanner(asset_types=frozenset({AssetType.IP}))
    with pytest.raises(ScopePolicyError, match="asset type"):
        make_guard()[0].check(context(), target(), ip_scanner)


def test_non_network_asset_types_are_rejected() -> None:
    repo_scanner = scanner(asset_types=frozenset({AssetType.REPO}))
    with pytest.raises(ScopeError, match="network"):
        make_guard()[0].check(
            context(), target("github.com/acme/app", AssetType.REPO), repo_scanner
        )


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

    def lookup_many(self, queries: Sequence[DnsQuery]) -> tuple[DnsLookup, ...]:
        return tuple(DnsLookup(query, self.answers.get(query.name, ())) for query in queries)

    def lookup_records(self, name: str, rdtype: str) -> tuple[str, tuple[str, ...]]:
        return name, self.answers.get(name, ())

    def lookup_records_checking_disabled(
        self, name: str, rdtype: str
    ) -> tuple[str, tuple[str, ...]]:
        return self.lookup_records(name, rdtype)


def test_dns_only_grant_denies_http_entirely() -> None:
    scope, _ = make_guard()
    runtime = scope.check(context(), target(), scanner())
    with pytest.raises(ScopeError):
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
    with pytest.raises(ScopeError):
        runtime.http.get("https://acme.com/", limit=10)
    runtime.http.get("https://api.crt.example.org/?q=acme.com", limit=10)
    assert http.requests == [("https://api.crt.example.org/?q=acme.com", 10)]


def test_target_grant_allows_only_the_scanned_host() -> None:
    scope = verify_all(make_guard()[0])
    active = scanner(
        requires_verification=True, grant=ScannerGrant(http=HttpPermission.TARGET, dns_lookups=1)
    )
    runtime = scope.check(context(), target(), active)
    runtime.http.get("https://acme.com/", limit=10)
    with pytest.raises(ScopeError):
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


def test_guarded_dns_returns_raw_private_answers_without_validating_them() -> None:
    """Raw records are data: the resolver reports 10.0.0.1 but a connection path still blocks it."""
    dns = StubDns({"split.example": ("10.0.0.1",)})
    guarded = _GuardedDns(dns, max_lookups=2)

    result = guarded.lookup_many((DnsQuery("split.example", DnsRecordType.A),))

    assert result[0].values == ("10.0.0.1",)
    with pytest.raises(ScopeError, match="private"):
        guarded.resolve_name("split.example")
    with pytest.raises(ScopeError, match="budget"):
        guarded.lookup_many((DnsQuery("split.example", DnsRecordType.A),))


def test_guarded_dns_charges_one_unit_per_raw_query() -> None:
    guarded = _GuardedDns(StubDns(), max_lookups=2)

    guarded.lookup_many(
        (DnsQuery("a.example", DnsRecordType.A), DnsQuery("a.example", DnsRecordType.AAAA))
    )

    with pytest.raises(ScopeError, match="budget"):
        guarded.lookup_many((DnsQuery("a.example", DnsRecordType.A),))


def test_guarded_dns_caps_a_scanner_declared_budget() -> None:
    assert _GuardedDns(StubDns(), max_lookups=10_000)._remaining == MAX_DNS_LOOKUPS


def test_guarded_http_bounds_the_response_limit() -> None:
    inner = StubHttp()
    guarded = _GuardedHttp(
        inner, target=None, services=frozenset({"crt.example.org"}), check_host=lambda h: h
    )
    guarded.get("https://api.crt.example.org/", limit=10**9)
    guarded.get("https://api.crt.example.org/", limit=0)
    assert inner.requests[0][1] == MAX_BODY_BYTES
    assert inner.requests[1][1] == 1


class RecordingSafeHttp(SafeHttpClient):
    """A real `SafeHttpClient` whose transport is replaced: proves what would hit the wire."""

    def __init__(self, resolver: object, **kwargs: object) -> None:
        super().__init__(resolver, **kwargs)  # type: ignore[arg-type]
        self.sent: list[tuple[str, int]] = []

    def with_redirect_policy(
        self,
        resolver: object,
        *,
        redirect_allowed: object,
        request_allowed: object = None,
        max_redirects: int,
        stop_on_out_of_scope_redirect: bool = False,
        rate_limiter: object = None,
        rate_limit_org_id: object = None,
        user_agent: str | None = None,
    ) -> "RecordingSafeHttp":
        clone = RecordingSafeHttp(
            resolver,
            redirect_allowed=redirect_allowed,  # type: ignore[arg-type]
            request_allowed=request_allowed,  # type: ignore[arg-type]
            max_redirects=max_redirects,
            stop_on_out_of_scope_redirect=stop_on_out_of_scope_redirect,
            timeout_seconds=self._timeout,
            tls=self._tls,
            rate_limiter=rate_limiter,
            rate_limit_org_id=rate_limit_org_id,
            user_agent=user_agent,
        )
        clone.sent = self.sent
        return clone

    def _request(
        self,
        url: str,
        *,
        limit: int,
        headers: Mapping[str, str] | None = None,
        method: str = "GET",
    ) -> HttpBody:
        del headers, method
        self.sent.append((url, limit))
        return HttpBody(200, b"[]")


def make_runtime(
    *, grant: ScannerGrant, verified: bool = False
) -> tuple[ScannerRuntime, RecordingSafeHttp]:
    answers = StaticAnswers({"acme.com": ("93.184.216.34",), "crt.example.org": ("93.184.216.34",)})
    http = RecordingSafeHttp(answers)
    scope = ScopeGuard(
        dns=answers,
        http=http,
        ownership=UnverifiedOwnership(),
        classify=ClassifiedAsPublicSuffix(),
        active_scans_enabled=verified,
    )
    if verified:
        verify_all(scope)
    busy = scanner(
        grant=grant,
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN}),
        requires_verification=verified,
    )
    return scope.check(context(), target(), busy), http


def test_run_client_enforces_the_allowlist_before_the_first_request() -> None:
    """Regression: `client_for()` hands over the inner client, which must not skip the policy."""
    runtime, http = make_runtime(
        grant=ScannerGrant(
            http=HttpPermission.SERVICES, http_hosts=frozenset({"crt.example.org"}), dns_lookups=5
        )
    )
    with pytest.raises(ScopeError):
        runtime.http.get("https://evil.example.net/", limit=10)
    assert http.sent == []  # nothing left the process


def test_run_client_with_a_dns_only_grant_sends_no_http_request() -> None:
    runtime, http = make_runtime(grant=ScannerGrant())
    with pytest.raises(ScopeError):
        runtime.http.get("https://acme.com/", limit=10)
    assert http.sent == []


def test_run_client_bounds_a_scanner_supplied_limit() -> None:
    runtime, http = make_runtime(
        grant=ScannerGrant(
            http=HttpPermission.SERVICES, http_hosts=frozenset({"crt.example.org"}), dns_lookups=5
        )
    )
    runtime.http.get("https://crt.example.org/", limit=10**9)
    assert http.sent == [("https://crt.example.org/", MAX_BODY_BYTES)]


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


def sandboxed_guard() -> tuple[ScopeGuard, FakeSandboxRunner]:
    scope, _ = make_guard()
    sandbox = FakeSandboxRunner()
    scope._sandbox = sandbox  # type: ignore[assignment]
    return scope, sandbox


def test_scanner_without_a_sandbox_grant_cannot_run_any_analyzer() -> None:
    scope, sandbox = sandboxed_guard()
    runtime = scope.check(context(), target(), scanner())

    with pytest.raises(ScopePolicyError, match="analyzer"):
        runtime.sandbox.run("fixture.echo", uuid4())
    assert sandbox.calls == []


def test_scanner_cannot_run_an_analyzer_outside_its_grant() -> None:
    scope, sandbox = sandboxed_guard()
    granted = scanner(grant=ScannerGrant(sandbox_analyzers=frozenset({"fixture.echo"})))
    runtime = scope.check(context(), target(), granted)

    with pytest.raises(ScopePolicyError, match="analyzer"):
        runtime.sandbox.run("fixture.other", uuid4())
    assert sandbox.calls == []


def test_scanner_with_a_grant_reaches_the_runner_with_only_name_and_artifact() -> None:
    scope, sandbox = sandboxed_guard()
    granted = scanner(grant=ScannerGrant(sandbox_analyzers=frozenset({"fixture.echo"})))
    runtime = scope.check(context(), target(), granted)
    artifact_id = uuid4()

    result = runtime.sandbox.run("fixture.echo", artifact_id)

    assert result is sandbox.result
    assert sandbox.calls == [("fixture.echo", artifact_id)]


def test_granted_scanner_still_fails_closed_when_no_runner_is_wired() -> None:
    scope, _ = make_guard()
    granted = scanner(grant=ScannerGrant(sandbox_analyzers=frozenset({"fixture.echo"})))
    runtime = scope.check(context(), target(), granted)

    with pytest.raises(SandboxError, match="not configured"):
        runtime.sandbox.run("fixture.echo", uuid4())


# --- Authoritative DNS, RDAP and zone-transfer capabilities (#19) ---------------------------


def test_authoritative_capability_is_only_wired_when_granted() -> None:
    scope, _ = make_guard()
    runtime = scope.check(context(), target(), scanner())

    with pytest.raises(ScopePolicyError, match="authoritative"):
        runtime.authoritative.query("acme.com", DnsRecordType.SOA)


def test_authoritative_queries_are_restricted_to_the_target() -> None:
    scope, _ = make_guard()
    granted = scanner(grant=ScannerGrant(authoritative_dns=True, dns_lookups=3))
    runtime = scope.check(context(), target(), granted)

    with pytest.raises(ScopePolicyError, match="target's zone"):
        runtime.authoritative.query("other.com", DnsRecordType.SOA)
    answers = runtime.authoritative.query("acme.com", DnsRecordType.SOA)
    assert answers.zone == "acme.com"


def test_authoritative_grant_needs_a_dns_budget() -> None:
    busy = scanner(grant=ScannerGrant(authoritative_dns=True, dns_lookups=2))
    with pytest.raises(ScopePolicyError, match="DNS lookup"):
        make_guard()[0].check(context(), target(), busy)


def test_zone_transfer_requires_ownership_even_without_the_plugin_flag() -> None:
    active = scanner(
        requires_verification=False,
        grant=ScannerGrant(zone_transfer=True, dns_lookups=3),
    )
    with pytest.raises(ScopeError, match="verified"):
        make_guard()[0].check(context(), target(), active)


def test_zone_transfer_capability_is_wired_and_restricted() -> None:
    scope = verify_all(make_guard()[0])
    granted = scanner(grant=ScannerGrant(zone_transfer=True, dns_lookups=3))
    runtime = scope.check(context(), target(), granted)

    with pytest.raises(ScopePolicyError, match="target's zone"):
        runtime.zone_transfer.attempt("other.com")
    assert runtime.zone_transfer.attempt("acme.com") == ()


def test_zone_transfer_grant_needs_a_dns_budget() -> None:
    busy = scanner(grant=ScannerGrant(zone_transfer=True, dns_lookups=2))
    with pytest.raises(ScopePolicyError, match="DNS lookup"):
        verify_all(make_guard()[0]).check(context(), target(), busy)


def test_rdap_capability_is_only_wired_when_granted() -> None:
    scope, _ = make_guard()
    runtime = scope.check(context(), target(), scanner())

    with pytest.raises(ScopePolicyError, match="RDAP"):
        runtime.rdap.lookup("acme.com")


def test_rdap_lookups_are_restricted_to_the_target_or_its_registrable_domain() -> None:
    scope, _ = make_guard()
    granted = scanner(grant=ScannerGrant(rdap=True, dns_lookups=2))
    runtime = scope.check(context(), target(), granted)

    with pytest.raises(ScopePolicyError, match="registration"):
        runtime.rdap.lookup("other.com")
    # The stub client answers with an empty JSON array, which is not a bootstrap registry.
    assert runtime.rdap.lookup("acme.com") is None


def test_rdap_grant_needs_a_dns_budget() -> None:
    busy = scanner(grant=ScannerGrant(rdap=True, dns_lookups=1))
    with pytest.raises(ScopePolicyError, match="DNS lookup"):
        make_guard()[0].check(context(), target(), busy)


# --- Custom LLM base_url SSRF guard (#24) --------------------------------------------------


def test_llm_base_url_accepts_public_https_and_normalizes_default_port() -> None:
    dns = StubDns({"api.openai.com": ("93.184.216.34",)})

    assert validate_llm_base_url(" https://API.OpenAI.COM:443/v1 ", resolver=dns) == (
        "https://api.openai.com/v1"
    )
    assert validate_llm_base_url("https://llm.example.com:8443/v1", resolver=dns) == (
        "https://llm.example.com:8443/v1"
    )


@pytest.mark.parametrize(
    "bad_url",
    [
        "",
        "http://api.openai.com/v1",  # plain http refused unless allowlisted
        "ftp://api.openai.com/v1",
        "file:///etc/passwd",
        "https://user:hunter2@api.openai.com/v1",
        "https://user@api.openai.com/v1",
        "https://api.openai.com/v1?token=x",
        "https://api.openai.com/v1?",
        "https://api.openai.com/v1#frag",
        "https://localhost/v1",
        "https://127.0.0.1/v1",
        "https://[::1]/v1",
        "https://169.254.169.254/latest/meta-data/",
        "https://10.0.0.1/v1",
        "https://8.8.8.8/v1",  # IP literals refused unless allowlisted
        "https://ollama.internal/v1",
        "https://printer.local/v1",
        "https://ollama/v1",  # single-label
        "https://2130706433/v1",
        "https://0177.0.0.1/v1",
        "https://bad\\host.example.com/v1",
        "https://api.openai.com:0/v1",
        "https://api.openai.com:99999/v1",
        "https://api.openai.com/v1\nX-Inject: 1",
    ],
)
def test_llm_base_url_rejects_unsafe_or_ssrf_urls(bad_url: str) -> None:
    dns = StubDns({"api.openai.com": ("93.184.216.34",)})

    with pytest.raises(ScopeError) as exc_info:
        validate_llm_base_url(bad_url, resolver=dns)

    assert "hunter2" not in str(exc_info.value)


@pytest.mark.parametrize(
    "resolved_ips",
    [
        ("127.0.0.1",),
        ("10.0.0.5",),
        ("172.16.0.1",),
        ("192.168.1.10",),
        ("169.254.169.254",),
        ("100.64.0.1",),
        ("::1",),
        ("fe80::1",),
        ("::ffff:127.0.0.1",),
        ("93.184.216.34", "10.0.0.1"),  # one private IP invalidates the whole set
        (),
    ],
)
def test_llm_base_url_rejects_public_names_resolving_to_non_public_ips(
    resolved_ips: tuple[str, ...],
) -> None:
    dns = StubDns({"rebind.example.com": resolved_ips})

    with pytest.raises(ScopeError):
        validate_llm_base_url("https://rebind.example.com/v1", resolver=dns)


def test_llm_base_url_rejects_dns_lookup_failure() -> None:
    class FailingDns(StubDns):
        def resolve_name(self, host: str) -> tuple[str, ...]:
            raise DnsError("timeout")

    with pytest.raises(ScopeError, match="resolved"):
        validate_llm_base_url("https://api.openai.com/v1", resolver=FailingDns())


def test_llm_base_url_allows_allowlisted_self_hosted_hosts_including_http() -> None:
    dns = StubDns()
    allowed = frozenset({"localhost", "127.0.0.1", "::1", "ollama.internal"})

    assert (
        validate_llm_base_url("http://localhost:11434/v1", allowed_hosts=allowed, resolver=dns)
        == "http://localhost:11434/v1"
    )
    assert (
        validate_llm_base_url("http://127.0.0.1:8000/v1", allowed_hosts=allowed, resolver=dns)
        == "http://127.0.0.1:8000/v1"
    )
    assert (
        validate_llm_base_url("http://[::1]:8000/v1", allowed_hosts=allowed, resolver=dns)
        == "http://[::1]:8000/v1"
    )
    assert (
        validate_llm_base_url("http://ollama.internal/v1", allowed_hosts=allowed, resolver=dns)
        == "http://ollama.internal/v1"
    )
    assert dns.calls == []  # allowlisted hosts skip public DNS resolution

    # Allowlist is exact-match and never bypasses credential/query/fragment rules.
    for blocked in (
        "http://sub.ollama.internal/v1",
        "http://user:pass@localhost:11434/v1",
        "http://localhost:11434/v1?x=1",
    ):
        with pytest.raises(ScopeError):
            validate_llm_base_url(blocked, allowed_hosts=allowed, resolver=dns)


# --- Guarded TLS handshake adapter (#71) ------------------------------------------------------


class _RecordingTlsConnector:
    def __init__(self, outcome: RawTlsHandshake) -> None:
        self.outcome = outcome
        self.calls: list[tuple[str, int, str, bool]] = []

    def handshake(
        self,
        *,
        address: str,
        port: int,
        server_hostname: str,
        verify: bool,
        check_hostname: bool = True,
        timeout: float,
        min_version: object = None,
        max_version: object = None,
    ) -> RawTlsHandshake:
        del check_hostname, timeout, min_version, max_version
        self.calls.append((address, port, server_hostname, verify))
        return self.outcome


def test_tls_capability_is_only_wired_when_granted() -> None:
    scope, _ = make_guard()
    runtime = scope.check(context(), target(), scanner())

    with pytest.raises(ScopePolicyError, match="TLS"):
        runtime.tls.inspect("acme.com")


def test_tls_grant_requires_active_enabled_verified_ownership_and_dns_budget() -> None:
    tls_scanner = scanner(
        queue="active",
        requires_verification=True,
        grant=ScannerGrant(tls=True, dns_lookups=1),
    )

    disabled_scope, _ = make_guard(active_scans_enabled=False)
    verify_all(disabled_scope)
    with pytest.raises(ScopeError, match="disabled"):
        disabled_scope.check(context(), target(), tls_scanner)

    unverified_scope, _ = make_guard(active_scans_enabled=True)
    with pytest.raises(ScopeError, match="verified"):
        unverified_scope.check(context(), target(), tls_scanner)

    no_dns = scanner(
        queue="active",
        requires_verification=True,
        grant=ScannerGrant(tls=True, dns_lookups=0),
    )
    verified_scope = verify_all(make_guard(active_scans_enabled=True)[0])
    with pytest.raises(ScopePolicyError, match="DNS lookup"):
        verified_scope.check(context(), target(), no_dns)


def test_tls_guard_restricts_host_port_and_private_ips_and_pins_valid_target() -> None:
    connector = _RecordingTlsConnector(
        RawTlsHandshake("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, (), verified=True)
    )
    dns = StubDns({"acme.com": ("93.184.216.34",)})
    scope = ScopeGuard(
        dns=dns,
        http=StubHttp(),
        ownership=EverythingVerified(),
        classify=ClassifiedAsPublicSuffix(),
        active_scans_enabled=True,
        tls=connector,
    )
    granted = scanner(
        queue="active",
        requires_verification=True,
        grant=ScannerGrant(tls=True, tls_ports=frozenset({443, 8443}), dns_lookups=3),
    )
    runtime = scope.check(context(), target(), granted)

    with pytest.raises(ScopePolicyError, match="target host"):
        runtime.tls.inspect("other.example.com")
    with pytest.raises(ScopePolicyError, match="Port"):
        runtime.tls.inspect("acme.com", port=8000)
    assert connector.calls == []

    info = runtime.tls.inspect("acme.com", port=8443)
    assert info.address == "93.184.216.34"
    assert connector.calls == [("93.184.216.34", 8443, "acme.com", True)]

    # Private DNS answers are blocked before dialing the connector.
    dns.answers["acme.com"] = ("127.0.0.1",)
    with pytest.raises(ScopeError, match="private"):
        runtime.tls.inspect("acme.com")
    assert len(connector.calls) == 1


def test_target_http_grant_validates_ports_urls_and_verified_root_redirects() -> None:
    with pytest.raises(ValueError, match="http_ports"):
        ScannerGrant(http=HttpPermission.NONE, http_ports=frozenset({443}))
    with pytest.raises(ValueError, match="allowed web ports"):
        ScannerGrant(http=HttpPermission.TARGET, http_ports=frozenset({22}))

    scope, http = make_guard(active_scans_enabled=True)
    verify_all(scope)
    web_scanner = scanner(
        asset_types=frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.URL}),
        queue="active",
        requires_verification=True,
        grant=ScannerGrant(
            http=HttpPermission.TARGET,
            http_ports=frozenset({80, 443}),
            follow_redirects=True,
            dns_lookups=4,
        ),
    )

    runtime = scope.check(context(), target("acme.com"), web_scanner)
    assert http.policies[0][2] == 4
    hook = http.policies[0][1]
    assert callable(hook)
    assert hook("https://acme.com/") is True
    assert hook("https://www.acme.com/login") is True
    assert hook("http://acme.com:80/") is True
    assert hook("https://acme.com:8443/") is False
    assert hook("https://attacker.example.net/") is False
    del runtime

    url_runtime = scope.check(context(), target("https://acme.com/app", AssetType.URL), web_scanner)
    assert url_runtime is not None
    with pytest.raises(ScopeError, match="allowed web ports"):
        scope.check(context(), target("https://acme.com:8443/", AssetType.URL), web_scanner)

    no_redir = scanner(
        asset_types=frozenset({AssetType.DOMAIN}),
        queue="active",
        requires_verification=True,
        grant=ScannerGrant(http=HttpPermission.TARGET, follow_redirects=False, dns_lookups=2),
    )
    scope.check(context(), target("acme.com"), no_redir)
    assert http.policies[-1][2] == 0


def test_target_http_forwards_custom_headers_through_scope_guard() -> None:
    scope, http = make_guard(active_scans_enabled=True)
    verify_all(scope)
    cors_scanner = scanner(
        asset_types=frozenset({AssetType.URL}),
        queue="active",
        requires_verification=True,
        grant=ScannerGrant(http=HttpPermission.TARGET, dns_lookups=4),
    )

    runtime = scope.check(context(), target("https://acme.com/", AssetType.URL), cors_scanner)
    runtime.http.get(
        "https://acme.com/", limit=1024, headers={"Origin": "https://cors-probe.invalid"}
    )
    assert http.headers_seen[-1] == {"Origin": "https://cors-probe.invalid"}


def test_target_http_grant_validates_and_enforces_paths_methods_and_soft_404_probe() -> None:
    with pytest.raises(ValueError, match="http_methods"):
        ScannerGrant(http=HttpPermission.TARGET, http_methods=frozenset({"POST"}))
    with pytest.raises(ValueError, match="http_paths"):
        ScannerGrant(http=HttpPermission.TARGET, http_paths=frozenset({"/.git/../HEAD"}))
    with pytest.raises(ValueError, match="http_paths"):
        ScannerGrant(http=HttpPermission.NONE, http_paths=frozenset({"/.env"}))
    with pytest.raises(ValueError, match="soft_404_probe"):
        ScannerGrant(http=HttpPermission.NONE, soft_404_probe=True)

    scope, _http = make_guard(active_scans_enabled=True)
    verify_all(scope)
    exposure_scanner = scanner(
        asset_types=frozenset({AssetType.URL}),
        queue="active",
        requires_verification=True,
        grant=ScannerGrant(
            http=HttpPermission.TARGET,
            http_methods=frozenset({"GET", "HEAD"}),
            http_paths=frozenset({"/.env", "/backup.zip"}),
            soft_404_probe=True,
            follow_redirects=False,
            dns_lookups=4,
        ),
    )

    runtime = scope.check(
        context(),
        target("https://acme.com/app", AssetType.URL),
        exposure_scanner,
    )
    runtime.http.get("https://acme.com/attacksurf-not-found-0123456789abcdef", limit=1024)
    # Only one soft-404 sentinel probe is permitted per host per run.
    with pytest.raises(ScopePolicyError, match="path"):
        runtime.http.get("https://acme.com/attacksurf-not-found-fedcba9876543210", limit=1024)
    runtime.http.get("https://acme.com/.env", limit=1024)
    runtime.http.head("https://acme.com/backup.zip")
    with pytest.raises(ScopePolicyError, match="path"):
        runtime.http.get("https://acme.com/other", limit=1024)
    with pytest.raises(ScopePolicyError, match="path"):
        runtime.http.get("https://acme.com/.env?raw=1", limit=1024)

    get_only = scanner(
        asset_types=frozenset({AssetType.URL}),
        queue="active",
        requires_verification=True,
        grant=ScannerGrant(http=HttpPermission.TARGET, dns_lookups=2),
    )
    url_runtime = scope.check(
        context(),
        target("https://acme.com/portal?tab=info", AssetType.URL),
        get_only,
    )
    url_runtime.http.get("https://acme.com/portal?tab=info", limit=1024)
    with pytest.raises(ScopePolicyError, match="method"):
        url_runtime.http.head("https://acme.com/portal?tab=info")
    with pytest.raises(ScopePolicyError, match="path"):
        url_runtime.http.get("https://acme.com/portal?tab=other", limit=1024)
