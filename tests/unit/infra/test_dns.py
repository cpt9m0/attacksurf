"""Resolvers and PSL classification: bounded, search-list free, and no runtime downloads."""

import asyncio
from dataclasses import dataclass
from typing import cast

import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest
import tldextract

from attacksurf.domain import scope
from attacksurf.domain.net import DnsError, DnsLookup, DnsQuery, DnsRecordType, DnsStatus
from attacksurf.domain.scope import PublicSuffix
from attacksurf.infra import public_suffix
from attacksurf.infra.dns import DnsPythonResolver, _record_text
from attacksurf.scanners import registry


@dataclass
class Answer:
    rrset: list[str] | None


class FakeResolve:
    """Stands in for `dns.resolver.Resolver.resolve`: canned answers, recorded calls."""

    def __init__(self, answers: dict[tuple[str, str], list[str] | Exception | None]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, str, bool]] = []

    def __call__(
        self, qname: str, rdtype: str, *, search: bool, raise_on_no_answer: bool
    ) -> Answer:
        self.calls.append((qname, rdtype, search))
        outcome = self.answers.get((qname, rdtype))
        if isinstance(outcome, Exception):
            raise outcome
        return Answer(rrset=outcome)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> tuple[DnsPythonResolver, FakeResolve]:
    resolver = DnsPythonResolver()
    rdata = FakeResolve(
        {
            ("example.com", "A"): ["93.184.216.34", "93.184.216.35"],
            ("example.com", "AAAA"): ["2606:2800:220:1::1"],
            ("broken.example", "A"): dns.resolver.NoNameservers(),
            ("empty.example", "A"): None,
        }
    )
    monkeypatch.setattr(resolver._resolver, "resolve", rdata)
    return resolver, rdata


def test_resolver_disables_search_domains() -> None:
    assert DnsPythonResolver()._resolver.use_search_by_default is False


class _RecordAnswer:
    """Just enough of `dns.resolver.Answer` for the owner-aware lookup path."""

    def __init__(self, owner: str, values: list[str]) -> None:
        self.rrset = _RecordRrset(owner, values)
        self.canonical_name = dns.name.from_text(owner)


class _RecordRrset:
    def __init__(self, owner: str, values: list[str]) -> None:
        self.name = dns.name.from_text(owner)
        self.values = values

    def __iter__(self):
        return iter(self.values)


def test_checking_disabled_lookup_uses_a_cd_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bogus zone is only visible with CD, so the diagnostic path must send that flag."""
    resolver = DnsPythonResolver()
    calls: list[tuple[str, str]] = []

    def resolve(qname: str, rdtype: str, *, search: bool, raise_on_no_answer: bool) -> object:
        calls.append((qname, rdtype))
        return _RecordAnswer(qname, [f"{qname}."])

    monkeypatch.setattr(resolver._diagnostic_resolver, "resolve", resolve)

    assert resolver.lookup_records_checking_disabled("example.com", "NS") == (
        "example.com",
        ("example.com.",),
    )
    assert calls == [("example.com", "NS")]
    assert resolver._diagnostic_resolver.flags == dns.flags.RD | dns.flags.CD
    assert resolver._resolver.flags is None  # ordinary lookups keep the resolver default


def test_name_lookup_combines_and_deduplicates_families(
    fake: tuple[DnsPythonResolver, FakeResolve],
) -> None:
    resolver, calls = fake
    answers = resolver.resolve_name("example.com")
    assert answers == ("93.184.216.34", "93.184.216.35", "2606:2800:220:1::1")
    assert all(search is False for _, _, search in calls.calls)


def test_ipv4_lookup_only_queries_a_records(
    fake: tuple[DnsPythonResolver, FakeResolve],
) -> None:
    resolver, calls = fake
    assert resolver.resolve_ipv4("example.com") == ("93.184.216.34", "93.184.216.35")
    assert {rdtype for _, rdtype, _ in calls.calls} == {"A"}


def test_missing_records_are_empty_not_errors(
    fake: tuple[DnsPythonResolver, FakeResolve],
) -> None:
    resolver, _ = fake
    assert resolver.resolve_ipv4("empty.example") == ()


def test_resolver_failures_become_message_free_dns_errors(
    fake: tuple[DnsPythonResolver, FakeResolve],
) -> None:
    resolver, calls = fake
    with pytest.raises(DnsError) as raised:
        resolver.resolve_ipv4("broken.example")
    assert str(raised.value) == ""
    assert calls.calls == [("broken.example", "A", False)]


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("example.com", PublicSuffix.ROOT),
        ("www.example.co.uk", PublicSuffix.SUBDOMAIN),
        ("co.uk", PublicSuffix.SUFFIX_ONLY),
        ("no-such-suffix.invalid", PublicSuffix.NONE),
        ("host.unknowntld", PublicSuffix.NONE),
    ],
)
def test_classify_uses_the_bundled_snapshot(host: str, expected: PublicSuffix) -> None:
    assert public_suffix.classify(host) is expected


def test_psl_lookup_never_fetches_at_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("tldextract must not touch the network")

    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    monkeypatch.setattr("urllib.request.Request", forbidden)
    extract = public_suffix._extract()
    assert extract.suffix_list_urls == ()
    assert public_suffix.classify("example.com") is PublicSuffix.ROOT


def test_tldextract_is_not_imported_by_scanner_code() -> None:
    # PSL classification stays in infra: scanners and domain code get the result, not the lib.
    assert not hasattr(scope, "tldextract")
    assert not hasattr(registry, "tldextract")
    assert tldextract is not None


def _answer(qname: str, rdtype: str, *values: str) -> dns.resolver.Answer:
    query = dns.message.make_query(qname, rdtype)
    response = dns.message.make_response(query)
    if values:
        rrset = response.find_rrset(
            response.answer,
            dns.name.from_text(qname),
            dns.rdataclass.IN,
            dns.rdatatype.from_text(rdtype),
            create=True,
        )
        for value in values:
            rrset.add(
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rdtype), value),
                ttl=300,
            )
    return dns.resolver.Answer(
        dns.name.from_text(qname),
        dns.rdatatype.from_text(rdtype),
        dns.rdataclass.IN,
        cast(dns.message.QueryMessage, response),
    )


class FakeAsyncResolver:
    def __init__(self, answers: dict[tuple[str, str], object]) -> None:
        self.answers = answers

    async def resolve(
        self, qname: str, rdtype: str, *, search: bool, raise_on_no_answer: bool
    ) -> dns.resolver.Answer:
        outcome = self.answers.get((qname, rdtype))
        if isinstance(outcome, Exception):
            raise outcome
        if isinstance(outcome, dns.resolver.Answer):
            return outcome
        return _answer(qname, rdtype)


def test_resolver_uses_configured_public_nameservers_and_limits() -> None:
    resolver = DnsPythonResolver(
        nameservers=("1.1.1.1", "8.8.8.8"), timeout=1.5, lifetime=2.5, max_concurrency=3
    )

    assert resolver._resolver.nameservers == ["1.1.1.1", "8.8.8.8"]
    assert resolver._resolver.timeout == 1.5
    assert resolver._resolver.lifetime == 2.5
    async_resolver = resolver._make_async_resolver()
    assert async_resolver.nameservers == ["1.1.1.1", "8.8.8.8"]
    assert async_resolver.use_search_by_default is False


def test_resolver_requires_at_least_one_nameserver() -> None:
    with pytest.raises(ValueError, match="at least one"):
        DnsPythonResolver(nameservers=())


def test_lookup_many_maps_each_query_outcome(monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = DnsPythonResolver()
    fake = FakeAsyncResolver(
        {
            ("example.com", "A"): _answer("example.com", "A", "93.184.216.34"),
            ("missing.example", "A"): dns.resolver.NXDOMAIN(),
            ("empty.example", "A"): None,
            ("broken.example", "A"): dns.resolver.NoNameservers(),
            ("example.com", "TXT"): _answer("example.com", "TXT", '"hello" "world"'),
        }
    )
    monkeypatch.setattr(resolver, "_make_async_resolver", lambda: fake)
    queries = (
        DnsQuery("example.com", DnsRecordType.A),
        DnsQuery("missing.example", DnsRecordType.A),
        DnsQuery("empty.example", DnsRecordType.A),
        DnsQuery("broken.example", DnsRecordType.A),
        DnsQuery("example.com", DnsRecordType.TXT),
    )

    results = resolver.lookup_many(queries)

    assert [result.status for result in results] == [
        DnsStatus.OK,
        DnsStatus.NXDOMAIN,
        DnsStatus.NO_ANSWER,
        DnsStatus.ERROR,
        DnsStatus.OK,
    ]
    assert results[0].values == ("93.184.216.34",)
    assert results[4].values == ("helloworld",)


def test_lookup_many_runs_queries_concurrently_under_the_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = DnsPythonResolver(max_concurrency=2)
    active = 0
    peak = 0

    async def fake_lookup(_resolver: object, query: DnsQuery) -> DnsLookup:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return DnsLookup(query)

    def make_resolver() -> object:
        return object()

    monkeypatch.setattr(resolver, "_make_async_resolver", make_resolver)
    monkeypatch.setattr(resolver, "_lookup_one", fake_lookup)

    results = resolver.lookup_many(
        tuple(DnsQuery(f"h{index}.example", DnsRecordType.A) for index in range(6))
    )

    assert len(results) == 6
    assert peak == 2


def test_lookup_many_without_queries_does_not_start_an_event_loop() -> None:
    assert DnsPythonResolver().lookup_many(()) == ()


def test_txt_record_text_escapes_nul_bytes() -> None:
    class TxtRecord:
        strings = (b"a\x00b",)

    assert _record_text(TxtRecord(), DnsRecordType.TXT) == "a\\0b"
