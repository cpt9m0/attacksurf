"""Resolvers and PSL classification: bounded, search-list free, and no runtime downloads."""

from dataclasses import dataclass

import dns.resolver
import pytest
import tldextract

from attacksurf.domain import scope
from attacksurf.domain.net import DnsError
from attacksurf.domain.scope import PublicSuffix
from attacksurf.infra import public_suffix
from attacksurf.infra.dns import DnsPythonResolver
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
