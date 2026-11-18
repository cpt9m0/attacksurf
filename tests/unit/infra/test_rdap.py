"""RDAP: IANA bootstrap resolution, 24-hour caching and untrusted response parsing.

No test opens a socket: the safe client factory and the resolver are replaced, and the tests
assert which URLs would have been requested and which hosts the redirect hook allows.
"""

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attacksurf.domain.cache import NullCache
from attacksurf.domain.net import DnsError, DnsLookup, DnsQuery, HttpBody
from attacksurf.domain.scope import ScopeError
from attacksurf.infra.rdap import (
    BOOTSTRAP_CACHE_KEY,
    BOOTSTRAP_HOST,
    CACHE_TTL_SECONDS,
    DOMAIN_CACHE_PREFIX,
    IANA_BOOTSTRAP_URL,
    RdapClient,
)
from tests.fakes import FakeCache

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "dns" / "whois"
BOOTSTRAP = (FIXTURES / "iana_bootstrap.json").read_text()
REGISTRATION = (FIXTURES / "rdap_com_example.json").read_text()
DOMAIN = "example.com"
DOMAIN_URL = "https://rdap.verisign.com/com/v1/domain/example.com"
ORG_URL = "https://rdap.publicinterestregistry.org/rdap/domain/example.org"


class StubDns:
    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        raise AssertionError("RDAP only resolves through the safe client")

    def resolve_name(self, host: str) -> tuple[str, ...]:
        return ("93.184.216.34",)

    def lookup_many(self, queries: Sequence[DnsQuery]) -> tuple[DnsLookup, ...]:
        raise AssertionError("RDAP only resolves through the safe client")


class StubHttp:
    """Base client: records the run's allowlist and serves canned responses through it."""

    def __init__(self, responses: dict[str, object] | None = None) -> None:
        self.responses = responses or {}
        self.requests: list[str] = []
        self.policies: list[Any] = []

    def get(self, url: str, *, limit: int) -> HttpBody:
        raise AssertionError("the adapter must request through with_redirect_policy")

    def close(self) -> None:
        pass

    def with_redirect_policy(
        self, resolver: object, *, redirect_allowed: Any, max_redirects: int
    ) -> "RunHttp":
        self.policies.append(redirect_allowed)
        return RunHttp(self, redirect_allowed)


class RunHttp:
    """The run-scoped client: the policy hook is consulted before every request."""

    def __init__(self, inner: StubHttp, allowed: Any) -> None:
        self._inner = inner
        self._allowed = allowed

    def get(self, url: str, *, limit: int) -> HttpBody:
        if not self._allowed(url):
            raise ScopeError("The target is out of scope.")
        self._inner.requests.append(url)
        outcome = self._inner.responses.get(url)
        if isinstance(outcome, Exception):
            raise outcome
        if not isinstance(outcome, HttpBody):
            return HttpBody(404, b"{}")
        return outcome

    def close(self) -> None:
        pass


def body(payload: object) -> HttpBody:
    return HttpBody(200, json.dumps(payload).encode())


def make_client(
    responses: dict[str, object] | None = None,
    *,
    cache: FakeCache | None = None,
) -> tuple[RdapClient, StubHttp, FakeCache]:
    http = StubHttp(
        responses
        if responses is not None
        else {
            IANA_BOOTSTRAP_URL: HttpBody(200, BOOTSTRAP.encode()),
            DOMAIN_URL: HttpBody(200, REGISTRATION.encode()),
            ORG_URL: HttpBody(200, REGISTRATION.encode()),
        }
    )
    actual_cache = cache if cache is not None else FakeCache()
    return RdapClient(http, StubDns(), actual_cache), http, actual_cache


def test_lookup_returns_trimmed_registration_data() -> None:
    client, http, _ = make_client()

    registration = client.lookup(DOMAIN)

    assert registration is not None
    assert registration.domain == DOMAIN
    assert registration.registrar == "RESERVED-Internet Assigned Numbers Authority"
    assert registration.expires_at == datetime(2027, 8, 13, 4, 0, tzinfo=UTC)
    assert registration.statuses == (
        "client delete prohibited",
        "client transfer prohibited",
        "client update prohibited",
    )
    assert http.requests == [IANA_BOOTSTRAP_URL, DOMAIN_URL]


def test_lookup_caches_registration_and_bootstrap_for_24_hours() -> None:
    client, _, cache = make_client()

    client.lookup(DOMAIN)

    assert CACHE_TTL_SECONDS == 24 * 3600
    assert cache.ttls[f"{DOMAIN_CACHE_PREFIX}:{DOMAIN}"] == CACHE_TTL_SECONDS
    assert cache.ttls[BOOTSTRAP_CACHE_KEY] == CACHE_TTL_SECONDS


def test_cached_registration_avoids_the_network() -> None:
    cache = FakeCache(
        {
            f"{DOMAIN_CACHE_PREFIX}:{DOMAIN}": json.dumps(
                {
                    "registrar": "Example Registrar",
                    "expires_at": "2027-01-02T03:04:05+00:00",
                    "statuses": ["client transfer prohibited"],
                }
            )
        }
    )
    client, http, _ = make_client(cache=cache)

    registration = client.lookup(DOMAIN)

    assert registration is not None
    assert registration.registrar == "Example Registrar"
    assert registration.expires_at == datetime(2027, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert http.requests == []


def test_cached_bootstrap_is_reused_for_another_domain() -> None:
    client, http, _ = make_client()

    client.lookup(DOMAIN)
    client.lookup("example.org")

    assert http.requests == [IANA_BOOTSTRAP_URL, DOMAIN_URL, ORG_URL]


def test_unknown_tld_returns_none_without_a_domain_request() -> None:
    client, http, _ = make_client()

    assert client.lookup("example.invalidtld") is None
    assert http.requests == [IANA_BOOTSTRAP_URL]


def test_non_https_base_url_is_rejected() -> None:
    bootstrap = {
        "services": [[["com"], ["http://rdap.verisign.com/com/v1/"]]],
    }
    client, http, _ = make_client({IANA_BOOTSTRAP_URL: body(bootstrap)})

    assert client.lookup(DOMAIN) is None
    assert http.requests == [IANA_BOOTSTRAP_URL]


def test_malformed_bootstrap_is_a_miss() -> None:
    client, _, _ = make_client({IANA_BOOTSTRAP_URL: HttpBody(200, b"not json")})

    assert client.lookup(DOMAIN) is None


def test_unreachable_bootstrap_is_a_miss() -> None:
    client, _, _ = make_client({IANA_BOOTSTRAP_URL: DnsError()})

    assert client.lookup(DOMAIN) is None


def test_a_redirect_to_another_host_is_denied() -> None:
    client, http, _ = make_client()

    client.lookup(DOMAIN)

    policy = http.policies[-1]
    assert policy(IANA_BOOTSTRAP_URL)
    assert policy(DOMAIN_URL)
    assert not policy("https://evil.example/domain/example.com")
    assert BOOTSTRAP_HOST == "data.iana.org"


@pytest.mark.parametrize(
    "response",
    [
        HttpBody(404, b"{}"),
        HttpBody(500, REGISTRATION.encode()),
        HttpBody(200, REGISTRATION.encode(), truncated=True),
        HttpBody(200, b"not json"),
    ],
)
def test_unusable_registration_response_is_a_miss(response: HttpBody) -> None:
    client, _, _ = make_client(
        {
            IANA_BOOTSTRAP_URL: HttpBody(200, BOOTSTRAP.encode()),
            DOMAIN_URL: response,
        }
    )

    assert client.lookup(DOMAIN) is None


def test_a_failed_domain_request_is_a_miss() -> None:
    client, _, _ = make_client(
        {
            IANA_BOOTSTRAP_URL: HttpBody(200, BOOTSTRAP.encode()),
            DOMAIN_URL: ScopeError("The request timed out."),
        }
    )

    assert client.lookup(DOMAIN) is None


def test_a_non_domain_object_is_a_miss() -> None:
    client, _, _ = make_client(
        {
            IANA_BOOTSTRAP_URL: HttpBody(200, BOOTSTRAP.encode()),
            DOMAIN_URL: body({"objectClassName": "entity"}),
        }
    )

    assert client.lookup(DOMAIN) is None


@pytest.mark.parametrize("domain", ["not a domain", "127.0.0.1", ""])
def test_an_invalid_domain_is_a_miss_without_a_request(domain: str) -> None:
    client, http, _ = make_client()

    assert client.lookup(domain) is None
    assert http.requests == []


def test_expiration_is_normalized_to_utc() -> None:
    payload = {
        "objectClassName": "domain",
        "events": [{"eventAction": "Expiration", "eventDate": "2027-01-01T02:00:00+02:00"}],
    }
    client, _, _ = make_client(
        {IANA_BOOTSTRAP_URL: HttpBody(200, BOOTSTRAP.encode()), DOMAIN_URL: body(payload)}
    )

    registration = client.lookup(DOMAIN)

    assert registration is not None
    assert registration.expires_at == datetime(2027, 1, 1, 0, 0, tzinfo=UTC)


def test_a_date_without_an_offset_is_read_as_utc() -> None:
    payload = {
        "events": [{"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00"}],
    }
    client, _, _ = make_client(
        {IANA_BOOTSTRAP_URL: HttpBody(200, BOOTSTRAP.encode()), DOMAIN_URL: body(payload)}
    )

    registration = client.lookup(DOMAIN)

    assert registration is not None
    assert registration.expires_at == datetime(2027, 1, 1, tzinfo=UTC)


def test_an_invalid_expiration_is_ignored() -> None:
    payload = {
        "events": [
            {"eventAction": "expiration", "eventDate": "not-a-date"},
            {"eventAction": "registration", "eventDate": "2027-01-01T00:00:00Z"},
        ],
    }
    client, _, _ = make_client(
        {IANA_BOOTSTRAP_URL: HttpBody(200, BOOTSTRAP.encode()), DOMAIN_URL: body(payload)}
    )

    registration = client.lookup(DOMAIN)

    assert registration is not None
    assert registration.expires_at is None


def test_statuses_are_deduplicated_lowercased_and_capped() -> None:
    payload = {"status": ["Client Transfer Prohibited"] + [f"status-{i}" for i in range(30)]}
    client, _, _ = make_client(
        {IANA_BOOTSTRAP_URL: HttpBody(200, BOOTSTRAP.encode()), DOMAIN_URL: body(payload)}
    )

    registration = client.lookup(DOMAIN)

    assert registration is not None
    assert registration.statuses[0] == "client transfer prohibited"
    assert len(registration.statuses) == 20


def test_a_registrar_without_a_vcard_name_is_none() -> None:
    payload = {"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", []]}]}
    client, _, _ = make_client(
        {IANA_BOOTSTRAP_URL: HttpBody(200, BOOTSTRAP.encode()), DOMAIN_URL: body(payload)}
    )

    registration = client.lookup(DOMAIN)

    assert registration is not None
    assert registration.registrar is None


def test_a_null_cache_still_returns_data() -> None:
    _, http, _ = make_client()
    null_client = RdapClient(http, StubDns(), NullCache())

    assert null_client.lookup(DOMAIN) is not None
