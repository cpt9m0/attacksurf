"""Bounded DNS lookups for scanners, through the system resolver configuration.

Sending a query to a nameserver found in a response (e.g. a delegated zone) would be an SSRF
primitive, so every lookup goes to the configured stub resolver and recursion happens upstream;
`infra.scope_guard` validates the answers. Search domains are disabled: single-label names are
rejected by the gate, so a search list could only widen scope.
"""

from typing import Any

import dns.exception
import dns.resolver

from attacksurf.domain.net import DnsError

DNS_TIMEOUT_SECONDS = 3.0
DNS_LIFETIME_SECONDS = 5.0
# Client-side failures (bad answers, missing servers) and OS socket errors. Not BaseException:
# a KeyboardInterrupt must propagate.
DNS_FAILURES = (dns.exception.DNSException, OSError)


class DnsPythonResolver:
    def __init__(
        self, *, timeout: float = DNS_TIMEOUT_SECONDS, lifetime: float = DNS_LIFETIME_SECONDS
    ) -> None:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = lifetime
        resolver.use_search_by_default = False
        resolver.retry_servfail = False
        self._resolver = resolver

    def resolve_ipv4(self, host: str) -> tuple[str, ...]:
        return self._query(host, "A")

    def resolve_name(self, host: str) -> tuple[str, ...]:
        return tuple(dict.fromkeys(self._query(host, "A") + self._query(host, "AAAA")))

    def _query(self, host: str, rdtype: str) -> tuple[str, ...]:
        try:
            answer: Any = self._resolver.resolve(
                host, rdtype, search=False, raise_on_no_answer=False
            )
        except DNS_FAILURES:
            # Messages can embed resolver or network details; keep them out of `Job.error`.
            raise DnsError() from None
        if answer.rrset is None:
            return ()
        return tuple(str(record) for record in answer.rrset)
