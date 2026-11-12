"""Bounded DNS lookups for scanners, through configured public resolvers.

Sending a query to a nameserver found in a response (e.g. a delegated zone) would be an SSRF
primitive, so every lookup goes to the configured stub resolvers and recursion happens upstream.
Search domains are disabled: single-label names are rejected by the gate, so a search list could
only widen scope. `infra.scope_guard` validates every address before a connection; the raw
`lookup_many` path returns record data for scanners (including private addresses, which are
reported, never dialed).
"""

import asyncio
from collections.abc import Sequence
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver

from attacksurf.domain.net import DnsError, DnsLookup, DnsQuery, DnsRecordType, DnsStatus

DNS_TIMEOUT_SECONDS = 3.0
DNS_LIFETIME_SECONDS = 5.0
DNS_MAX_CONCURRENCY = 20
# Public recursive resolvers; operators can replace them with DNS_RESOLVERS.
DEFAULT_NAMESERVERS = ("1.1.1.1", "8.8.8.8")
# Client-side failures (bad answers, missing servers) and OS socket errors. Not BaseException:
# a KeyboardInterrupt must propagate.
DNS_FAILURES = (dns.exception.DNSException, OSError)


class DnsPythonResolver:
    def __init__(
        self,
        *,
        nameservers: Sequence[str] | None = None,
        timeout: float = DNS_TIMEOUT_SECONDS,
        lifetime: float = DNS_LIFETIME_SECONDS,
        max_concurrency: int = DNS_MAX_CONCURRENCY,
    ) -> None:
        servers = tuple(DEFAULT_NAMESERVERS if nameservers is None else nameservers)
        if not servers:
            raise ValueError("at least one DNS resolver is required")
        self._nameservers = servers
        self._timeout = timeout
        self._lifetime = lifetime
        self._max_concurrency = max_concurrency
        self._resolver = self._make_sync_resolver()

    def _configure(self, resolver: Any) -> None:
        resolver.nameservers = list(self._nameservers)
        resolver.timeout = self._timeout
        resolver.lifetime = self._lifetime
        resolver.use_search_by_default = False
        resolver.retry_servfail = False

    def _make_sync_resolver(self) -> Any:
        resolver = dns.resolver.Resolver(configure=False)
        self._configure(resolver)
        return resolver

    def _make_async_resolver(self) -> Any:
        resolver = dns.asyncresolver.Resolver(configure=False)
        self._configure(resolver)
        return resolver

    def lookup_records(self, name: str, rdtype: str) -> tuple[str, tuple[str, ...]]:
        """Arbitrary record types (NS, A) plus the owner name the stub actually answered for.

        The owner is returned because the stub follows CNAMEs: asking `www.example.org` for NS
        can answer with `example.net`'s servers, and ownership discovery must not mistake an
        alias's authorities for the original name's (ADR 0014).
        """
        try:
            answer: Any = self._resolver.resolve(
                name, rdtype, search=False, raise_on_no_answer=False
            )
        except DNS_FAILURES:
            raise DnsError() from None
        if answer.rrset is None:
            return _strip_dot(answer.canonical_name.to_text()), ()
        owner = _strip_dot(answer.rrset.name.to_text())
        return owner, tuple(str(record) for record in answer.rrset)

    def lookup_many(self, queries: Sequence[DnsQuery]) -> tuple[DnsLookup, ...]:
        """Resolve raw records concurrently; per-query failures are returned as `ERROR`."""
        if not queries:
            return ()
        try:
            return asyncio.run(self._lookup_many(tuple(queries)))
        except RuntimeError:
            # No usable event loop in this thread (or one is already running). The caller sees
            # a normal adapter failure, never a dnspython traceback.
            raise DnsError() from None

    async def _lookup_many(self, queries: tuple[DnsQuery, ...]) -> tuple[DnsLookup, ...]:
        resolver = self._make_async_resolver()
        semaphore = asyncio.Semaphore(self._max_concurrency)

        async def one(query: DnsQuery) -> DnsLookup:
            async with semaphore:
                return await self._lookup_one(resolver, query)

        return tuple(await asyncio.gather(*(one(query) for query in queries)))

    async def _lookup_one(self, resolver: Any, query: DnsQuery) -> DnsLookup:
        try:
            answer: Any = await resolver.resolve(
                query.name,
                query.record_type.value,
                search=False,
                raise_on_no_answer=False,
            )
        except dns.resolver.NXDOMAIN:
            return DnsLookup(query, (), DnsStatus.NXDOMAIN)
        except dns.resolver.NoAnswer:
            return DnsLookup(query, (), DnsStatus.NO_ANSWER)
        except DNS_FAILURES:
            return DnsLookup(query, (), DnsStatus.ERROR)
        if answer.rrset is None:
            return DnsLookup(query, (), DnsStatus.NO_ANSWER)
        return DnsLookup(
            query,
            tuple(_record_text(record, query.record_type) for record in answer.rrset),
            DnsStatus.OK,
        )

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


def _record_text(record: Any, record_type: DnsRecordType) -> str:
    """TXT chunks are joined without their presentation quotes; other types keep `str()`."""
    if record_type is DnsRecordType.TXT:
        strings = getattr(record, "strings", ())
        return b"".join(strings).decode("utf-8", errors="replace")
    return str(record)


def _strip_dot(name: str) -> str:
    return name[:-1] if name.endswith(".") else name
