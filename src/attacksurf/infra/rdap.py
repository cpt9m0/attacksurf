"""RDAP registration data for the domain-expiry checks (#19, ADR 0026).

RDAP servers live on per-TLD hosts, so a fixed `ScannerGrant.http_hosts` allowlist cannot name
them. The adapter resolves the TLD's base URL from IANA's bootstrap registry (a fixed public
host) and only then talks to that one host. Both requests go through the safe client, so every
address is pinned and validated; base URLs must be https and redirects never leave the
bootstrap/RDAP host. Responses are untrusted: only the registrar name, the expiration date and
the EPP statuses are kept, capped, and cached for 24 hours as public data. Any failure is a miss
(no finding), never a job failure.
"""

import json
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit

from attacksurf.domain.assets import AssetError, normalize_hostname
from attacksurf.domain.cache import ScanCache
from attacksurf.domain.net import DnsError, DnsResolver, DomainRegistration, HttpBody, ScopeHttp
from attacksurf.domain.scope import ScopeError

IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_HOST = "data.iana.org"
BOOTSTRAP_CACHE_KEY = "rdap-bootstrap:v1"
DOMAIN_CACHE_PREFIX = "rdap-domain:v1"
CACHE_TTL_SECONDS = 24 * 3600
MAX_BODY_BYTES = 256 * 1024
MAX_REDIRECTS = 2
MAX_STATUSES = 20
MAX_STATUS_LENGTH = 100
MAX_REGISTRAR_LENGTH = 200
HTTP_OK = 200
# A bootstrap service entry is [tlds, urls]; a jCard is ["vcard", properties].
_SERVICE_FIELDS = 2
_VCARD_FIELDS = 2
# A jCard property is [name, parameters, type, value].
_PROPERTY_FIELDS = 4


class RdapClient:
    """`RdapLookup` over the IANA bootstrap registry, with a 24-hour public-data cache."""

    def __init__(self, http: ScopeHttp, dns: DnsResolver, cache: ScanCache) -> None:
        self._http = http
        self._dns = dns
        self._cache = cache

    def lookup(self, domain: str) -> DomainRegistration | None:
        try:
            normalized = normalize_hostname(domain)
        except (AssetError, ValueError, UnicodeError):
            return None
        key = f"{DOMAIN_CACHE_PREFIX}:{normalized}"
        cached = _from_cache(self._cache.get(key), normalized)
        if cached is not None:
            return cached
        base = self._base_url(normalized)
        if base is None:
            return None
        host = _host(base)
        body = self._get(
            f"{base.rstrip('/')}/domain/{quote(normalized, safe='')}",
            allowed={BOOTSTRAP_HOST, host} if host else {BOOTSTRAP_HOST},
        )
        if body is None:
            return None
        registration = parse_registration(body, normalized)
        if registration is None:
            return None
        self._cache.set(key, _to_cache(registration), ttl_seconds=CACHE_TTL_SECONDS)
        return registration

    def _base_url(self, domain: str) -> str | None:
        cached = self._cache.get(BOOTSTRAP_CACHE_KEY)
        if cached is not None:
            base = _base_from_payload(_json(cached), domain)
            if base is not None:
                return base
        body = self._get(IANA_BOOTSTRAP_URL, allowed={BOOTSTRAP_HOST})
        if body is None:
            return None
        text = body.content.decode("utf-8", errors="replace")
        base = _base_from_payload(_json(text), domain)
        if base is None:
            return None
        self._cache.set(BOOTSTRAP_CACHE_KEY, text, ttl_seconds=CACHE_TTL_SECONDS)
        return base

    def _get(self, url: str, *, allowed: set[str]) -> HttpBody | None:
        """One request through a client whose redirects stay on `allowed` hosts."""
        client = self._http.with_redirect_policy(
            self._dns,
            redirect_allowed=lambda target: _host(target) in allowed,
            max_redirects=MAX_REDIRECTS,
        )
        try:
            body = client.get(url, limit=MAX_BODY_BYTES)
        except (DnsError, ScopeError):
            return None
        finally:
            client.close()
        if body.status_code != HTTP_OK or body.truncated:
            return None
        return body


def parse_registration(body: HttpBody, domain: str) -> DomainRegistration | None:
    """Trim a RDAP domain object; None for a non-domain or malformed payload."""
    try:
        payload = json.loads(body.content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(payload, dict):
        return None
    object_class = payload.get("objectClassName")
    if object_class is not None and object_class != "domain":
        return None
    return DomainRegistration(
        domain=domain,
        registrar=_registrar(payload.get("entities")),
        expires_at=_expiration(payload.get("events")),
        statuses=_statuses(payload.get("status")),
    )


def _base_from_payload(payload: object, domain: str) -> str | None:
    """First https RDAP base URL for the domain's TLD from the IANA bootstrap registry."""
    tld = domain.rsplit(".", 1)[-1].lower()
    if not isinstance(payload, dict):
        return None
    services = payload.get("services")
    if not isinstance(services, list):
        return None
    for entry in services:
        if not isinstance(entry, list) or len(entry) != _SERVICE_FIELDS:
            continue
        tlds, urls = entry
        if not isinstance(tlds, list) or not isinstance(urls, list):
            continue
        if not any(isinstance(item, str) and item.lower() == tld for item in tlds):
            continue
        for url in urls:
            base = _https_base(url)
            if base is not None:
                return base
    return None


def _https_base(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    try:
        parts = urlsplit(candidate)
        _ = parts.port  # raises ValueError for an invalid port
    except ValueError:
        return None
    if parts.scheme != "https" or not parts.hostname:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if parts.query or parts.fragment:
        return None  # a base URL with a query/fragment can't be joined safely
    return candidate


def _host(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def _expiration(events: object) -> datetime | None:
    if not isinstance(events, list):
        return None
    result: datetime | None = None
    for event in events:
        if not isinstance(event, dict):
            continue
        action = event.get("eventAction")
        if not isinstance(action, str) or action.strip().lower() != "expiration":
            continue
        parsed = _parse_date(event.get("eventDate"))
        if parsed is not None:
            result = parsed
    return result


def _parse_date(value: object) -> datetime | None:
    """RFC 3339 event date, normalized to UTC; a date without an offset is read as UTC."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _registrar(entities: object) -> str | None:
    if not isinstance(entities, list):
        return None
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles")
        if not isinstance(roles, list) or "registrar" not in {
            role.lower() for role in roles if isinstance(role, str)
        }:
            continue
        name = _vcard_name(entity.get("vcardArray"))
        if name is not None:
            return name
    return None


def _vcard_name(vcard: object) -> str | None:
    """The `fn` (formatted name) property of a jCard, capped."""
    if not isinstance(vcard, list) or len(vcard) != _VCARD_FIELDS or vcard[0] != "vcard":
        return None
    properties = vcard[1]
    if not isinstance(properties, list):
        return None
    for prop in properties:
        if not isinstance(prop, list) or len(prop) < _PROPERTY_FIELDS:
            continue
        if prop[0] == "fn" and isinstance(prop[3], str):
            value = prop[3].strip()
            if value:
                return value[:MAX_REGISTRAR_LENGTH]
    return None


def _statuses(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    statuses: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        text = item.strip().lower()
        if text and text not in statuses:
            statuses.append(text[:MAX_STATUS_LENGTH])
        if len(statuses) >= MAX_STATUSES:
            break
    return tuple(statuses)


def _json(value: str) -> object:
    try:
        return json.loads(value)
    except (ValueError, RecursionError):
        return None


def _to_cache(registration: DomainRegistration) -> str:
    return json.dumps(
        {
            "registrar": registration.registrar,
            "expires_at": (
                registration.expires_at.isoformat() if registration.expires_at else None
            ),
            "statuses": list(registration.statuses),
        },
        ensure_ascii=False,
    )


def _from_cache(value: str | None, domain: str) -> DomainRegistration | None:
    if value is None:
        return None
    payload = _json(value)
    if not isinstance(payload, dict):
        return None
    registrar = payload.get("registrar")
    expires = payload.get("expires_at")
    statuses = payload.get("statuses")
    if registrar is None and expires is None and not statuses:
        return None  # an empty or damaged entry is a miss, not a 24-hour hole
    return DomainRegistration(
        domain=domain,
        registrar=registrar if isinstance(registrar, str) else None,
        expires_at=_parse_date(expires) if isinstance(expires, str) else None,
        statuses=(
            tuple(item for item in statuses if isinstance(item, str))
            if isinstance(statuses, list)
            else ()
        ),
    )
