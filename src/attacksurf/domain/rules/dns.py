"""DNS rules. Resolution stores evidence; only non-public addresses are a finding here."""

from attacksurf.domain.findings import Severity
from attacksurf.domain.rules.catalog import Rule

PRIVATE_IP_EXPOSED = Rule(
    id="dns.records.private_ip_exposed",
    title="Public DNS record points to a non-public address",
    description=(
        "A public DNS record for this asset points to a private, loopback, link-local or "
        "special-purpose IP address. It can leak internal network topology or indicate a "
        "misconfiguration, but it is informational on its own."
    ),
    default_severity=Severity.INFO,
    remediation=(
        "Remove the non-public address from public DNS, or confirm that publishing $address "
        "for $domain is intentional."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc1918",
        "https://www.rfc-editor.org/rfc/rfc6890",
    ),
)

DNS_RULES: tuple[Rule, ...] = (PRIVATE_IP_EXPOSED,)
