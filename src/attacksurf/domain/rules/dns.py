"""DNS rules: record exposure (#16), email authentication (#17), takeover candidates (#18)."""

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

SPF_MISSING = Rule(
    id="dns.email.spf_missing",
    title="No SPF record published",
    description=(
        "The domain publishes no SPF record, so receivers cannot tell which hosts may send "
        "mail for it. Anyone can forge the domain in the envelope sender (MAIL FROM)."
    ),
    default_severity=Severity.MEDIUM,
    remediation=(
        "Publish an SPF TXT record at $domain listing only the hosts allowed to send mail "
        'for it. If the domain never sends mail, publish "v=spf1 -all" to state that '
        "explicitly."
    ),
    references=("https://www.rfc-editor.org/rfc/rfc7208",),
)

SPF_MULTIPLE_RECORDS = Rule(
    id="dns.email.spf_multiple_records",
    title="More than one SPF record published",
    description=(
        "The domain publishes more than one SPF record. Receivers must ignore SPF entirely "
        "when that happens (a permanent error), so the domain is effectively unprotected."
    ),
    default_severity=Severity.MEDIUM,
    remediation=(
        'Merge the SPF records at $domain into a single TXT record starting with "v=spf1"; '
        "receivers ignore domains that publish more than one."
    ),
    references=("https://www.rfc-editor.org/rfc/rfc7208#section-3.2",),
)

SPF_PERMISSIVE = Rule(
    id="dns.email.spf_permissive",
    title="SPF record ends in a permissive qualifier",
    description=(
        "The SPF record authorizes every other host (`+all`) or explicitly takes no position "
        "on them (`?all`), so spoofed mail still passes SPF."
    ),
    default_severity=Severity.HIGH,
    remediation=(
        'Replace the permissive ending ($ending) in the SPF record at $domain with "-all" '
        '(fail), so receivers reject mail from unlisted hosts. Use "~all" only while '
        "testing a new record."
    ),
    references=("https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4",),
)

SPF_TOO_MANY_LOOKUPS = Rule(
    id="dns.email.spf_too_many_lookups",
    title="SPF record needs more than ten DNS lookups",
    description=(
        "Evaluating the SPF record requires more than ten DNS-querying terms (`include`, "
        "`a`, `mx`, `ptr`, `exists`, `redirect`). Receivers must abort evaluation (a "
        "permanent error), so the record provides no protection."
    ),
    default_severity=Severity.MEDIUM,
    remediation=(
        "Reduce the DNS-querying terms in the SPF record at $domain to ten or fewer "
        "($count found), for example by flattening includes into address literals; "
        "receivers treat more than ten lookups as a permanent error."
    ),
    references=("https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4",),
)

DMARC_MISSING = Rule(
    id="dns.email.dmarc_missing",
    title="No DMARC record published",
    description=(
        "The domain publishes no DMARC policy, so receivers have no instruction to reject "
        "mail that fails SPF and DKIM alignment. The domain is spoofable even with SPF or "
        "DKIM alone."
    ),
    default_severity=Severity.MEDIUM,
    remediation=(
        'Publish a DMARC TXT record at _dmarc.$domain (for example "v=DMARC1; p=reject; '
        'rua=mailto:dmarc@$domain"), so receivers reject unauthenticated mail that claims '
        "to come from $domain. Domains that never send mail need this too."
    ),
    references=("https://www.rfc-editor.org/rfc/rfc7489",),
)

DMARC_POLICY_NONE = Rule(
    id="dns.email.dmarc_policy_none",
    title="DMARC policy is monitor-only",
    description=(
        "The DMARC policy is `p=none`: receivers take no action on mail that fails "
        "authentication. Spoofed mail is still delivered."
    ),
    default_severity=Severity.MEDIUM,
    remediation=(
        'Raise the DMARC policy for $domain from "p=none" to "p=quarantine" and then '
        '"p=reject" once legitimate mail passes SPF or DKIM alignment.'
    ),
    references=("https://www.rfc-editor.org/rfc/rfc7489#section-6.3",),
)

DMARC_NO_REPORTING = Rule(
    id="dns.email.dmarc_no_reporting",
    title="DMARC record requests no aggregate reports",
    description=(
        "The DMARC record names no aggregate-report mailbox (`rua`) and no failure-report "
        "mailbox (`ruf`), so the owner never learns who sends mail in the domain's name."
    ),
    default_severity=Severity.LOW,
    remediation=(
        "Add an aggregate-report mailbox to the DMARC record for $domain "
        '("rua=mailto:dmarc@$domain") so abuse and misconfiguration become visible.'
    ),
    references=("https://www.rfc-editor.org/rfc/rfc7489#section-6.2",),
)

DMARC_PCT_PARTIAL = Rule(
    id="dns.email.dmarc_pct_partial",
    title="DMARC policy applies to only some mail",
    description=(
        "The DMARC record sets `pct` below 100, so the policy is applied to only a fraction "
        "of unauthenticated mail and the rest is delivered normally."
    ),
    default_severity=Severity.LOW,
    remediation=(
        'Raise "pct" to 100 in the DMARC record for $domain (or remove the tag, which '
        "defaults to 100) so the policy applies to all mail."
    ),
    references=("https://www.rfc-editor.org/rfc/rfc7489#section-6.3",),
)

DKIM_NOT_FOUND = Rule(
    id="dns.email.dkim_not_found",
    title="No DKIM selector found",
    description=(
        "None of the probed DKIM selectors publishes a key, so mail from the domain likely "
        "carries no DKIM signature. Only common selectors are probed, so this is a hint, "
        "not proof that DKIM is absent."
    ),
    default_severity=Severity.LOW,
    remediation=(
        "Enable DKIM signing with the mail provider for $domain and publish the selector "
        "TXT record it gives you under <selector>._domainkey.$domain. No common selector "
        "was found, so confirm with the provider before treating this as a gap."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc6376",
        "https://www.rfc-editor.org/rfc/rfc8301",
    ),
)

MTA_STS_MISSING = Rule(
    id="dns.email.mta_sts_missing",
    title="No MTA-STS policy published",
    description=(
        "The domain publishes no MTA-STS policy, so sending servers fall back to "
        "opportunistic TLS and a network attacker can strip encryption. Informational: "
        "enforcing TLS is hardening, not spoofing protection."
    ),
    default_severity=Severity.INFO,
    remediation=(
        "Optionally publish an MTA-STS policy for $domain: a TXT record at "
        '_mta-sts.$domain ("v=STSv1; id=...") plus a policy file at '
        "https://mta-sts.$domain/.well-known/mta-sts.txt."
    ),
    references=("https://www.rfc-editor.org/rfc/rfc8461",),
)

TAKEOVER_DANGLING_CNAME = Rule(
    id="dns.takeover.dangling_cname",
    title="Dangling CNAME points at a deprovisioned service",
    description=(
        "The name CNAMEs to $target on $service, a service whose unclaimed instances stop "
        "resolving, and the target no longer resolves (NXDOMAIN). Anyone can usually register "
        "the abandoned name or account and serve content under this subdomain, inheriting its "
        "cookies, trust and search ranking."
    ),
    default_severity=Severity.HIGH,
    remediation=(
        "Remove the CNAME record for $domain pointing at $target, or re-provision the "
        "$service resource it named and confirm it resolves again. Do not leave the record "
        "in place while the resource is unclaimed."
    ),
    references=(
        "https://github.com/EdOverflow/can-i-take-over-xyz",
        "https://www.rfc-editor.org/rfc/rfc1034",
    ),
)

TAKEOVER_FINGERPRINT_MATCH = Rule(
    id="dns.takeover.fingerprint_match",
    title="CNAME target reports an unclaimed service instance",
    description=(
        "The name CNAMEs to $target on $service, and the service answers with its "
        '"not found" signature for unclaimed instances. The resource the record was created '
        "for has been deleted, so anyone can usually claim the name and serve content under "
        "this subdomain."
    ),
    default_severity=Severity.HIGH,
    remediation=(
        "Remove the CNAME record for $domain pointing at $target, or re-create the $service "
        "resource it named so the service stops reporting it as unclaimed."
    ),
    references=("https://github.com/EdOverflow/can-i-take-over-xyz",),
)

TAKEOVER_DANGLING_NS = Rule(
    id="dns.takeover.dangling_ns",
    title="NS delegation points at a nameserver that no longer exists",
    description=(
        "The name is delegated to the nameserver $target, which no longer resolves "
        "(NXDOMAIN). The delegation is broken, and where the nameserver's own domain has "
        "lapsed anyone can re-register it and answer authoritatively for this zone, "
        "controlling every record under it."
    ),
    default_severity=Severity.CRITICAL,
    remediation=(
        "Remove or replace the NS record for $domain delegating to $target. Point the "
        "delegation only at nameservers that exist and serve this zone, and confirm the "
        "nameserver's own domain registration is current."
    ),
    references=(
        "https://github.com/EdOverflow/can-i-take-over-xyz",
        "https://www.rfc-editor.org/rfc/rfc1912",
    ),
)

DNS_RULES: tuple[Rule, ...] = (
    PRIVATE_IP_EXPOSED,
    SPF_MISSING,
    SPF_MULTIPLE_RECORDS,
    SPF_PERMISSIVE,
    SPF_TOO_MANY_LOOKUPS,
    DMARC_MISSING,
    DMARC_POLICY_NONE,
    DMARC_NO_REPORTING,
    DMARC_PCT_PARTIAL,
    DKIM_NOT_FOUND,
    MTA_STS_MISSING,
    TAKEOVER_DANGLING_CNAME,
    TAKEOVER_FINGERPRINT_MATCH,
    TAKEOVER_DANGLING_NS,
)
