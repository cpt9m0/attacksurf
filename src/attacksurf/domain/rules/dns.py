"""DNS rules: record exposure (#16), email authentication (#17), takeover candidates (#18),
DNSSEC/NS/MX/CAA hygiene, registration expiry and zone transfers (#19)."""

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

DNSKEY_NOT_ENABLED = Rule(
    id="dns.dnssec.not_enabled",
    title="DNSSEC is not enabled for the zone",
    description=(
        "The zone publishes no DS record at its parent, so resolvers cannot validate its "
        "answers and a network attacker can forge them. Some registries do not offer DS "
        "records, so this is informational on its own."
    ),
    default_severity=Severity.INFO,
    remediation=(
        "Sign the $zone zone and publish its DS record at the registrar (or with the parent "
        "zone). Keep the DS record in step with the zone's DNSKEY records when keys roll."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc4033",
        "https://www.rfc-editor.org/rfc/rfc4035",
    ),
)

DNSKEY_BROKEN_CHAIN = Rule(
    id="dns.dnssec.broken_chain",
    title="DNSSEC delegation chain is broken",
    description=(
        "The parent zone publishes a DS record for $zone, but none of the zone's published "
        "DNSKEY records matches it. Validating resolvers treat the zone as bogus and return "
        "SERVFAIL, so the domain becomes unreachable for DNSSEC-validating clients."
    ),
    default_severity=Severity.HIGH,
    remediation=(
        "Publish the DS record that matches the zone's current DNSKEY (or remove the stale DS "
        "record) at the registrar, then confirm a validating resolver can resolve $zone."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc4034#section-5.1.4",
        "https://www.rfc-editor.org/rfc/rfc4035#section-5.2",
    ),
)

SINGLE_NAMESERVER = Rule(
    id="dns.ns.single_nameserver",
    title="Zone is served by a single nameserver",
    description=(
        "The zone has only one nameserver. If it becomes unreachable, the whole zone stops "
        "resolving; RFC 1034 expects at least two servers, ideally on different networks."
    ),
    default_severity=Severity.LOW,
    remediation=(
        "Add a second nameserver for $zone at a different provider or network, and list both "
        "in the zone's NS records."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc1034#section-4.1",
        "https://www.rfc-editor.org/rfc/rfc1912#section-2.8",
    ),
)

LAME_DELEGATION = Rule(
    id="dns.ns.lame_delegation",
    title="Nameserver does not answer authoritatively for the zone",
    description=(
        "The nameserver $server is listed in the NS records for $zone but does not answer "
        "authoritatively for the zone's SOA record. Resolvers that pick that server get no "
        "usable answer, so resolution is unreliable."
    ),
    default_severity=Severity.MEDIUM,
    remediation=(
        "Remove $server from the NS records for $zone, or fix its zone data so it serves the "
        "zone authoritatively. Confirm every listed nameserver answers an SOA query with the "
        "authoritative-answer flag set."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc1912#section-2.8",
        "https://www.rfc-editor.org/rfc/rfc1034",
    ),
)

INCONSISTENT_SOA = Rule(
    id="dns.ns.inconsistent_soa",
    title="Nameservers disagree on the zone's SOA record",
    description=(
        "The authoritative nameservers for $zone returned $count different SOA serials, so "
        "they serve different versions of the zone (a split-brain setup). Records can appear "
        "or disappear depending on which server a resolver asks."
    ),
    default_severity=Severity.MEDIUM,
    remediation=(
        "Make every nameserver for $zone serve the same zone data and the same SOA serial, "
        "for example by fixing the zone transfer between the primary and its secondaries."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc1034",
        "https://www.rfc-editor.org/rfc/rfc1912#section-2.8",
    ),
)

MX_POINTS_TO_CNAME = Rule(
    id="dns.mx.points_to_cname",
    title="MX record points at a CNAME",
    description=(
        "The MX record for $domain points at $target, which is a CNAME. Mail servers expect "
        "MX targets to be hostnames with address records; following the alias is not required "
        "and some mail servers will fail to deliver."
    ),
    default_severity=Severity.LOW,
    remediation=(
        "Point the MX record for $domain at $target's canonical name (or remove the CNAME and "
        "give $target its own A/AAAA records)."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc5321#section-5.1",
        "https://www.rfc-editor.org/rfc/rfc2181#section-10.3",
    ),
)

MX_UNRESOLVABLE = Rule(
    id="dns.mx.unresolvable",
    title="MX target does not resolve",
    description=(
        "The MX record for $domain points at $target, which has no A or AAAA records. Mail "
        "sent to the domain cannot be delivered to that server."
    ),
    default_severity=Severity.MEDIUM,
    remediation=(
        "Update the MX record for $domain to a host that resolves, or restore the address "
        "records for $target."
    ),
    references=("https://www.rfc-editor.org/rfc/rfc5321#section-5.1",),
)

CAA_MISSING = Rule(
    id="dns.caa.missing",
    title="No CAA record published",
    description=(
        "Neither the domain nor its registrable parent publishes a CAA record, so any "
        "certificate authority may issue a certificate for it. CAA lets the owner restrict "
        "issuance to the CAs they use."
    ),
    default_severity=Severity.INFO,
    remediation=(
        "Publish a CAA record at $zone listing the certificate authorities you use, for "
        'example: $zone CAA 0 issue "letsencrypt.org".'
    ),
    references=("https://www.rfc-editor.org/rfc/rfc8659",),
)

EXPIRING_SOON = Rule(
    id="dns.whois.expiring_soon",
    title="Domain registration expires soon",
    description=(
        "The registration for $domain expires on $expires_at ($days days). If it lapses, "
        "anyone can register the domain and take over every record and service under it."
    ),
    default_severity=Severity.MEDIUM,
    remediation=(
        "Renew $domain with $registrar before $expires_at, and enable auto-renew so a missed "
        "notice cannot let the registration lapse."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc9083",
        "https://www.icann.org/resources/pages/expired-registration-2013-05-03-en",
    ),
)

REGISTRAR_LOCK_MISSING = Rule(
    id="dns.whois.registrar_lock_missing",
    title="Domain has no registrar transfer lock",
    description=(
        "RDAP reports no client or server transfer prohibition for $domain. Without that "
        "lock, a stolen registrar credential is enough to move the domain to another "
        "registrar, taking its DNS with it."
    ),
    default_severity=Severity.MEDIUM,
    remediation=(
        "Enable the registrar lock for $domain (the clientTransferProhibited status) with "
        "$registrar, and keep the registrar account protected with strong authentication."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc5731",
        "https://www.rfc-editor.org/rfc/rfc9083",
    ),
)

AXFR_ALLOWED = Rule(
    id="dns.axfr.allowed",
    title="Nameserver allows unauthenticated zone transfers",
    description=(
        "The nameserver $server transferred the $zone zone to an unauthenticated client "
        "($records records in the first response), exposing every hostname and record in it. "
        "Zone transfers should be limited to the zone's authorized secondaries."
    ),
    default_severity=Severity.HIGH,
    remediation=(
        "Restrict AXFR on $server to the zone's secondary nameservers (for example with "
        "allow-transfer/ACL configuration), and confirm an unauthenticated transfer is refused."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc5936",
        "https://www.rfc-editor.org/rfc/rfc1035",
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
    DNSKEY_NOT_ENABLED,
    DNSKEY_BROKEN_CHAIN,
    SINGLE_NAMESERVER,
    LAME_DELEGATION,
    INCONSISTENT_SOA,
    MX_POINTS_TO_CNAME,
    MX_UNRESOLVABLE,
    CAA_MISSING,
    EXPIRING_SOON,
    REGISTRAR_LOCK_MISSING,
    AXFR_ALLOWED,
)
