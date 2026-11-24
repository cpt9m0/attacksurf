# Scanners and Rules

Every security check in **attacksurf** is a plugin registered with `@register_scanner` and bounded
by `ScopeGuard` ([security model](security.md)). Plugins emit normalized findings referencing rules
in this catalog (`src/attacksurf/domain/rules/`).

---

## Scan Profiles

| Profile | Availability | Discovery plugins | Check plugins | Discovery cap |
|---|---|---|---|---|
| `dns_passive` | UI, API, CLI | `dns.discovery.ct` | `dns.resolve`, `dns.email`, `dns.takeover`, `dns.takeover.http`, `dns.dnssec`, `dns.ns`, `dns.mx`, `dns.caa`, `dns.whois`, `dns.axfr` | `1000` assets / root |
| `web_active` | UI, API, CLI | `web.probe` | `web.components`, `web.tls`, `web.headers`, `web.cors`, `web.exposures` | `1000` assets / root |
| `dns_scheduled` | Scheduled rescans only (internal) | — | `dns.resolve`, `dns.email`, `dns.dnssec` | `1000` assets / root |

> [!NOTE]
> `dns_scheduled` is absent from user-selectable `PROFILES` so scheduled rescans run read-only DNS
> checks without triggering CT discovery, target HTTP requests, or zone transfers.

---

## Registered Scanners

Passive scanners run on the `passive` queue (`worker-passive`); verified active checks
(`dns.takeover.http`, `dns.axfr`, and upcoming website checks) run on the `active` queue
(`worker-active`, isolated egress) and require `ACTIVE_SCANS_ENABLED=true` plus an unexpired
DNS TXT ownership proof (`_attacksurf-verify.<root>`). `ScopeGuard` skips them with a `skipped`
job status when active scans are disabled or the target is unverified.

| Scanner | Target types | Ownership required | Timeout | Network / capability grant | What it does |
|---|---|---|---|---|---|
| `dns.discovery.ct` | `domain` | No | 180 s | `SERVICES` (`crt.sh`, `api.certspotter.com`), 20 DNS lookups | Enumerates subdomains from Certificate Transparency logs (6 h Redis cache) and probes random labels to mark wildcard DNS zones. |
| `dns.resolve` | `domain`, `subdomain` | No | 60 s | DNS only (40 lookups), offline `ip2asn` | Queries `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `CAA`, `SOA`; follows CNAME chains (≤ 5 hops); builds IP assets, `resolves_to`/`cname_to` edges, PTR/ASN details; flags non-public IP answers; marks unreachable discovered subdomains inactive. |
| `dns.email` | `domain` | No | 60 s | DNS only (10 lookups) | Reads TXT records at apex, `_dmarc` (with organizational domain fallback), `_mta-sts`, and common DKIM selectors (`default`, `google`, `selector1`, `selector2`, `k1`, `mail`) to detect spoofing gaps. |
| `dns.takeover` | `domain`, `subdomain` | No | 60 s | DNS only (16 lookups) | Follows CNAME chains and checks NS delegations against pinned takeover signatures for NXDOMAIN dangling resources. |
| `dns.takeover.http` | `domain`, `subdomain` | **Yes** (`TARGET`) | 60 s | `TARGET` HTTP (64 KiB GET), 16 DNS lookups | Confirms resolving CNAME takeover candidates by issuing one passive HTTP GET to the scanned host and matching unclaimed-service body/status signatures. |
| `dns.dnssec` | `domain` | No | 60 s | Authoritative DNS (18 lookups) | Compares the parent delegation's `DS` records against authoritative `DNSKEY` answers from the zone's nameservers (key tag, algorithm, digest). |
| `dns.ns` | `domain` | No | 60 s | Authoritative DNS (16 lookups) | Queries each authoritative nameserver directly for `SOA` to catch single-NS setups, lame delegations, and split-brain SOA serial mismatches. |
| `dns.mx` | `domain` | No | 60 s | DNS only (20 lookups) | Checks `MX` exchange targets (excluding RFC 7505 null MX) for CNAME targets and missing `A`/`AAAA` address records. |
| `dns.caa` | `domain` | No | 30 s | DNS only (6 lookups) | Walks up to the registrable domain checking for `CAA` records that restrict certificate issuance. |
| `dns.whois` | `domain` | No | 60 s | RDAP via IANA bootstrap (4 DNS lookups, 24 h cache) | Fetches registration metadata for the domain via IANA RDAP bootstrap (`https`) to flag imminent expiry (< 30 / < 7 days) and missing transfer locks. |
| `dns.axfr` | `domain` | **Yes** (`zone_transfer`) | 60 s | Authoritative `AXFR` (16 lookups) | Sends one zone-transfer request per nameserver when the scanned domain owns `NS` records itself; records only whether AXFR succeeded and the record count (never stores zone contents). |
| `web.probe` | `domain`, `subdomain`, `url` | **Yes** (`TARGET`) | 60 s | `TARGET` HTTP (256 KiB GET on ports `80`/`443`, verified same-root redirects ≤ 4 hops), 16 DNS lookups | Probes `https://` then `http://` on active verified hosts, creates `url` assets and `serves` relations with capped metadata (`headers`, redacted `Set-Cookie`, trimmed title, body SHA-256), passively fingerprints `technologies` from the captured response (`scanners/web/fingerprint.py`), flags versioned `Server`/`X-Powered-By` headers (`web.disclosure.version_banner`), stops cleanly before out-of-scope redirects, and deactivates non-responding discovered `url` assets on rescan. |
| `web.components` | `url` | No | 30 s | None (`VulnIntelLookup` read-only DB catalog) | Matches fingerprinted `Asset.details["technologies"]` with concrete versions against the local NVD/KEV/EPSS store using a curated technology → CPE mapping, emitting CVSS-scored `web.components.known_vulnerable` findings bumped on CISA KEV. |
| `web.tls` | `domain`, `subdomain`, `url` (`https://`) | **Yes** (`tls`) | 30 s | Guarded TLS on ports `443`, `8000`, `8080`, `8443`, `8888`, 4 DNS lookups | Inspects TLS certificate chains, hostname match, expiry, key strength, signature algorithms, and legacy TLS 1.0/1.1 acceptance via `ctx.runtime.tls`, storing `Asset.details["tls"]` and chain-summary evidence. |
| `web.headers` | `url` | No | 10 s | None (`Asset.details["web"]` captured by `web.probe`) | Checks HSTS presence/max-age (`≥ 180` days), HTML CSP presence & unsafe script directives without nonces/hashes, clickjacking (`X-Frame-Options` / `frame-ancestors`), `X-Content-Type-Options: nosniff`, redacted session cookie hardening flags, and unredirected HTTP port 80 responses. |
| `web.cors` | `url` | **Yes** (`TARGET`) | 15 s | `TARGET` HTTP (16 KiB GET, `follow_redirects=False`, allowed web ports), 4 DNS lookups | Issues one `GET` with `Origin: https://cors-probe.invalid` and flags reflected foreign `Access-Control-Allow-Origin` paired with `Access-Control-Allow-Credentials: true`. |
| `web.exposures` | `url` | **Yes** (`TARGET`) | 120 s | `TARGET` HTTP (`GET`/`HEAD` on fixed `http_paths` allowlist + 1 soft-404 baseline, `follow_redirects=False`, allowed web ports), 40 DNS lookups | Calibrates a random soft-404 baseline and probes a fixed set of 33 sensitive/admin/API/security.txt paths with strict content validators (`HEAD`-only on backups & `/actuator/heapdump`, key names only on `.env*`, credential redaction on `.git/config`). |

---

## Detection Rules (50)

### DNS Records (`dns.resolve`)

| Rule ID | Default severity | Title | References |
|---|---|---|---|
| `dns.records.private_ip_exposed` | `info` | Public DNS record points to a non-public address | [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918), [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890) |

### Email Security (`dns.email`)

| Rule ID | Default severity | Title | References |
|---|---|---|---|
| `dns.email.spf_missing` | `medium` | No SPF record published | [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) |
| `dns.email.spf_multiple_records` | `medium` | More than one SPF record published | [RFC 7208 §3.2](https://www.rfc-editor.org/rfc/rfc7208#section-3.2) |
| `dns.email.spf_permissive` | `high` | SPF record ends in a permissive qualifier | [RFC 7208 §4.6.4](https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4) |
| `dns.email.spf_too_many_lookups` | `medium` | SPF record needs more than ten DNS lookups | [RFC 7208 §4.6.4](https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4) |
| `dns.email.dmarc_missing` | `medium` | No DMARC record published | [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489) |
| `dns.email.dmarc_policy_none` | `medium` | DMARC policy is monitor-only | [RFC 7489 §6.3](https://www.rfc-editor.org/rfc/rfc7489#section-6.3) |
| `dns.email.dmarc_no_reporting` | `low` | DMARC record requests no aggregate reports | [RFC 7489 §6.2](https://www.rfc-editor.org/rfc/rfc7489#section-6.2) |
| `dns.email.dmarc_pct_partial` | `low` | DMARC policy applies to only some mail | [RFC 7489 §6.3](https://www.rfc-editor.org/rfc/rfc7489#section-6.3) |
| `dns.email.dkim_not_found` | `low` | No DKIM selector found | [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376), [RFC 8301](https://www.rfc-editor.org/rfc/rfc8301) |
| `dns.email.mta_sts_missing` | `info` | No MTA-STS policy published | [RFC 8461](https://www.rfc-editor.org/rfc/rfc8461) |

### Subdomain Takeover (`dns.takeover`, `dns.takeover.http`)

| Rule ID | Default severity | Title | References |
|---|---|---|---|
| `dns.takeover.dangling_cname` | `high` | Dangling CNAME points at a deprovisioned service | [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz), [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034) |
| `dns.takeover.fingerprint_match` | `high` | CNAME target reports an unclaimed service instance | [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) |
| `dns.takeover.dangling_ns` | `critical` | NS delegation points at a nameserver that no longer exists | [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz), [RFC 1912](https://www.rfc-editor.org/rfc/rfc1912) |

### DNSSEC & Zone Hygiene (`dns.dnssec`, `dns.ns`, `dns.mx`, `dns.caa`, `dns.axfr`)

| Rule ID | Default severity | Title | References |
|---|---|---|---|
| `dns.dnssec.not_enabled` | `info` | DNSSEC is not enabled for the zone | [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033), [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035) |
| `dns.dnssec.broken_chain` | `high` | DNSSEC delegation chain is broken | [RFC 4034 §5.1.4](https://www.rfc-editor.org/rfc/rfc4034#section-5.1.4), [RFC 4035 §5.2](https://www.rfc-editor.org/rfc/rfc4035#section-5.2) |
| `dns.ns.single_nameserver` | `low` | Zone is served by a single nameserver | [RFC 1034 §4.1](https://www.rfc-editor.org/rfc/rfc1034#section-4.1), [RFC 1912 §2.8](https://www.rfc-editor.org/rfc/rfc1912#section-2.8) |
| `dns.ns.lame_delegation` | `medium` | Nameserver does not answer authoritatively for the zone | [RFC 1912 §2.8](https://www.rfc-editor.org/rfc/rfc1912#section-2.8), [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034) |
| `dns.ns.inconsistent_soa` | `medium` | Nameservers disagree on the zone's SOA record | [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034), [RFC 1912 §2.8](https://www.rfc-editor.org/rfc/rfc1912#section-2.8) |
| `dns.mx.points_to_cname` | `low` | MX record points at a CNAME | [RFC 5321 §5.1](https://www.rfc-editor.org/rfc/rfc5321#section-5.1), [RFC 2181 §10.3](https://www.rfc-editor.org/rfc/rfc2181#section-10.3) |
| `dns.mx.unresolvable` | `medium` | MX target does not resolve | [RFC 5321 §5.1](https://www.rfc-editor.org/rfc/rfc5321#section-5.1) |
| `dns.caa.missing` | `info` | No CAA record published | [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659) |
| `dns.axfr.allowed` | `high` | Nameserver allows unauthenticated zone transfers | [RFC 5936](https://www.rfc-editor.org/rfc/rfc5936), [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) |

### Domain Registration (`dns.whois`)

| Rule ID | Default severity | Title | References |
|---|---|---|---|
| `dns.whois.expiring_soon` | `medium` *(high < 7 days)* | Domain registration expires soon | [RFC 9083](https://www.rfc-editor.org/rfc/rfc9083), [ICANN expired registration](https://www.icann.org/resources/pages/expired-registration-2013-05-03-en) |
| `dns.whois.registrar_lock_missing` | `medium` | Domain has no registrar transfer lock | [RFC 5731](https://www.rfc-editor.org/rfc/rfc5731), [RFC 9083](https://www.rfc-editor.org/rfc/rfc9083) |

### Web Disclosure (`web.probe`)

| Rule ID | Default severity | Title | References |
|---|---|---|---|
| `web.disclosure.version_banner` | `info` | HTTP response header discloses software version | [OWASP WSTG-INFO-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server), [RFC 9110 §10.2.4](https://www.rfc-editor.org/rfc/rfc9110#section-10.2.4) |

### Web Components (`web.components`)

| Rule ID | Default severity | Title | References |
|---|---|---|---|
| `web.components.known_vulnerable` | `medium` *(CVSS + KEV bump)* | Web component matches known vulnerabilities | [NVD](https://nvd.nist.gov/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss/) |

### Web TLS (`web.tls`)

| Rule ID | Default severity | Title | References |
|---|---|---|---|
| `web.tls.cert_expired` | `high` | TLS certificate is expired | [RFC 5280 §4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5), [OWASP WSTG-CRYP-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security) |
| `web.tls.cert_expiring` | `medium` *(high ≤ 7 days)* | TLS certificate expires soon | [RFC 5280 §4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5) |
| `web.tls.hostname_mismatch` | `high` | TLS certificate does not match the hostname | [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125), [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525) |
| `web.tls.untrusted_chain` | `high` | TLS certificate chain is not trusted | [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280), [OWASP WSTG-CRYP-01](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security) |
| `web.tls.weak_key` | `high` | TLS certificate uses a weak public key | [NIST SP 800-52r2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf) |
| `web.tls.weak_signature` | `high` | TLS certificate uses a weak signature algorithm | [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996), [CA/B Forum BRs](https://cabforum.org/working-groups/server/baseline-requirements/documents/) |
| `web.tls.legacy_protocol` | `medium` | Server accepts deprecated legacy TLS protocol | [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) |

### Web Headers, Cookies & CORS (`web.headers`, `web.cors`)

| Rule ID | Default severity | Title | References |
|---|---|---|---|
| `web.headers.hsts_missing` | `low` | HTTPS response lacks Strict-Transport-Security header | [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797), [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/#http-strict-transport-security) |
| `web.headers.hsts_weak` | `low` | Strict-Transport-Security max-age is below 6 months | [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797) |
| `web.headers.csp_missing` | `low` | HTML response lacks Content-Security-Policy header | [CSP3](https://www.w3.org/TR/CSP3/), [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/#content-security-policy) |
| `web.headers.csp_unsafe` | `low` | Content-Security-Policy permits unsafe script execution | [CSP3](https://www.w3.org/TR/CSP3/#unsafe-inline-usage) |
| `web.headers.clickjacking` | `low` | HTML response lacks framing protection | [OWASP Clickjacking](https://owasp.org/www-community/attacks/Clickjacking), [CSP3 frame-ancestors](https://www.w3.org/TR/CSP3/#directive-frame-ancestors) |
| `web.headers.nosniff_missing` | `info` | Response lacks X-Content-Type-Options: nosniff | [Fetch](https://fetch.spec.whatwg.org/#x-content-type-options-header), [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/#x-content-type-options) |
| `web.cookies.insecure_flags` | `low` | Session-like cookie missing Secure, HttpOnly, or SameSite attribute | [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265), [OWASP SecureCookieAttribute](https://owasp.org/www-community/controls/SecureCookieAttribute) |
| `web.https.no_redirect` | `low` | Plain HTTP endpoint serves content without redirecting to HTTPS | [OWASP WSTG-CRYP-03](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels) |
| `web.cors.wildcard_credentials` | `medium` | CORS reflects arbitrary origin with credentials allowed | [Fetch CORS](https://fetch.spec.whatwg.org/#http-cors-protocol), [OWASP WSTG-CLNT-07](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing) |

### Web Exposures (`web.exposures`)

| Rule ID | Default severity | Title | References |
|---|---|---|---|
| `web.exposure.git_repo` | `high` | Exposed version control metadata on web host | [OWASP WSTG-CONF-05](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces), [CWE-538](https://cwe.mitre.org/data/definitions/538.html) |
| `web.exposure.env_file` | `critical` | Exposed environment configuration file on web host | [CWE-538](https://cwe.mitre.org/data/definitions/538.html), [OWASP WSTG-CONF-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information) |
| `web.exposure.backup_archive` | `high` *(`low` `.DS_Store`)* | Exposed backup archive or metadata file on web host | [OWASP WSTG-CONF-04](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information), [CWE-530](https://cwe.mitre.org/data/definitions/530.html) |
| `web.exposure.debug_endpoint` | `high` *(`medium` Apache/PHP info)* | Exposed diagnostic or debug endpoint on web host | [CWE-215](https://cwe.mitre.org/data/definitions/215.html), [OWASP WSTG-CONF-05](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces) |
| `web.exposure.api_docs` | `info` | Public API documentation endpoint exposed | [OWASP API9:2023](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/) |
| `web.exposure.admin_panel` | `info` | Publicly reachable administrative or login interface | [OWASP WSTG-CONF-05](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces) |
| `web.security.security_txt_missing` | `info` | Host lacks a valid security.txt vulnerability disclosure policy | [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) |

---

Want to add a check? See [Writing a scanner plugin](writing-a-scanner.md).
