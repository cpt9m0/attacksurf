"""Web rules: disclosure and active HTTP security checks (#73+)."""

from attacksurf.domain.findings import Severity
from attacksurf.domain.rules.catalog import Rule

VERSION_BANNER = Rule(
    id="web.disclosure.version_banner",
    title="HTTP response header discloses software version",
    description=(
        "An HTTP response includes a `Server` or `X-Powered-By` header containing a specific "
        "software version. While not directly exploitable on its own, version banners reveal the "
        "exact technology stack and make targeted vulnerability lookup trivial."
    ),
    default_severity=Severity.INFO,
    remediation=(
        "Configure the web server or reverse proxy for $url to suppress or genericize the "
        "$headers header(s) so software version numbers are not disclosed in HTTP responses."
    ),
    references=(
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
        "https://www.rfc-editor.org/rfc/rfc9110#section-10.2.4",
    ),
)

KNOWN_VULNERABLE_COMPONENT = Rule(
    id="web.components.known_vulnerable",
    title="Web component matches known vulnerabilities",
    description=(
        "A fingerprinted web technology and version match known CVEs in the local NVD, CISA "
        "KEV, and FIRST EPSS vulnerability catalog. Confidence is medium because Linux "
        "distributions often backport security patches while keeping older version banners."
    ),
    default_severity=Severity.MEDIUM,
    remediation=(
        "Verify whether $product $version on $url is patched against $cve_summary, prioritising "
        "any CISA KEV entries, and upgrade to a supported release if vulnerable."
    ),
    references=(
        "https://nvd.nist.gov/",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "https://www.first.org/epss/",
    ),
)

TLS_CERT_EXPIRED = Rule(
    id="web.tls.cert_expired",
    title="TLS certificate is expired",
    description=(
        "The server presents a leaf TLS certificate whose validity period has ended. Browsers "
        "and API clients reject expired certificates or require users to bypass security warnings."
    ),
    default_severity=Severity.HIGH,
    remediation=(
        "Renew and deploy a valid TLS certificate for $host on port $port (leaf expired at "
        "$not_after), and verify automated renewal (for example ACME/Certbot) is working."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
    ),
)

TLS_CERT_EXPIRING = Rule(
    id="web.tls.cert_expiring",
    title="TLS certificate expires soon",
    description=(
        "The leaf TLS certificate expires within 30 days (escalated to high severity within 7 "
        "days). Failing to renew before expiry will cause client connection errors and outages."
    ),
    default_severity=Severity.MEDIUM,
    remediation=(
        "Renew and deploy the TLS certificate for $host on port $port ($days_remaining day(s) "
        "remaining, expires $not_after)."
    ),
    references=("https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5",),
)

TLS_HOSTNAME_MISMATCH = Rule(
    id="web.tls.hostname_mismatch",
    title="TLS certificate does not match the hostname",
    description=(
        "None of the Subject Alternative Names or Common Name in the presented leaf certificate "
        "match the requested host, causing standard TLS clients to reject the connection."
    ),
    default_severity=Severity.HIGH,
    remediation=(
        "Issue and serve a certificate for $host on port $port that includes $host in its "
        "Subject Alternative Name (SAN) extension."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc6125",
        "https://www.rfc-editor.org/rfc/rfc9525",
    ),
)

TLS_UNTRUSTED_CHAIN = Rule(
    id="web.tls.untrusted_chain",
    title="TLS certificate chain is not trusted",
    description=(
        "The presented certificate is self-signed or chains to an unknown or incomplete CA trust "
        "store ($error_code), preventing clients from authenticating the endpoint."
    ),
    default_severity=Severity.HIGH,
    remediation=(
        "Serve a complete certificate chain issued by a publicly trusted Certificate Authority "
        "for $host on port $port, including all intermediate certificates."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc5280",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
    ),
)

TLS_WEAK_KEY = Rule(
    id="web.tls.weak_key",
    title="TLS certificate uses a weak public key",
    description=(
        "A leaf or intermediate certificate in the chain uses a public key below modern security "
        "strength minimums (RSA < 2048 bits, DSA, or a weak/small elliptic curve)."
    ),
    default_severity=Severity.HIGH,
    remediation=(
        "Reissue the affected certificate for $host on port $port with at least an RSA 2048-bit "
        "or P-256 (secp256r1) / Ed25519 key (observed: $details)."
    ),
    references=("https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf",),
)

TLS_WEAK_SIGNATURE = Rule(
    id="web.tls.weak_signature",
    title="TLS certificate uses a weak signature algorithm",
    description=(
        "A leaf or non-root intermediate certificate in the chain is signed using a deprecated "
        "hash algorithm such as SHA-1 or MD5, which modern browsers and clients reject."
    ),
    default_severity=Severity.HIGH,
    remediation=(
        "Reissue the affected certificate chain for $host on port $port using SHA-256 or "
        "stronger signatures (observed: $details)."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc8996",
        "https://cabforum.org/working-groups/server/baseline-requirements/documents/",
    ),
)

TLS_LEGACY_PROTOCOL = Rule(
    id="web.tls.legacy_protocol",
    title="Server accepts deprecated legacy TLS protocol",
    description=(
        "The TLS endpoint negotiated a deprecated protocol version ($protocols) known to have "
        "cryptographic weaknesses and retired by RFC 8996."
    ),
    default_severity=Severity.MEDIUM,
    remediation=(
        "Disable $protocols on $host:$port and configure the TLS listener to accept TLS 1.2 and "
        "TLS 1.3 only."
    ),
    references=("https://www.rfc-editor.org/rfc/rfc8996",),
)

WEB_RULES: tuple[Rule, ...] = (
    VERSION_BANNER,
    KNOWN_VULNERABLE_COMPONENT,
    TLS_CERT_EXPIRED,
    TLS_CERT_EXPIRING,
    TLS_HOSTNAME_MISMATCH,
    TLS_UNTRUSTED_CHAIN,
    TLS_WEAK_KEY,
    TLS_WEAK_SIGNATURE,
    TLS_LEGACY_PROTOCOL,
)
