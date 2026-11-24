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

HEADERS_HSTS_MISSING = Rule(
    id="web.headers.hsts_missing",
    title="HTTPS response lacks Strict-Transport-Security header",
    description=(
        "An HTTPS endpoint did not return a `Strict-Transport-Security` header, leaving browsers "
        "unable to enforce HTTPS-only connections automatically against protocol downgrade attacks."
    ),
    default_severity=Severity.LOW,
    remediation=(
        "Add `Strict-Transport-Security: max-age=31536000` (and `includeSubDomains` if safe) "
        "to HTTPS responses on $url."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc6797",
        "https://owasp.org/www-project-secure-headers/#http-strict-transport-security",
    ),
)

HEADERS_HSTS_WEAK = Rule(
    id="web.headers.hsts_weak",
    title="Strict-Transport-Security max-age is below 6 months",
    description=(
        "The `Strict-Transport-Security` header specifies a `max-age` shorter than 15,552,000 "
        "seconds (180 days), reducing how long browsers remember to enforce HTTPS."
    ),
    default_severity=Severity.LOW,
    remediation=(
        "Increase the `Strict-Transport-Security` `max-age` on $url to at least 15552000 "
        "(6 months), preferably 31536000 (1 year)."
    ),
    references=("https://www.rfc-editor.org/rfc/rfc6797",),
)

HEADERS_CSP_MISSING = Rule(
    id="web.headers.csp_missing",
    title="HTML response lacks Content-Security-Policy header",
    description=(
        "An HTML endpoint did not return a `Content-Security-Policy` header, removing a major "
        "defense-in-depth control against cross-site scripting and unauthorized resource loads."
    ),
    default_severity=Severity.LOW,
    remediation=(
        "Define and serve a restrictive `Content-Security-Policy` on $url, limiting script "
        "execution to trusted origins or cryptographic nonces/hashes."
    ),
    references=(
        "https://www.w3.org/TR/CSP3/",
        "https://owasp.org/www-project-secure-headers/#content-security-policy",
    ),
)

HEADERS_CSP_UNSAFE = Rule(
    id="web.headers.csp_unsafe",
    title="Content-Security-Policy permits unsafe script execution",
    description=(
        "The `Content-Security-Policy` `script-src` directive (or `default-src` fallback) permits "
        "$tokens without a script nonce or hash, weakening XSS protection."
    ),
    default_severity=Severity.LOW,
    remediation=(
        "Replace $tokens in the `Content-Security-Policy` on $url with cryptographic nonces or "
        "hashes and explicit script allowlists."
    ),
    references=("https://www.w3.org/TR/CSP3/#unsafe-inline-usage",),
)

HEADERS_CLICKJACKING = Rule(
    id="web.headers.clickjacking",
    title="HTML response lacks framing protection",
    description=(
        "An HTML endpoint sets neither `X-Frame-Options` nor a Content-Security-Policy "
        "`frame-ancestors` directive, allowing third-party pages to embed it in a frame."
    ),
    default_severity=Severity.LOW,
    remediation=(
        "Add `Content-Security-Policy: frame-ancestors 'none'` (or `'self'`) and optionally "
        "`X-Frame-Options: DENY` or `SAMEORIGIN` to responses on $url."
    ),
    references=(
        "https://owasp.org/www-community/attacks/Clickjacking",
        "https://www.w3.org/TR/CSP3/#directive-frame-ancestors",
    ),
)

HEADERS_NOSNIFF_MISSING = Rule(
    id="web.headers.nosniff_missing",
    title="Response lacks X-Content-Type-Options: nosniff",
    description=(
        "The HTTP response does not include `X-Content-Type-Options: nosniff`, allowing older "
        "or permissive clients to MIME-sniff responses away from the declared content type."
    ),
    default_severity=Severity.INFO,
    remediation="Send `X-Content-Type-Options: nosniff` on all HTTP responses from $url.",
    references=(
        "https://fetch.spec.whatwg.org/#x-content-type-options-header",
        "https://owasp.org/www-project-secure-headers/#x-content-type-options",
    ),
)

COOKIES_INSECURE_FLAGS = Rule(
    id="web.cookies.insecure_flags",
    title="Session-like cookie missing Secure, HttpOnly, or SameSite attribute",
    description=(
        "One or more cookies with session-like names ($cookies) were set without the full set "
        "of `Secure` (on HTTPS), `HttpOnly`, and `SameSite` hardening attributes."
    ),
    default_severity=Severity.LOW,
    remediation=(
        "Set `HttpOnly`, `SameSite=Lax` (or `Strict`), and `Secure` (for HTTPS) on the "
        "session cookies ($cookies) returned by $url."
    ),
    references=(
        "https://www.rfc-editor.org/rfc/rfc6265",
        "https://owasp.org/www-community/controls/SecureCookieAttribute",
    ),
)

HTTPS_NO_REDIRECT = Rule(
    id="web.https.no_redirect",
    title="Plain HTTP endpoint serves content without redirecting to HTTPS",
    description=(
        "An unencrypted HTTP endpoint ($url) returned content directly rather than redirecting "
        "clients to HTTPS, exposing traffic to interception and tampering."
    ),
    default_severity=Severity.LOW,
    remediation=(
        "Configure $url on port 80 to issue a 301/308 redirect to the corresponding `https://` "
        "URL instead of serving content over cleartext HTTP."
    ),
    references=(
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels",
    ),
)

CORS_WILDCARD_CREDENTIALS = Rule(
    id="web.cors.wildcard_credentials",
    title="CORS reflects arbitrary origin with credentials allowed",
    description=(
        "Sending an untrusted foreign `Origin` to $url produced an `Access-Control-Allow-Origin` "
        "response permitting that origin alongside `Access-Control-Allow-Credentials: true`, "
        "exposing authenticated responses across origins."
    ),
    default_severity=Severity.MEDIUM,
    remediation=(
        "Validate the request `Origin` header on $url against an explicit allowlist of trusted "
        "origins rather than reflecting arbitrary origins when `Access-Control-Allow-Credentials: "
        "true` is set, and include `Vary: Origin`."
    ),
    references=(
        "https://fetch.spec.whatwg.org/#http-cors-protocol",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
    ),
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
    HEADERS_HSTS_MISSING,
    HEADERS_HSTS_WEAK,
    HEADERS_CSP_MISSING,
    HEADERS_CSP_UNSAFE,
    HEADERS_CLICKJACKING,
    HEADERS_NOSNIFF_MISSING,
    COOKIES_INSECURE_FLAGS,
    HTTPS_NO_REDIRECT,
    CORS_WILDCARD_CREDENTIALS,
)
