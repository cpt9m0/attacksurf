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

WEB_RULES: tuple[Rule, ...] = (VERSION_BANNER, KNOWN_VULNERABLE_COMPONENT)
