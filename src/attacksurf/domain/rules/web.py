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

WEB_RULES: tuple[Rule, ...] = (VERSION_BANNER,)
