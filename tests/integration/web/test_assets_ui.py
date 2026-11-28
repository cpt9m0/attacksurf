"""Asset pages against real Postgres, signed in through the real signup flow.

Each request closes the shared `db_session` at teardown, which detaches ORM rows: helpers
pass ids around and tests re-read rows after requests.
"""

import re
import ssl
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from werkzeug.test import TestResponse

from attacksurf.domain.accounts import Role
from attacksurf.domain.assets import AssetSource, AssetType, RelationKind
from attacksurf.domain.findings import Confidence, Severity, finding_fingerprint
from attacksurf.domain.jobs import JobTask, PipelineQueue, TaskQueue
from attacksurf.domain.net import HttpBody, TlsError
from attacksurf.domain.scans import ScanStatus, ScanTrigger
from attacksurf.domain.verification import VerificationMethod, VerificationStatus
from attacksurf.infra import public_suffix
from attacksurf.infra.db.models import (
    Asset,
    Finding,
    Membership,
    Scan,
    ScanSchedule,
    User,
    Verification,
)
from attacksurf.infra.scope_guard import ScopeGuard
from attacksurf.infra.tls import RawTlsHandshake
from attacksurf.scanners.profiles import PROFILES
from attacksurf.scanners.registry import registry
from attacksurf.scanners.web import components as _web_components  # noqa: F401
from attacksurf.scanners.web import exposures as _web_exposures  # noqa: F401
from attacksurf.scanners.web import headers as _web_headers  # noqa: F401
from attacksurf.scanners.web import probe as _web_probe  # noqa: F401
from attacksurf.scanners.web import tls as _web_tls  # noqa: F401
from attacksurf.scanners.web import wordpress as _web_wordpress  # noqa: F401
from attacksurf.services import asset_views
from attacksurf.services import scans as scans_service
from attacksurf.services.assets import record_asset, record_relation
from attacksurf.services.ownership import DbOwnershipChecker
from attacksurf.services.scanner_jobs import run_check
from tests.dns_fakes import FakeScopeHttp, MutableDnsZone

_CSRF = re.compile(r'name="csrf_token" value="([^"]+)"')
_INLINE_CODE = (
    re.compile(r"<script(?![^>]*\ssrc=)[^>]*>"),
    re.compile(r"\son[a-z]+\s*="),
    re.compile(r"\sstyle\s*="),
)
HTMX = {"HX-Request": "true"}


def _csrf(client: FlaskClient, path: str = "/assets") -> str:
    match = _CSRF.search(client.get(path).get_data(as_text=True))
    assert match
    return match.group(1)


def _signup(app: Flask, email: str) -> FlaskClient:
    client = app.test_client()
    response = client.post(
        "/signup",
        data={
            "email": email,
            "password": "correct horse battery",
            "org_name": email.split("@", maxsplit=1)[0],
            "csrf_token": _csrf(client, "/signup"),
        },
    )
    assert response.status_code == 302, response.get_data(as_text=True)
    return client


def _add(client: FlaskClient, value: str, headers: dict[str, str] | None = None) -> TestResponse:
    return client.post(
        "/assets", data={"value": value, "csrf_token": _csrf(client)}, headers=headers or {}
    )


def _root_id(session: Session, value: str = "example.com") -> UUID:
    return session.scalars(
        select(Asset.id).where(Asset.type == AssetType.DOMAIN, Asset.value == value)
    ).one()


def _discover(session: Session, root_id: UUID, kind: AssetType, value: str) -> UUID:
    root = session.get(Asset, root_id)
    assert root is not None
    asset_id = record_asset(
        session, root.org_id, kind, value, source=AssetSource.DISCOVERED, parent_id=root_id
    ).id
    session.commit()
    return asset_id


def _org_id(session: Session, asset_id: UUID) -> UUID:
    asset = session.get(Asset, asset_id)
    assert asset is not None
    return asset.org_id


def _is_active(session: Session, asset_id: UUID) -> bool:
    session.expire_all()
    asset = session.get(Asset, asset_id)
    assert asset is not None
    return asset.is_active


def _html(client: FlaskClient, path: str, headers: dict[str, str] | None = None) -> str:
    response = client.get(path, headers=headers or {})
    assert response.status_code == 200, response.status_code
    return response.get_data(as_text=True)


def _row(html: str, asset_id: UUID) -> str:
    """The list's table row whose first cell links to `asset_id`."""
    start = html.index(f'<tr><td><a class="mono" href="/assets/{asset_id}"')
    return html[start : html.index("</tr>", start)]


@pytest.fixture
def alice(db_app: Flask) -> FlaskClient:
    return _signup(db_app, "alice@example.com")


def test_add_domain_then_see_it_listed_and_open_its_detail(
    alice: FlaskClient, db_session: Session
) -> None:
    # Acceptance criterion of #13.
    response = _add(alice, "Example.COM")

    root_id = _root_id(db_session)
    assert response.status_code == 303
    assert response.headers["Location"] == f"/assets/{root_id}"
    detail = _html(alice, f"/assets/{root_id}")
    assert '<h1 class="mono">example.com</h1>' in detail
    assert "Added example.com. Run a scan" in detail  # the flash survives the redirect
    assert "It becomes inactive and is no longer scanned." in detail  # no children yet
    assert "example.com" in _row(_html(alice, "/assets"), root_id)


def test_htmx_add_navigates_with_hx_redirect(alice: FlaskClient, db_session: Session) -> None:
    response = _add(alice, "example.com", HTMX)

    assert response.status_code == 200
    assert response.headers["HX-Redirect"] == f"/assets/{_root_id(db_session)}"


def test_root_admin_can_turn_off_recurring_scans(alice: FlaskClient, db_session: Session) -> None:
    _add(alice, "example.com")
    root_id = _root_id(db_session)
    page = f"/assets/{root_id}"
    assert "Scheduled rescans" in _html(alice, page)

    response = alice.post(
        f"{page}/schedule", data={"csrf_token": _csrf(alice, page), "frequency": "daily"}
    )

    assert (response.status_code, response.headers["Location"]) == (303, page)
    row = db_session.scalars(
        select(ScanSchedule).where(ScanSchedule.root_asset_id == root_id)
    ).one()
    assert (row.enabled, row.next_run_at, row.frequency) == (False, None, "daily")
    assert "Scheduling is off." in _html(alice, page)

    response = alice.post(
        f"{page}/schedule",
        data={"csrf_token": _csrf(alice, page), "frequency": "daily", "enabled": "1"},
    )

    assert response.status_code == 303
    changed = db_session.scalars(
        select(ScanSchedule).where(ScanSchedule.root_asset_id == root_id)
    ).one()
    assert changed.enabled
    assert changed.next_run_at is not None


def test_foreign_root_schedule_returns_404(
    alice: FlaskClient, db_app: Flask, db_session: Session
) -> None:
    bob = _signup(db_app, "bob@example.com")
    _add(bob, "example.org")
    root_id = _root_id(db_session, "example.org")

    response = alice.post(
        f"/assets/{root_id}/schedule",
        data={"csrf_token": _csrf(alice), "frequency": "weekly"},
    )

    assert response.status_code == 404


def test_member_sees_schedule_but_cannot_edit(alice: FlaskClient, db_session: Session) -> None:
    _add(alice, "example.com")
    root_id = _root_id(db_session)
    membership = db_session.scalars(
        select(Membership).join(User).where(User.email == "alice@example.com")
    ).one()
    membership.role = Role.MEMBER
    db_session.commit()
    path = f"/assets/{root_id}"

    html = _html(alice, path)

    assert "Scheduled rescans" in html
    assert "Save schedule" not in html
    assert (
        alice.post(
            f"{path}/schedule", data={"csrf_token": _csrf(alice), "frequency": "daily"}
        ).status_code
        == 403
    )


def test_schedule_form_requires_csrf_and_known_frequency(
    alice: FlaskClient, db_session: Session
) -> None:
    _add(alice, "example.com")
    root_id = _root_id(db_session)
    path = f"/assets/{root_id}/schedule"

    assert alice.post(path, data={"frequency": "weekly"}).status_code == 400
    assert (
        alice.post(path, data={"csrf_token": _csrf(alice), "frequency": "monthly"}).status_code
        == 422
    )


def test_htmx_add_with_invalid_name_returns_the_form_with_an_inline_error(
    alice: FlaskClient,
) -> None:
    response = _add(alice, "printer.corp", HTMX)

    html = response.get_data(as_text=True)
    assert response.status_code == 422
    assert html.lstrip().startswith('<form id="add-domain"')  # just the form, swapped in place
    assert "Internal-only domain names can&#39;t be scanned." in html
    assert 'aria-invalid="true"' in html
    assert 'value="printer.corp"' in html
    assert " autofocus" in html


def test_add_without_js_rerenders_the_page_with_the_error(alice: FlaskClient) -> None:
    _add(alice, "example.com")

    response = _add(alice, "example.com")

    html = response.get_data(as_text=True)
    assert response.status_code == 422
    assert "<h1>Assets</h1>" in html
    assert "example.com is already in your assets." in html


def test_add_without_csrf_token_is_rejected(alice: FlaskClient) -> None:
    assert alice.post("/assets", data={"value": "example.com"}).status_code == 400


def test_empty_list_explains_how_to_start(alice: FlaskClient) -> None:
    html = _html(alice, "/assets")

    assert "No assets yet" in html
    assert "0 assets" in html


def test_list_shows_discovered_assets_with_root_and_finding_stats(
    alice: FlaskClient, db_session: Session
) -> None:
    _add(alice, "example.com")
    root_id = _root_id(db_session)
    www_id = _discover(db_session, root_id, AssetType.SUBDOMAIN, "www.example.com")
    org_id = _org_id(db_session, root_id)
    db_session.add(
        Finding(
            org_id=org_id,
            asset_id=www_id,
            rule_id="dns.email.dmarc_missing",
            fingerprint=finding_fingerprint(org_id, www_id, "dns.email.dmarc_missing"),
            title="No DMARC record",
            description="No policy.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            first_seen=datetime.now(UTC),
            last_seen=datetime.now(UTC),
        )
    )
    db_session.commit()

    html = _html(alice, "/assets")

    assert "2 assets" in html
    row = _row(html, www_id)
    assert f'href="/assets/{root_id}">example.com</a>' in row
    assert 'class="badge sev-high"' in row
    assert "just now" in row


def test_list_filters_from_the_query_string(alice: FlaskClient, db_session: Session) -> None:
    _add(alice, "example.com")
    root_id = _root_id(db_session)
    ip_id = _discover(db_session, root_id, AssetType.IP, "192.0.2.10")

    html = _html(alice, "/assets?type=ip&q=192")

    assert "1 asset matches these filters" in html
    assert "192.0.2.10" in _row(html, ip_id)
    with pytest.raises(ValueError, match="substring not found"):
        _row(html, root_id)
    assert '<option value="ip" selected>' in html
    assert 'value="192"' in html


def test_filter_requests_return_the_results_region(alice: FlaskClient) -> None:
    _add(alice, "example.com")

    html = _html(alice, "/assets?q=exa", HTMX)

    # HTMX picks #asset-results out of the fragment (hx-select).
    assert '<div id="asset-results">' in html
    assert "<html" not in html


def test_filter_and_tab_requests_are_synchronized(alice: FlaskClient, db_session: Session) -> None:
    # The search box and the form both issue requests into #asset-results (and tab links into
    # #asset-tab): `this:replace` on the shared ancestor aborts the older one, so a slow stale
    # response can't overwrite newer results. Descendants inherit it; `this` is the declarer.
    _add(alice, "example.com")

    listing = _html(alice, "/assets")
    detail = _html(alice, f"/assets/{_root_id(db_session)}")

    form = listing[
        listing.index('<form class="filters') : listing.index(
            "</form>", listing.index('<form class="filters')
        )
    ]
    assert form.split(">", 1)[0].count('hx-sync="this:replace"') == 1
    assert form.count("hx-sync") == 1  # the search input inherits it rather than overriding
    tabs = detail[detail.index('<nav class="tabs"') :]
    assert 'hx-sync="this:replace"' in tabs.split(">", 1)[0]


def test_bad_filter_values_are_a_bad_request(alice: FlaskClient) -> None:
    assert alice.get("/assets?type=server").status_code == 400


def test_pagination_keeps_the_filters(alice: FlaskClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(asset_views, "PAGE_SIZE", 1)
    _add(alice, "example.com")
    _add(alice, "example.org")

    html = _html(alice, "/assets?type=domain")

    assert 'href="/assets?page=2&amp;type=domain"' in html


def test_detail_tabs_show_relations_findings_and_scans(
    alice: FlaskClient, db_session: Session
) -> None:
    _add(alice, "example.com")
    root_id = _root_id(db_session)
    www_id = _discover(db_session, root_id, AssetType.SUBDOMAIN, "www.example.com")
    ip_id = _discover(db_session, root_id, AssetType.IP, "192.0.2.10")
    org_id = _org_id(db_session, root_id)
    record_relation(db_session, org_id, www_id, ip_id, RelationKind.RESOLVES_TO)
    db_session.add(
        Scan(
            org_id=org_id,
            root_asset_id=root_id,
            profile="dns_passive",
            status=ScanStatus.COMPLETED,
            triggered_by=ScanTrigger.USER,
        )
    )
    db_session.commit()

    overview = _html(alice, f"/assets/{www_id}")
    incoming = _html(alice, f"/assets/{ip_id}")
    findings = _html(alice, f"/assets/{www_id}?tab=findings")
    scans = _html(alice, f"/assets/{www_id}?tab=scans", HTMX)

    assert "Resolves to" in overview
    assert f'href="/assets/{ip_id}">192.0.2.10</a>' in overview
    assert f'href="/assets/{root_id}">example.com</a>' in overview  # breadcrumb to the root
    assert "Resolves to this asset" in incoming
    assert "No findings" in findings
    tab = f"/assets/{www_id}?tab=findings"
    assert f'<a href="{tab}" hx-get="{tab}" aria-current="page">Findings</a>' in findings
    assert "<code>dns_passive</code>" in scans
    assert 'class="pill pill-good">completed' in scans
    assert '<div id="asset-tab">' in scans


def test_unknown_tab_falls_back_to_overview(alice: FlaskClient, db_session: Session) -> None:
    _add(alice, "example.com")

    html = _html(alice, f"/assets/{_root_id(db_session)}?tab=<script>")

    assert "Points to" in html
    assert "<script>" not in html


def test_detail_highlights_the_assets_nav_item(alice: FlaskClient, db_session: Session) -> None:
    _add(alice, "example.com")

    html = _html(alice, f"/assets/{_root_id(db_session)}")

    assert '<a href="/assets" aria-current="true">' in html


def test_owner_archives_a_root_through_the_confirm_dialog(
    alice: FlaskClient, db_session: Session
) -> None:
    _add(alice, "example.com")
    root_id = _root_id(db_session)
    www_id = _discover(db_session, root_id, AssetType.SUBDOMAIN, "www.example.com")
    detail = _html(alice, f"/assets/{root_id}")
    assert '<dialog class="dialog" x-ref="dialog"' in detail
    assert "It and the 1 asset discovered under it become inactive" in detail
    assert f'action="/assets/{root_id}/archive"' in detail

    response = alice.post(
        f"/assets/{root_id}/archive", data={"csrf_token": _csrf(alice, f"/assets/{root_id}")}
    )

    assert (response.status_code, response.headers["Location"]) == (303, "/assets")
    assert not _is_active(db_session, root_id)
    assert not _is_active(db_session, www_id)
    after = _html(alice, f"/assets/{root_id}")
    assert 'class="pill pill-neutral">archived' in after
    assert "<dialog" not in after  # already archived: nothing to confirm


def test_archiving_a_root_shows_its_running_scan_as_cancelled(
    alice: FlaskClient, db_session: Session
) -> None:
    _add(alice, "example.com")
    root_id = _root_id(db_session)
    db_session.add(
        Scan(
            org_id=_org_id(db_session, root_id),
            root_asset_id=root_id,
            profile="dns_passive",
            status=ScanStatus.RUNNING,
            triggered_by=ScanTrigger.USER,
        )
    )
    db_session.commit()

    alice.post(
        f"/assets/{root_id}/archive", data={"csrf_token": _csrf(alice, f"/assets/{root_id}")}
    )

    history = _html(alice, f"/assets/{root_id}?tab=scans", HTMX)
    assert 'class="pill pill-neutral">cancelled' in history


def test_discovered_assets_have_no_archive_action(alice: FlaskClient, db_session: Session) -> None:
    _add(alice, "example.com")
    www_id = _discover(db_session, _root_id(db_session), AssetType.SUBDOMAIN, "www.example.com")

    assert "<dialog" not in _html(alice, f"/assets/{www_id}")
    response = alice.post(f"/assets/{www_id}/archive", data={"csrf_token": _csrf(alice)})
    assert response.status_code == 404


def test_members_see_no_archive_action_and_cannot_archive(
    alice: FlaskClient, db_session: Session
) -> None:
    _add(alice, "example.com")
    root_id = _root_id(db_session)
    user = db_session.scalars(select(User).where(User.email == "alice@example.com")).one()
    membership = db_session.scalars(select(Membership).where(Membership.user_id == user.id)).one()
    membership.role = Role.MEMBER
    db_session.commit()

    assert "<dialog" not in _html(alice, f"/assets/{root_id}")
    response = alice.post(f"/assets/{root_id}/archive", data={"csrf_token": _csrf(alice)})
    assert response.status_code == 403
    assert _is_active(db_session, root_id)


def test_another_org_cannot_see_or_archive_the_asset(
    alice: FlaskClient, db_app: Flask, db_session: Session
) -> None:
    _add(alice, "example.com")
    root_id = _root_id(db_session)
    bob = _signup(db_app, "bob@example.com")

    for path in ("/assets?status=all", f"/assets?root={root_id}"):
        html = _html(bob, path)
        assert "0 assets" in html
        assert str(root_id) not in html
    assert bob.get(f"/assets/{root_id}").status_code == 404
    assert bob.get(f"/assets/{root_id}?tab=findings").status_code == 404
    response = bob.post(f"/assets/{root_id}/archive", data={"csrf_token": _csrf(bob)})
    assert response.status_code == 404
    assert _is_active(db_session, root_id)


def test_asset_pages_have_no_inline_script_or_style(
    alice: FlaskClient, db_session: Session
) -> None:
    # The CSP blocks inline code; this keeps the new templates from silently breaking under it.
    _add(alice, "example.com")
    root_id = _root_id(db_session)

    for path in ("/assets", "/assets?status=all&type=domain", f"/assets/{root_id}"):
        html = _html(alice, path)
        assert not any(pattern.search(html) for pattern in _INLINE_CODE), path


def test_asset_detail_shows_the_dns_chain_and_escapes_records(
    alice: FlaskClient, db_session: Session
) -> None:
    _add(alice, "example.com")
    root_id = _root_id(db_session)
    www_id = _discover(db_session, root_id, AssetType.SUBDOMAIN, "www.example.com")
    www = db_session.get(Asset, www_id)
    assert www is not None
    www.details = {
        "dns": {
            "a": ["203.0.113.10"],
            "cname_chain": ["www.example.com", "cdn.example.net"],
            "txt": ["<script>alert(1)</script>"],
        }
    }
    db_session.commit()

    html = _html(alice, f"/assets/{www_id}")

    assert "www.example.com" in html
    assert "cdn.example.net" in html
    assert "203.0.113.10" in html
    assert "→" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html


def test_ip_asset_detail_shows_reverse_dns_and_asn(alice: FlaskClient, db_session: Session) -> None:
    _add(alice, "example.com")
    root_id = _root_id(db_session)
    ip_id = _discover(db_session, root_id, AssetType.IP, "203.0.113.10")
    ip_asset = db_session.get(Asset, ip_id)
    assert ip_asset is not None
    ip_asset.details = {
        "ip": {
            "ptr": "host.example.net",
            "asn": 13335,
            "org": "CLOUDFLARENET",
            "country": "US",
        }
    }
    db_session.commit()

    html = _html(alice, f"/assets/{ip_id}")

    assert "host.example.net" in html
    assert "AS13335" in html
    assert "CLOUDFLARENET" in html
    assert "US" in html


def test_asset_with_no_dns_records_does_not_render_an_empty_dns_card(
    alice: FlaskClient, db_session: Session
) -> None:
    _add(alice, "example.com")
    root_id = _root_id(db_session)
    www_id = _discover(db_session, root_id, AssetType.SUBDOMAIN, "www.example.com")
    www = db_session.get(Asset, www_id)
    assert www is not None
    www.details = {"dns": {}}
    db_session.commit()

    html = _html(alice, f"/assets/{www_id}")

    assert 'id="dns-title"' not in html


def test_add_url_via_ui_renders_verified_and_unverified_states_and_escapes_web_panels(
    alice: FlaskClient, db_app: Flask, db_session: Session
) -> None:
    _add(alice, "example.com")
    root_id = _root_id(db_session)
    now = datetime.now(UTC)
    db_session.add(
        Verification(
            org_id=_org_id(db_session, root_id),
            asset_id=root_id,
            method=VerificationMethod.DNS_TXT,
            token="verify-tok",
            status=VerificationStatus.VERIFIED,
            verified_at=now,
            last_checked_at=now,
            recheck_at=now,
            expires_at=now.replace(year=now.year + 1),
        )
    )
    db_session.commit()

    # Invalid HTMX submission returns 422 inline form partial with url_error.
    bad = alice.post(
        "/assets/url",
        data={"url": "https://printer.corp/", "csrf_token": _csrf(alice)},
        headers=HTMX,
    )
    assert bad.status_code == 422
    assert 'id="add-url"' in bad.get_data(as_text=True)

    # Verified URL links under example.com.
    ok = alice.post(
        "/assets/url",
        data={"url": "https://app.example.com/portal", "csrf_token": _csrf(alice)},
    )
    assert ok.status_code == 303
    url_row = db_session.scalars(
        select(Asset).where(
            Asset.type == AssetType.URL, Asset.value == "https://app.example.com/portal"
        )
    ).one()
    url_row.details = {
        "web": {
            "status_code": 200,
            "title": "<script>alert('xss')</script>App",
            "final_url": "https://app.example.com/portal",
            "content_type": "text/html",
            "redirect_chain": [{"url": "http://app.example.com/portal", "status": 301}],
        },
        "technologies": [
            {"name": "WordPress", "version": "6.5.2", "categories": ["CMS"], "confidence": 100},
        ],
        "tls": {
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "issuer": "CN=<Issuer>",
            "not_after": "2027-01-01T00:00:00+00:00",
            "trusted_chain": True,
            "hostname_matches": True,
        },
        "security_headers": {
            "hsts": True,
            "csp": False,
            "clickjacking_protected": True,
            "nosniff": True,
            "redirects_to_https": True,
        },
    }
    url_id = url_row.id
    db_session.commit()

    detail_html = _html(alice, f"/assets/{url_id}")
    assert "Verified" in detail_html
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;App" in detail_html
    assert "<script>alert('xss')</script>" not in detail_html
    assert "WordPress" in detail_html
    assert "6.5.2" in detail_html
    assert "TLSv1.3" in detail_html
    assert "CN=&lt;Issuer&gt;" in detail_html
    assert "Content-Security-Policy" in detail_html
    assert not any(pattern.search(detail_html) for pattern in _INLINE_CODE)

    # Filter list by technology.
    filtered_html = _html(alice, "/assets?tech=WordPress")
    assert "https://app.example.com/portal" in filtered_html
    assert "1 asset matches" in filtered_html

    # Unverified URL is saved and shows explanation banner + tenant isolation blocks Bob.
    unverified_resp = alice.post(
        "/assets/url",
        data={"url": "https://other.example.net/", "csrf_token": _csrf(alice)},
    )
    assert unverified_resp.status_code == 303
    unverified_row = db_session.scalars(
        select(Asset).where(
            Asset.type == AssetType.URL, Asset.value == "https://other.example.net/"
        )
    ).one()
    unverified_html = _html(alice, f"/assets/{unverified_row.id}")
    assert "Active web checks paused" in unverified_html
    assert "skipped until a covering root domain is verified" in unverified_html

    bob = _signup(db_app, "bob@example.com")
    assert bob.get(f"/assets/{url_id}").status_code == 404
    bob_list = _html(bob, "/assets?tech=WordPress")
    assert "0 assets" in bob_list
    assert "https://app.example.com/portal" not in bob_list
    # Bob adding a URL for a domain verified only by Alice still stores it as unverified for Bob.
    bob_add = bob.post(
        "/assets/url",
        data={"url": "https://app.example.com/portal", "csrf_token": _csrf(bob)},
    )
    assert bob_add.status_code == 303
    assert "Active web checks paused" in _html(bob, bob_add.headers["Location"])


def test_add_url_run_web_active_and_view_panels_on_url_detail(
    alice: FlaskClient, db_session: Session
) -> None:
    class _Queue(TaskQueue, PipelineQueue):
        def __init__(self) -> None:
            self.tasks: list[tuple[str, UUID, UUID]] = []
            self.header: tuple[JobTask, ...] = ()
            self.tail: tuple[JobTask, ...] = ()

        def enqueue(self, task_name: str, *, org_id: UUID, job_id: UUID) -> str:
            self.tasks.append((task_name, org_id, job_id))
            return "task-1"

        def enqueue_workflow(
            self, header: tuple[JobTask, ...], tail: tuple[JobTask, ...], error: JobTask
        ) -> None:
            del error
            self.header = header
            self.tail = tail

    class _Events:
        def publish(self, event: object) -> None:
            del event

    class _FakeTls:
        def __init__(self, der_cert: bytes) -> None:
            self._cert = der_cert

        def handshake(
            self,
            *,
            address: str,
            port: int,
            server_hostname: str,
            verify: bool,
            check_hostname: bool = True,
            timeout: float,
            min_version: ssl.TLSVersion | None = None,
            max_version: ssl.TLSVersion | None = None,
        ) -> RawTlsHandshake:
            del address, port, server_hostname, check_hostname, timeout, max_version
            if min_version in {ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1}:
                raise TlsError("legacy disabled")
            return RawTlsHandshake("TLSv1.3", "TLS_AES_256_GCM_SHA384", 256, (self._cert,), verify)

    _add(alice, "example.com")
    root_id = _root_id(db_session)
    org_id = _org_id(db_session, root_id)
    now = datetime.now(UTC)
    db_session.add(
        Verification(
            org_id=org_id,
            asset_id=root_id,
            method=VerificationMethod.DNS_TXT,
            token="verify-tok",
            status=VerificationStatus.VERIFIED,
            verified_at=now,
            last_checked_at=now,
            recheck_at=now,
            expires_at=now + timedelta(days=2),
        )
    )
    db_session.commit()

    resp = alice.post(
        "/assets/url",
        data={"url": "https://app.example.com/portal", "csrf_token": _csrf(alice)},
    )
    assert resp.status_code == 303
    url_row = db_session.scalars(
        select(Asset).where(
            Asset.org_id == org_id,
            Asset.type == AssetType.URL,
            Asset.value == "https://app.example.com/portal",
        )
    ).one()
    url_id = url_row.id

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "app.example.com")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Acme Test CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=5))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("app.example.com")]), critical=False
        )
        .sign(key, hashes.SHA256())
    ).public_bytes(serialization.Encoding.DER)

    dns = MutableDnsZone()
    dns.set_records("example.com", "A", ("93.184.216.34",))
    dns.set_records("app.example.com", "A", ("93.184.216.34",))
    http = FakeScopeHttp(
        {
            "https://example.com/": HttpBody(status_code=200, content=b"<html>Root</html>"),
            "http://example.com/": HttpBody(
                status_code=301, content=b"", final_url="https://example.com/"
            ),
            "https://app.example.com/portal": HttpBody(
                status_code=200,
                content=b"<html><head><title>App Portal</title></head><body>Hi</body></html>",
                headers={
                    "Content-Type": "text/html",
                    "Server": "nginx/1.26.2",
                    "Strict-Transport-Security": "max-age=31536000",
                    "X-Content-Type-Options": "nosniff",
                },
            ),
        }
    )
    factory = sessionmaker(bind=db_session.get_bind())
    guard = ScopeGuard(
        dns=dns,
        http=http,
        ownership=DbOwnershipChecker(factory),
        classify=public_suffix.classify,
        active_scans_enabled=True,
        tls=_FakeTls(cert),
    )
    events = _Events()
    q_disc = _Queue()
    scans_service.start_scan(
        db_session,
        q_disc,
        org_id=org_id,
        root_asset_id=root_id,
        profile="web_active",
        registry=registry,
        profiles=PROFILES,
    )
    scans_service.dispatch_stage(
        db_session,
        q_disc,
        org_id,
        q_disc.tasks[0][2],
        registry=registry,
        profiles=PROFILES,
    )
    db_session.commit()
    for task in q_disc.header:
        run_check(
            db_session,
            org_id,
            task.job_id,
            registry=registry,
            gate=guard,
            events=events,
            retry_allowed=False,
            profiles=PROFILES,
        )
    q_chk = _Queue()
    scans_service.dispatch_stage(
        db_session,
        q_chk,
        org_id,
        q_disc.tail[0].job_id,
        registry=registry,
        profiles=PROFILES,
    )
    db_session.commit()
    for task in q_chk.header:
        run_check(
            db_session,
            org_id,
            task.job_id,
            registry=registry,
            gate=guard,
            events=events,
            retry_allowed=False,
            profiles=PROFILES,
        )

    html = _html(alice, f"/assets/{url_id}")
    assert "App Portal" in html
    assert "Nginx" in html
    assert "1.26.2" in html
    assert "TLSv1.3" in html
    assert "Acme Test CA" in html
    assert "HSTS" in html
    assert "Content-Security-Policy" in html

    api_detail = alice.get(f"/api/v1/assets/{url_id}").get_json()
    assert api_detail["web"]["title"] == "App Portal"
    assert any(
        t["name"] == "Nginx" and t["version"] == "1.26.2" for t in api_detail["technologies"]
    )
    assert api_detail["tls"]["protocol"] == "TLSv1.3"
    assert any(h["key"] == "hsts" and h["passed"] is True for h in api_detail["security_headers"])
