"""Asset pages against real Postgres, signed in through the real signup flow.

Each request closes the shared `db_session` at teardown, which detaches ORM rows: helpers
pass ids around and tests re-read rows after requests.
"""

import re
from datetime import UTC, datetime
from uuid import UUID

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from werkzeug.test import TestResponse

from attacksurf.domain.accounts import Role
from attacksurf.domain.assets import AssetSource, AssetType, RelationKind
from attacksurf.domain.findings import Confidence, Severity, finding_fingerprint
from attacksurf.domain.scans import ScanStatus, ScanTrigger
from attacksurf.infra.db.models import Asset, Finding, Membership, Scan, User
from attacksurf.services import asset_views
from attacksurf.services.assets import record_asset, record_relation

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
