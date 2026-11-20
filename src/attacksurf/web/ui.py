"""HTML UI blueprint (Jinja + HTMX pages)."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

import structlog
from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    make_response,
    redirect,
    request,
    url_for,
)
from flask_login import current_user
from werkzeug.exceptions import HTTPException
from werkzeug.wrappers.response import Response as BaseResponse

from attacksurf.domain.accounts import Role, has_role
from attacksurf.domain.artifacts import ArtifactError, ArtifactStorageUnavailable
from attacksurf.domain.assets import (
    AssetError,
    AssetNotFound,
    AssetType,
    InvalidAssetValue,
)
from attacksurf.domain.findings import (
    FindingError,
    FindingNotFound,
    FindingStatus,
    Severity,
)
from attacksurf.domain.llm import ProviderKind
from attacksurf.domain.net import DnsResolver
from attacksurf.domain.scans import (
    ScanAlreadyActive,
    ScanError,
    ScanNotFound,
    ScanNotQueued,
    ScanRateLimited,
    ScanStatus,
    ScheduleFrequency,
)
from attacksurf.domain.scope import ScopeError
from attacksurf.infra.dns import DnsPythonResolver
from attacksurf.scanners.profiles import PROFILES
from attacksurf.scanners.registry import registry
from attacksurf.services import (
    asset_views,
    binaries,
    finding_views,
    llm_usage,
    org_settings,
    repos,
    scan_schedules,
    scan_views,
    triage_views,
    verifications,
)
from attacksurf.services import assets as assets_service
from attacksurf.services import findings as findings_service
from attacksurf.services import scans as scans_service
from attacksurf.services.asset_views import AssetFilter, AssetStatus
from attacksurf.services.finding_views import (
    FindingFilter,
    FindingSort,
    FindingStatusFilter,
)
from attacksurf.services.org_settings import InvalidOrgSettings, OrgSettingsError
from attacksurf.services.scan_views import ScanFilter
from attacksurf.services.uploads import AssetUpload
from attacksurf.web import export as export_module
from attacksurf.web import uploads
from attacksurf.web.asset_params import parse_asset_filter
from attacksurf.web.auth import get_settings, require_role
from attacksurf.web.db import get_session
from attacksurf.web.finding_params import filter_args as finding_filter_args
from attacksurf.web.finding_params import parse_finding_filter
from attacksurf.web.formatting import exact_time, humanize_delta
from attacksurf.web.queue import get_task_queue
from attacksurf.web.rendering import is_htmx_request, render_page
from attacksurf.web.scan_params import parse_scan_filter

bp = Blueprint("ui", __name__)

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class NavItem:
    endpoint: str
    label: str
    icon: str
    subpages: tuple[str, ...] = ()  # endpoints that keep this item highlighted


NAV_ITEMS = (
    NavItem("ui.dashboard", "Dashboard", "layout-dashboard"),
    NavItem("ui.assets", "Assets", "globe", subpages=("ui.asset_detail",)),
    NavItem("ui.scans", "Scans", "radar"),
    NavItem("ui.findings", "Findings", "bug"),
    NavItem("ui.settings", "Settings", "settings"),
)
# Binary assets don't exist yet (#101), so they aren't offered as a filter.
_TYPE_LABELS = {
    AssetType.DOMAIN: "Domain",
    AssetType.SUBDOMAIN: "Subdomain",
    AssetType.IP: "IP address",
    AssetType.URL: "URL",
    AssetType.REPO: "Code repository",
    AssetType.BINARY: "Binary",
}
ASSET_TABS = (("overview", "Overview"), ("findings", "Findings"), ("scans", "Scan history"))
_FINDING_STATUS_FILTER_LABELS = {
    FindingStatusFilter.ACTIVE: "Open/regressed",
    FindingStatusFilter.OPEN: "Open",
    FindingStatusFilter.FIXED: "Fixed",
    FindingStatusFilter.REGRESSED: "Regressed",
    FindingStatusFilter.ACCEPTED_RISK: "Accepted risk",
    FindingStatusFilter.FALSE_POSITIVE: "False positive",
    FindingStatusFilter.ALL: "All statuses",
}
_FINDING_SORT_LABELS = {
    FindingSort.SEVERITY: "Severity (worst)",
    FindingSort.LAST_SEEN: "Last seen (newest)",
}


@bp.app_context_processor
def _layout_context() -> dict[str, Any]:
    return {"nav_items": NAV_ITEMS, "is_htmx": is_htmx_request()}


@bp.app_template_filter("timeago")
def _timeago(value: datetime) -> str:
    return humanize_delta(value, datetime.now(UTC))


@bp.app_template_filter("exact_time")
def _exact_time(value: datetime) -> str:
    return exact_time(value)


@bp.get("/")
def dashboard() -> Response:
    return render_page(
        "pages/dashboard.html", data=finding_views.get_dashboard(get_session(), _org_id())
    )


@bp.get("/assets")
def assets() -> Response:
    flt, page = parse_asset_filter(request.args)
    return _assets_page(flt, page)


@bp.post("/assets")
def add_domain() -> BaseResponse:
    value = request.form.get("value", "")
    try:
        asset = assets_service.add_root_domain(
            get_session(),
            _org_id(),
            value,
            actor_id=current_user.session_user.user_id,
            scan_default_frequency=get_settings().scan_default_frequency,
        )
    except AssetError as exc:
        if is_htmx_request():
            return render_page(
                "pages/_add_domain_form.html", status=422, add_value=value, add_error=str(exc)
            )
        return _assets_page(AssetFilter(), 1, status=422, add_value=value, add_error=str(exc))
    flash(f"Added {asset.value}. Run a scan to discover what's under it.", "success")
    return _navigate(url_for("ui.asset_detail", asset_id=asset.id))


@bp.post("/assets/upload")
def upload_repo() -> BaseResponse:
    """Store an uploaded archive as a repo asset and queue its scan (#87)."""
    return _upload("archive", "Choose an archive to upload.", repos.upload_repo_archive)


@bp.post("/assets/upload-binary")
def upload_binary() -> BaseResponse:
    """Store an uploaded executable or mobile app as a binary asset and queue its scan (#101)."""
    return _upload("binary", "Choose a file to upload.", binaries.upload_binary)


@bp.get("/assets/<uuid:asset_id>")
def asset_detail(asset_id: UUID) -> Response:
    tab = request.args.get("tab", "overview")
    if tab not in dict(ASSET_TABS):
        tab = "overview"
    session = get_session()
    try:
        detail = asset_views.get_asset_detail(session, _org_id(), asset_id)
        findings = (
            asset_views.list_asset_findings(session, _org_id(), asset_id)
            if tab == "findings"
            else ()
        )
        scans = asset_views.list_asset_scans(session, _org_id(), asset_id) if tab == "scans" else ()
        ownership_context = (
            _ownership_context(asset_id)
            if tab == "overview" and detail.asset.type in {AssetType.DOMAIN, AssetType.SUBDOMAIN}
            else None
        )
    except AssetNotFound:
        abort(404)
    asset = detail.asset
    can_scan = asset.is_active and asset.type == AssetType.DOMAIN and asset.root_id is None
    show_schedule = can_scan and tab == "overview"
    return render_page(
        "pages/asset_detail.html",
        detail=detail,
        asset=asset,
        tab=tab,
        tabs=ASSET_TABS,
        findings=findings,
        scans=scans,
        can_scan=can_scan,
        show_schedule=show_schedule,
        schedule=(
            scan_schedules.get_schedule(session, _org_id(), asset.id) if show_schedule else None
        ),
        can_manage_schedule=show_schedule and has_role(current_user.role, Role.ADMIN),
        active_scan=(
            scan_views.active_scan_for_root(get_session(), _org_id(), asset.id)
            if can_scan
            else None
        ),
        can_archive=asset.is_active
        and asset.type == AssetType.DOMAIN
        and asset.root_id is None
        and has_role(current_user.role, Role.ADMIN),
        # Only roots carry a proof; a subdomain shows its root's, read-only.
        **(dict(ownership_context) if ownership_context else {}),
    )


@bp.post("/assets/<uuid:asset_id>/schedule")
@require_role(Role.ADMIN)
def update_schedule(asset_id: UUID) -> BaseResponse:
    """Save a root's recurring-scan preference, then return to its overview."""
    try:
        frequency = ScheduleFrequency(request.form.get("frequency", ""))
    except ValueError:
        abort(422)
    enabled_values = request.form.getlist("enabled")
    if enabled_values not in ([], ["1"]):
        abort(422)
    try:
        scan_schedules.save_schedule(
            get_session(),
            org_id=_org_id(),
            root_asset_id=asset_id,
            actor_id=current_user.session_user.user_id,
            frequency=frequency,
            enabled=bool(enabled_values),
            now=datetime.now(UTC),
        )
    except AssetNotFound:
        abort(404)
    flash("Scan schedule saved.", "success")
    return redirect(url_for("ui.asset_detail", asset_id=asset_id), 303)


@bp.post("/assets/<uuid:asset_id>/archive")
@require_role(Role.ADMIN)
def archive_asset(asset_id: UUID) -> BaseResponse:
    try:
        asset = assets_service.archive_root_domain(
            get_session(), _org_id(), asset_id, actor_id=current_user.session_user.user_id
        )
    except AssetNotFound:
        abort(404)
    flash(f"Archived {asset.value} and the assets discovered under it.", "success")
    return redirect(url_for("ui.assets"), 303)


@bp.post("/assets/<uuid:asset_id>/verify")
@require_role(Role.ADMIN)
def verify_asset(asset_id: UUID) -> BaseResponse:
    """Start or rotate a root's TXT proof, or run one check now (ADR 0014).

    `action=check` queues a check of the current token ("Verify now"), `action=start` issues a
    token, and anything else (the rotate dialog) issues a new one.
    """
    session = get_session()
    try:
        if request.form.get("action") == "check":
            verifications.queue_check(
                session, get_task_queue(), org_id=_org_id(), asset_id=asset_id
            )
        else:
            verifications.start_verification(
                session,
                get_task_queue(),
                org_id=_org_id(),
                asset_id=asset_id,
                actor_id=current_user.session_user.user_id,
            )
    except AssetNotFound:
        abort(404)
    if is_htmx_request():
        # Only the card changes: re-render it in place instead of reloading the page.
        return _ownership_card(asset_id)
    return redirect(url_for("ui.asset_detail", asset_id=asset_id), 303)


@bp.get("/assets/<uuid:asset_id>/ownership")
def ownership_card(asset_id: UUID) -> Response:
    """The ownership card alone, so a re-render never depends on the surrounding page."""
    try:
        return _ownership_card(asset_id)
    except AssetNotFound:
        abort(404)


@bp.get("/scans")
def scans() -> Response:
    flt, page = parse_scan_filter(request.args)
    return _scans_page(flt, page)


@bp.post("/scans")
def create_scan() -> BaseResponse:
    """Queue a `dns_passive` scan of a root domain, then show its progress.

    Any org member may start a scan; the service refuses unknown profiles, inactive or
    foreign roots, a second concurrent scan of the same root, and starts over the
    hourly quota. A broker failure is already recorded as a failed scan; the user gets
    a flash and a redirect, never a traceback.
    """
    raw_root = request.form.get("root_asset_id", "")
    profile = request.form.get("profile", "") or "dns_passive"
    try:
        root_id = UUID(raw_root)
    except (ValueError, AttributeError, TypeError):
        flash("Choose a domain to scan.", "error")
        return _navigate(url_for("ui.scans"))
    session = get_session()
    try:
        scan = scans_service.start_scan(
            session,
            get_task_queue(),
            org_id=_org_id(),
            root_asset_id=root_id,
            profile=profile,
            registry=registry,
            profiles=PROFILES,
            max_starts_per_hour=get_settings().scan_max_starts_per_hour,
            actor_id=current_user.session_user.user_id,
        )
    except ScanAlreadyActive as exc:
        flash("A scan of this domain is already running.", "info")
        return _navigate(url_for("ui.scan_detail", scan_id=exc.scan_id))
    except (ScanRateLimited, ScanError) as exc:
        flash(str(exc), "error")
        return _navigate(_scan_start_fallback(root_id))
    except AssetNotFound:
        abort(404)
    except HTTPException:
        raise
    except Exception as exc:  # broker down: the scan row is already marked failed
        log.warning("scan not queued", error=type(exc).__name__)
        flash("The scan could not be queued. Try again in a moment.", "error")
        return _navigate(_scan_start_fallback(root_id))
    flash(
        f"Scan started for {asset_views.get_asset(session, _org_id(), root_id).value}.", "success"
    )
    return _navigate(url_for("ui.scan_detail", scan_id=scan.id))


@bp.get("/scans/<uuid:scan_id>")
def scan_detail(scan_id: UUID) -> Response:
    try:
        detail = scan_views.get_scan_detail(get_session(), _org_id(), scan_id)
        triage = triage_views.get_scan_triage(get_session(), _org_id(), scan_id)
    except ScanNotFound:
        abort(404)
    return render_page(
        "pages/scan_detail.html", detail=detail, scan=detail.scan, triage=triage, scan_id=scan_id
    )


@bp.get("/scans/<uuid:scan_id>/triage")
def scan_triage(scan_id: UUID) -> Response:
    """The AI triage fragment alone, polled while its run is active (ADR 0029)."""
    try:
        triage = triage_views.get_scan_triage(get_session(), _org_id(), scan_id)
    except ScanNotFound:
        abort(404)
    return render_page("pages/_scan_triage.html", triage=triage, scan_id=scan_id)


@bp.get("/scans/<uuid:scan_id>/progress")
def scan_progress(scan_id: UUID) -> Response:
    """The progress fragment alone, so polling re-renders it without the whole page."""
    try:
        detail = scan_views.get_scan_detail(get_session(), _org_id(), scan_id)
    except ScanNotFound:
        abort(404)
    return render_page("pages/_scan_progress.html", detail=detail, scan=detail.scan, oob=True)


@bp.post("/scans/<uuid:scan_id>/cancel")
def cancel_scan(scan_id: UUID) -> BaseResponse:
    """Cancel a running scan (ADR 0021: database-only, no Celery revoke). Idempotent."""
    try:
        scan = scans_service.cancel_scan(
            get_session(), _org_id(), scan_id, actor_id=current_user.session_user.user_id
        )
    except ScanNotFound:
        abort(404)
    flash("Scan cancelled.", "success")
    return _navigate(url_for("ui.scan_detail", scan_id=scan.id))


@bp.get("/findings")
def findings() -> Response:
    flt, page = parse_finding_filter(request.args)
    return _findings_page(flt, page)


@bp.get("/findings/<uuid:finding_id>")
def finding_detail(finding_id: UUID) -> Response:
    try:
        detail = finding_views.get_finding_detail(get_session(), _org_id(), finding_id)
    except FindingNotFound:
        abort(404)
    return render_page(
        "pages/finding_detail.html",
        detail=detail,
        finding=detail.finding,
        status_options=[
            ("", "Choose a status change"),
            *_finding_action_options(detail.finding.status),
        ],
    )


@bp.post("/findings/<uuid:finding_id>/status")
def change_finding_status(finding_id: UUID) -> BaseResponse:
    """Apply one user decision (accept risk / false positive / reopen). Scans own the rest."""
    status = _finding_status(request.form.get("status", ""))
    if status is None:
        flash("Choose a status change.", "error")
        return _navigate(url_for("ui.finding_detail", finding_id=finding_id))
    try:
        findings_service.change_finding_status(
            get_session(),
            _org_id(),
            finding_id,
            status,
            actor_id=current_user.session_user.user_id,
            comment=request.form.get("comment", ""),
        )
    except FindingNotFound:
        abort(404)
    except FindingError as exc:
        flash(str(exc), "error")
        return _navigate(url_for("ui.finding_detail", finding_id=finding_id))
    flash("Finding updated.", "success")
    return _navigate(url_for("ui.finding_detail", finding_id=finding_id))


@bp.post("/findings/bulk-status")
def bulk_change_finding_status() -> BaseResponse:
    """Apply one decision to a selection; all-or-nothing, at most 50 findings."""
    flt, _ = parse_finding_filter(request.args)  # the filter rides on the form action
    back = url_for("ui.findings", **cast("dict[str, Any]", finding_filter_args(flt)))
    status = _finding_status(request.form.get("status", ""))
    if status is None:
        flash("Choose a status change.", "error")
        return _navigate(back)
    raw_ids = request.form.getlist("finding_ids")
    try:
        finding_ids = tuple(UUID(raw) for raw in raw_ids)
    except ValueError:
        flash("Select findings from the list.", "error")
        return _navigate(back)
    try:
        changed = findings_service.change_findings_status(
            get_session(),
            _org_id(),
            finding_ids,
            status,
            actor_id=current_user.session_user.user_id,
            comment=request.form.get("comment", ""),
        )
    except FindingNotFound:
        flash("Finding not found.", "error")
        return _navigate(back)
    except FindingError as exc:
        flash(str(exc), "error")
        return _navigate(back)
    flash(
        "No findings changed."
        if not changed
        else f"Updated {changed} finding{'s' if changed != 1 else ''}.",
        "success" if changed else "info",
    )
    return _navigate(back)


@bp.get("/findings/export.csv")
def export_findings_csv() -> Response:
    flt, _ = parse_finding_filter(request.args)
    export = finding_views.export_findings(get_session(), _org_id(), flt)
    return _export_response(export_module.findings_csv(export), "findings.csv", "text/csv", export)


@bp.get("/findings/export.json")
def export_findings_json() -> Response:
    flt, _ = parse_finding_filter(request.args)
    export = finding_views.export_findings(get_session(), _org_id(), flt)
    return _export_response(
        export_module.findings_json(export), "findings.json", "application/json", export
    )


@bp.get("/settings")
def settings() -> Response:
    return _settings_page()


@bp.post("/settings/ai")
@require_role(Role.ADMIN)
def save_ai_settings() -> BaseResponse:
    """Validate and save per-org AI provider settings and encrypted BYO API key (#24)."""
    ai_enabled = "ai_enabled" in request.form
    provider = request.form.get("provider", ProviderKind.ANTHROPIC.value)
    model = request.form.get("model", "")
    base_url = request.form.get("base_url", "")
    api_key = request.form.get("api_key", "")
    clear_api_key = request.form.get("clear_api_key") in {"1", "true", "on"}
    monthly_token_budget = request.form.get("monthly_token_budget", "")

    submitted = {
        "ai_enabled": ai_enabled,
        "provider": provider,
        "model": model,
        "base_url": base_url,
        "monthly_token_budget": monthly_token_budget,
    }
    session = get_session()
    try:
        org_settings.update_org_settings(
            session,
            _org_id(),
            ai_enabled=ai_enabled,
            provider=provider,
            model=model,
            base_url=base_url,
            api_key=api_key,
            clear_api_key=clear_api_key,
            monthly_token_budget=monthly_token_budget,
            actor_id=current_user.session_user.user_id,
            settings=get_settings(),
            resolver=get_dns_resolver(),
        )
    except InvalidOrgSettings as exc:
        field = exc.field or "_form"
        errors = {field: str(exc)}
        focus_field = exc.field
        if is_htmx_request():
            return render_page(
                "pages/_ai_settings_form.html",
                status=422,
                **_ai_settings_context(
                    form=submitted,
                    errors=errors,
                    focus_field=focus_field,
                ),
            )
        return _settings_page(status=422, form=submitted, errors=errors, focus_field=focus_field)
    flash("AI provider settings saved.", "success")
    return _navigate(url_for("ui.settings"))


@bp.post("/settings/ai/clear-key")
@require_role(Role.ADMIN)
def clear_org_ai_key() -> BaseResponse:
    """Erase the org's saved BYO API key."""
    org_settings.clear_org_api_key(
        get_session(), _org_id(), actor_id=current_user.session_user.user_id
    )
    flash("Organization API key removed.", "success")
    return _navigate(url_for("ui.settings"))


@bp.get("/settings/ai/test")
def ai_test_status() -> Response:
    """Poll-only connection test status fragment (`#ai-test-status`)."""
    return _ai_test_card()


@bp.post("/settings/ai/test")
@require_role(Role.ADMIN)
def test_ai_connection() -> BaseResponse:
    """Validate active LLM config/budget and enqueue `ai.test_connection` on the `ai` worker."""
    session = get_session()
    try:
        org_settings.queue_ai_connection_test(
            session,
            get_task_queue(),
            _org_id(),
            get_settings(),
            resolver=get_dns_resolver(),
        )
    except (OrgSettingsError, ScopeError) as exc:
        if is_htmx_request():
            return _ai_test_card(
                org_settings.AITestStatus(org_settings.AITestState.FAILED, message=str(exc)),
                status=422,
            )
        flash(str(exc), "error")
        return redirect(url_for("ui.settings"), 303)
    except Exception as exc:
        log.warning("ai connection test not queued", error=type(exc).__name__)
        msg = "The connection test could not be queued. Try again in a moment."
        if is_htmx_request():
            return _ai_test_card(
                org_settings.AITestStatus(org_settings.AITestState.FAILED, message=msg),
                status=503,
            )
        flash(msg, "error")
        return redirect(url_for("ui.settings"), 303)
    if is_htmx_request():
        return _ai_test_card()
    flash("AI connection test queued.", "info")
    return redirect(url_for("ui.settings"), 303)


def get_dns_resolver() -> DnsResolver:
    current = get_settings()
    return DnsPythonResolver(
        nameservers=current.dns_resolver_addresses,
        timeout=current.dns_timeout_seconds,
        lifetime=current.dns_lifetime_seconds,
        max_concurrency=current.dns_max_concurrency,
    )


def _org_id() -> UUID:
    return current_user.session_user.org_id


def _navigate(target: str) -> BaseResponse:
    """Go to `target` after a form succeeded, for HTMX and plain posts alike."""
    if is_htmx_request():
        # A redirect would be followed and swapped into the form; this makes HTMX navigate.
        return Response(status=200, headers={"HX-Redirect": target})
    return redirect(target, 303)


def _upload(field: str, missing: str, use_case: Callable[..., AssetUpload]) -> BaseResponse:
    """Run one upload use case on the file in `field`; errors land on that form's field."""
    upload = request.files.get(field)
    store = uploads.get_artifact_store()
    try:
        if store is None:
            raise ArtifactStorageUnavailable(uploads.NOT_CONFIGURED)
        if upload is None or not upload.filename:
            raise InvalidAssetValue(missing)
        done = use_case(
            get_session(),
            store,
            uploads.get_artifact_policy(),
            get_task_queue(),
            org_id=_org_id(),
            filename=upload.filename,
            source=upload.stream,
            actor_id=current_user.session_user.user_id,
        )
    except (AssetError, ArtifactError, ScanNotQueued) as exc:
        status = uploads.upload_error_status(exc)
        if is_htmx_request():
            return uploads.upload_form(str(exc), status)
        return _assets_page(AssetFilter(), 1, status=status, **{f"{field}_error": str(exc)})
    flash(
        f"Uploaded {done.asset_value}. Its scan is queued until the analysis worker is available.",
        "success",
    )
    return _navigate(url_for("ui.asset_detail", asset_id=done.asset_id))


def _ownership_card(asset_id: UUID) -> Response:
    """The ownership card of one asset; on a subdomain, its root's proof, read-only."""
    return render_page("pages/_ownership.html", **_ownership_context(asset_id))


def _ownership_context(asset_id: UUID) -> dict[str, Any]:
    """The proof a domain's card shows, plus where its actions post (the root, never a child)."""
    session = get_session()
    asset = asset_views.get_asset(session, _org_id(), asset_id)
    root_id = asset.root_id or asset.id
    root = asset if root_id == asset.id else asset_views.get_asset(session, _org_id(), root_id)
    check = verifications.check_in_flight(session, _org_id(), root.id)
    return {
        "view_id": asset.id,  # the asset being viewed: polls re-render this, not the root
        "proof_root_value": root.value,
        "ownership": verifications.read_verification(session, _org_id(), root.id),
        "checking": check.state
        in (verifications.CheckState.QUEUED, verifications.CheckState.RUNNING),
        "stalled_since": check.queued_since
        if check.state is verifications.CheckState.STALLED
        else None,
        "can_manage_ownership": root.id == asset.id
        and asset.is_active
        and has_role(current_user.role, Role.ADMIN),
    }


def _scan_start_fallback(root_id: UUID) -> str:
    """Back to the domain the scan was started from, or the scan list without it."""
    try:
        asset_views.get_asset(get_session(), _org_id(), root_id)
    except AssetNotFound:
        return url_for("ui.scans")
    return url_for("ui.asset_detail", asset_id=root_id)


def _findings_page(flt: FindingFilter, page: int, status: int = 200) -> Response:
    session = get_session()
    options = finding_views.list_filter_options(session, _org_id())
    return render_page(
        "pages/findings.html",
        status=status,
        result=finding_views.list_findings(session, _org_id(), flt, page),
        export_limit=finding_views.EXPORT_LIMIT,
        flt=flt,
        filtered=flt != FindingFilter(),
        # Non-default filters only, so pagination links and the bulk form stay short.
        filter_args=finding_filter_args(flt),
        severity_options=[("", "All severities")]
        + [(severity.value, severity.value.capitalize()) for severity in Severity],
        status_options=[
            (item.value, _FINDING_STATUS_FILTER_LABELS[item]) for item in FindingStatusFilter
        ],
        sort_options=[(item.value, _FINDING_SORT_LABELS[item]) for item in FindingSort],
        root_options=[("", "All roots")]
        + [(r.id, r.value if r.is_active else f"{r.value} (archived)") for r in options.roots],
        rule_options=[("", "All rules")]
        + [(rule.id, f"{rule.title} ({rule.id})") for rule in options.rules],
    )


def _finding_status(raw: str) -> FindingStatus | None:
    try:
        return FindingStatus(raw)
    except ValueError:
        return None


def _finding_action_options(current: FindingStatus) -> list[tuple[str, str]]:
    """The status changes a user may make on this finding; scans own fixed/regressed."""
    if current is FindingStatus.FIXED or current in (
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.FALSE_POSITIVE,
    ):
        return [(FindingStatus.OPEN.value, "Reopen")]
    return [
        (FindingStatus.ACCEPTED_RISK.value, "Accept risk"),
        (FindingStatus.FALSE_POSITIVE.value, "Mark false positive"),
    ]


def _export_response(
    body: str, filename: str, mimetype: str, export: finding_views.FindingExport
) -> Response:
    response = make_response(body)
    response.mimetype = mimetype
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = "no-store"
    if export.truncated:
        # Machine-readable flag for this download; the toolbar warns based on its list count.
        response.headers["X-Export-Truncated"] = "true"
    return response


def _scans_page(flt: ScanFilter, page: int, status: int = 200) -> Response:
    session = get_session()
    roots = asset_views.list_root_domains(session, _org_id())
    filter_args = {"root": flt.root_id, "status": flt.status}
    return render_page(
        "pages/scans.html",
        status=status,
        result=scan_views.list_scans(session, _org_id(), flt, page),
        flt=flt,
        filtered=flt != ScanFilter(),
        # Non-default filters only, so pagination links stay short and shareable.
        filter_args={key: value for key, value in filter_args.items() if value},
        root_options=[("", "All roots")]
        + [(r.id, r.value if r.is_active else f"{r.value} (archived)") for r in roots],
        status_options=[("", "All statuses")]
        + [(s.value, s.value.replace("_", " ").capitalize()) for s in ScanStatus],
        scan_root_options=[(r.id, r.value) for r in roots if r.is_active],
    )


def _assets_page(flt: AssetFilter, page: int, status: int = 200, **form: str) -> Response:
    session = get_session()
    roots = asset_views.list_root_domains(session, _org_id())
    filter_args = {
        "type": flt.type,
        "root": flt.root_id,
        "tag": flt.tag,
        "q": flt.q,
        "status": None if flt.status is AssetStatus.ACTIVE else flt.status,
    }
    return render_page(
        "pages/assets.html",
        status=status,
        result=asset_views.list_assets(session, _org_id(), flt, page),
        flt=flt,
        filtered=flt != AssetFilter(),
        # Non-default filters only, so pagination links stay short and shareable.
        filter_args={key: value for key, value in filter_args.items() if value},
        type_options=[("", "All types")] + [(t.value, _TYPE_LABELS[t]) for t in _TYPE_LABELS],
        root_options=[("", "All roots")]
        + [(r.id, r.value if r.is_active else f"{r.value} (archived)") for r in roots],
        status_options=[(s.value, s.value.capitalize()) for s in AssetStatus],
        add_value=form.get("add_value", ""),
        add_error=form.get("add_error"),
        archive_error=form.get("archive_error"),
        binary_error=form.get("binary_error"),
        **uploads.upload_context(),
    )


_PROVIDER_OPTIONS = (
    (ProviderKind.ANTHROPIC.value, "Anthropic"),
    (ProviderKind.OPENAI_COMPAT.value, "OpenAI-compatible"),
)


def _ai_settings_context(
    *,
    form: dict[str, Any] | None = None,
    errors: dict[str, str] | None = None,
    focus_field: str | None = None,
    current: org_settings.OrgSettingsView | None = None,
) -> dict[str, Any]:
    app_settings = get_settings()
    if current is None:
        current = org_settings.get_org_settings(get_session(), _org_id())
    resolved_form = form or {
        "ai_enabled": current.ai_enabled,
        "provider": current.provider.value,
        "model": current.model or "",
        "base_url": current.base_url or "",
        "monthly_token_budget": ""
        if current.monthly_token_budget is None
        else str(current.monthly_token_budget),
    }
    return {
        "current": current,
        "form": resolved_form,
        "errors": errors or {},
        "focus_field": focus_field,
        "provider_options": _PROVIDER_OPTIONS,
        "encryption_configured": app_settings.app_encryption_key_bytes is not None,
    }


def _ai_test_card(
    test_status: org_settings.AITestStatus | None = None,
    *,
    status: int = 200,
) -> Response:
    resolved = test_status or org_settings.get_ai_test_status(get_session(), _org_id())
    return render_page(
        "pages/_ai_test_status.html",
        status=status,
        can_manage_ai=has_role(current_user.role, Role.ADMIN),
        test_status=resolved,
    )


def _settings_page(
    *,
    status: int = 200,
    form: dict[str, Any] | None = None,
    errors: dict[str, str] | None = None,
    focus_field: str | None = None,
) -> Response:
    session = get_session()
    app_settings = get_settings()
    org_id = _org_id()
    current = org_settings.get_org_settings(session, org_id)
    overview = org_settings.get_org_budget_overview(session, org_id, app_settings)
    usage = llm_usage.get_usage_summary(session, org_id)
    test_status = org_settings.get_ai_test_status(session, org_id)
    return render_page(
        "pages/settings.html",
        status=status,
        can_manage_ai=has_role(current_user.role, Role.ADMIN),
        overview=overview,
        usage=usage,
        test_status=test_status,
        instance_budget=app_settings.llm_monthly_instance_token_budget,
        **_ai_settings_context(
            form=form,
            errors=errors,
            focus_field=focus_field,
            current=current,
        ),
    )
