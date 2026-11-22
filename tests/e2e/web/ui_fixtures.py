"""Hermetic service-layer UI fixtures for browser layout tests and screenshot capture.

All views are built from the real service/domain dataclasses and patched onto the service modules
without touching PostgreSQL, Redis, or outbound network adapters.
"""

from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import patch
from uuid import UUID

from attacksurf.ai.schemas import (
    FalsePositiveLikelihood,
    StoredKeyRisk,
    StoredNotableAsset,
    StoredSummary,
    StoredTriage,
    TriagePriority,
)
from attacksurf.domain.accounts import InvalidCredentials
from attacksurf.domain.assets import AssetSource, AssetType, RelationKind
from attacksurf.domain.findings import Confidence, EvidenceKind, FindingStatus, Severity
from attacksurf.domain.llm import KeySource, ProviderKind
from attacksurf.domain.scans import JobStatus, ScanStatus, ScanTrigger, ScheduleFrequency
from attacksurf.domain.verification import (
    OwnershipState,
    VerificationMethod,
    VerificationStatus,
)
from attacksurf.services import (
    asset_views,
    finding_views,
    llm_usage,
    notifications,
    org_settings,
    scan_schedules,
    scan_views,
    summary_views,
    triage_views,
    verifications,
)
from attacksurf.services import auth as auth_service

ROOT_ID = UUID("01934e10-0000-7000-8000-000000000001")
ROOT_2_ID = UUID("01934e10-0000-7000-8000-000000000002")
SUBDOMAIN_ID = UUID("01934e10-0000-7000-8000-000000000003")
IP_ID = UUID("01934e10-0000-7000-8000-000000000004")
REPO_ID = UUID("01934e10-0000-7000-8000-000000000005")
BINARY_ID = UUID("01934e10-0000-7000-8000-000000000006")

SCAN_RUNNING_ID = UUID("01934e20-0000-7000-8000-000000000001")
SCAN_DONE_ID = UUID("01934e20-0000-7000-8000-000000000002")

FINDING_1_ID = UUID("01934e30-0000-7000-8000-000000000001")
FINDING_2_ID = UUID("01934e30-0000-7000-8000-000000000002")
FINDING_3_ID = UUID("01934e30-0000-7000-8000-000000000003")
FINDING_4_ID = UUID("01934e30-0000-7000-8000-000000000004")
FINDING_5_ID = UUID("01934e30-0000-7000-8000-000000000005")


@dataclass(frozen=True)
class FakeSchedule:
    enabled: bool
    frequency: ScheduleFrequency
    next_run_at: datetime | None


def _raise_invalid_credentials(*_args: object, **_kwargs: object) -> object:
    raise InvalidCredentials("Invalid email or password.")


@contextmanager
def patch_empty_ui() -> Iterator[None]:
    """Patch service views for a freshly created empty organization."""
    empty_assets = asset_views.AssetPage(items=(), page=1, pages=1, total=0)
    empty_scans = scan_views.ScanPage(items=(), page=1, pages=1, total=0)
    empty_findings = finding_views.FindingPage(items=(), page=1, pages=1, total=0)
    default_settings = org_settings.OrgSettingsView(
        ai_enabled=True,
        provider=ProviderKind.ANTHROPIC,
        model=None,
        base_url=None,
        has_api_key=False,
        api_key_last4=None,
        monthly_token_budget=None,
    )
    default_overview = org_settings.OrgBudgetOverview(
        status="unconfigured",
        key_source=None,
        budget=org_settings.BudgetStatus(
            allowed=False,
            used_tokens=0,
            limit_tokens=None,
            reason="No organization API key or server instance LLM is configured.",
        ),
    )
    empty_usage = llm_usage.UsageSummary(
        months=6,
        current_month="2026-11",
        current_month_tokens=0,
        current_month_instance_tokens=0,
        current_month_org_tokens=0,
        current_month_cost_usd=None,
        total_tokens=0,
        total_cost_usd=None,
        rows=(),
    )
    with ExitStack() as stack:
        stack.enter_context(patch.object(auth_service, "has_users", lambda *_a, **_kw: False))
        stack.enter_context(patch.object(auth_service, "authenticate", _raise_invalid_credentials))
        stack.enter_context(
            patch.object(asset_views, "list_assets", lambda *_a, **_kw: empty_assets)
        )
        stack.enter_context(patch.object(asset_views, "list_root_domains", lambda *_a, **_kw: ()))
        stack.enter_context(patch.object(scan_views, "list_scans", lambda *_a, **_kw: empty_scans))
        stack.enter_context(
            patch.object(scan_views, "active_scan_for_root", lambda *_a, **_kw: None)
        )
        stack.enter_context(
            patch.object(finding_views, "list_findings", lambda *_a, **_kw: empty_findings)
        )
        stack.enter_context(
            patch.object(
                finding_views,
                "list_filter_options",
                lambda *_a, **_kw: finding_views.FindingFilterOptions(roots=(), rules=()),
            )
        )
        stack.enter_context(
            patch.object(
                finding_views,
                "get_dashboard",
                lambda *_a, **_kw: finding_views.DashboardData(
                    open_findings=0, by_severity=(), newest=(), active_assets=0, roots=()
                ),
            )
        )
        stack.enter_context(
            patch.object(summary_views, "list_latest_root_summaries", lambda *_a, **_kw: ())
        )
        stack.enter_context(
            patch.object(org_settings, "get_org_settings", lambda *_a, **_kw: default_settings)
        )
        stack.enter_context(
            patch.object(
                org_settings, "get_org_budget_overview", lambda *_a, **_kw: default_overview
            )
        )
        stack.enter_context(
            patch.object(
                org_settings,
                "get_ai_test_status",
                lambda *_a, **_kw: org_settings.AITestStatus(org_settings.AITestState.NONE),
            )
        )
        stack.enter_context(
            patch.object(llm_usage, "get_usage_summary", lambda *_a, **_kw: empty_usage)
        )
        stack.enter_context(
            patch.object(
                notifications,
                "get_notification_preference",
                lambda *_a, **_kw: notifications.NotificationPreferenceView(
                    email_enabled=True, min_severity=Severity.HIGH
                ),
            )
        )
        yield


@contextmanager
def patch_populated_ui(*, export_warning: bool = False) -> Iterator[None]:  # noqa: PLR0915
    """Patch service views with realistic populated ASM data across all routes."""
    now = datetime.now(UTC)
    two_hours_ago = now - timedelta(hours=2)
    yesterday = now - timedelta(days=1)
    three_days_ago = now - timedelta(days=3)
    seven_days_ago = now - timedelta(days=7)
    in_five_days = now + timedelta(days=5)

    root_asset = asset_views.AssetRow(
        id=ROOT_ID,
        type=AssetType.DOMAIN,
        value="acme-payments.example.com",
        source=AssetSource.USER,
        root_id=None,
        root_value=None,
        tags=("production", "pci-scope"),
        first_seen=seven_days_ago,
        last_seen=two_hours_ago,
        is_active=True,
        open_findings=4,
        max_severity=Severity.CRITICAL,
        verification=OwnershipState.VERIFIED,
    )
    root_2_asset = asset_views.AssetRow(
        id=ROOT_2_ID,
        type=AssetType.DOMAIN,
        value="legacy-portal.example.org",
        source=AssetSource.USER,
        root_id=None,
        root_value=None,
        tags=("staging",),
        first_seen=seven_days_ago,
        last_seen=yesterday,
        is_active=False,
        open_findings=1,
        max_severity=Severity.MEDIUM,
        verification=OwnershipState.NONE,
    )
    subdomain_asset = asset_views.AssetRow(
        id=SUBDOMAIN_ID,
        type=AssetType.SUBDOMAIN,
        value="checkout-edge-us-east-1.acme-payments.example.com",
        source=AssetSource.DISCOVERED,
        root_id=ROOT_ID,
        root_value=root_asset.value,
        tags=("cdn", "external"),
        first_seen=three_days_ago,
        last_seen=two_hours_ago,
        is_active=True,
        open_findings=2,
        max_severity=Severity.CRITICAL,
        verification=OwnershipState.VERIFIED,
    )
    ip_asset = asset_views.AssetRow(
        id=IP_ID,
        type=AssetType.IP,
        value="198.51.100.42",
        source=AssetSource.DISCOVERED,
        root_id=ROOT_ID,
        root_value=root_asset.value,
        tags=(),
        first_seen=three_days_ago,
        last_seen=two_hours_ago,
        is_active=True,
        open_findings=0,
        max_severity=None,
        verification=OwnershipState.NONE,
    )
    repo_asset = asset_views.AssetRow(
        id=REPO_ID,
        type=AssetType.REPO,
        value="checkout-service-2026.11.tar.gz",
        source=AssetSource.USER,
        root_id=None,
        root_value=None,
        tags=("release-candidate",),
        first_seen=yesterday,
        last_seen=yesterday,
        is_active=True,
        open_findings=1,
        max_severity=Severity.HIGH,
        verification=OwnershipState.NONE,
    )
    binary_asset = asset_views.AssetRow(
        id=BINARY_ID,
        type=AssetType.BINARY,
        value="sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        source=AssetSource.USER,
        root_id=None,
        root_value=None,
        tags=("android",),
        first_seen=two_hours_ago,
        last_seen=two_hours_ago,
        is_active=True,
        open_findings=0,
        max_severity=None,
        verification=OwnershipState.NONE,
    )
    assets_by_id = {
        a.id: a
        for a in (root_asset, root_2_asset, subdomain_asset, ip_asset, repo_asset, binary_asset)
    }

    finding_rows = (
        finding_views.FindingRow(
            id=FINDING_1_ID,
            rule_id="dns.takeover.dangling_cname",
            title="Dangling CNAME points to unclaimed cloud bucket",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.OPEN,
            location=(
                "checkout-edge-us-east-1.acme-payments.example.com -> "
                "acme-pay-stage.s3.amazonaws.com"
            ),
            asset_id=SUBDOMAIN_ID,
            asset_type=AssetType.SUBDOMAIN,
            asset_value=subdomain_asset.value,
            root_id=ROOT_ID,
            root_value=root_asset.value,
            first_seen=three_days_ago,
            last_seen=two_hours_ago,
            fixed_at=None,
            scanner="dns.takeover",
        ),
        finding_views.FindingRow(
            id=FINDING_2_ID,
            rule_id="dns.zone_transfer.axfr_open",
            title="Authoritative nameserver permits unauthenticated AXFR zone transfer",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=FindingStatus.REGRESSED,
            location="ns1.acme-payments.example.com (198.51.100.53)",
            asset_id=ROOT_ID,
            asset_type=AssetType.DOMAIN,
            asset_value=root_asset.value,
            root_id=ROOT_ID,
            root_value=root_asset.value,
            first_seen=seven_days_ago,
            last_seen=two_hours_ago,
            fixed_at=None,
            scanner="dns.axfr",
        ),
        finding_views.FindingRow(
            id=FINDING_3_ID,
            rule_id="dns.email.dmarc_policy_none",
            title="DMARC policy is p=none (monitoring only, no spoofing enforcement)",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            status=FindingStatus.OPEN,
            location="_dmarc.acme-payments.example.com",
            asset_id=ROOT_ID,
            asset_type=AssetType.DOMAIN,
            asset_value=root_asset.value,
            root_id=ROOT_ID,
            root_value=root_asset.value,
            first_seen=seven_days_ago,
            last_seen=two_hours_ago,
            fixed_at=None,
            scanner="dns.email",
        ),
        finding_views.FindingRow(
            id=FINDING_4_ID,
            rule_id="dns.caa.missing",
            title="No CAA record restricts which CAs may issue TLS certificates",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            status=FindingStatus.ACCEPTED_RISK,
            location="acme-payments.example.com",
            asset_id=ROOT_ID,
            asset_type=AssetType.DOMAIN,
            asset_value=root_asset.value,
            root_id=ROOT_ID,
            root_value=root_asset.value,
            first_seen=seven_days_ago,
            last_seen=two_hours_ago,
            fixed_at=None,
            scanner="dns.records",
        ),
        finding_views.FindingRow(
            id=FINDING_5_ID,
            rule_id="dns.email.spf_present",
            title="SPF record published with -all hardfail enforcement",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            status=FindingStatus.FIXED,
            location="acme-payments.example.com",
            asset_id=ROOT_ID,
            asset_type=AssetType.DOMAIN,
            asset_value=root_asset.value,
            root_id=ROOT_ID,
            root_value=root_asset.value,
            first_seen=seven_days_ago,
            last_seen=yesterday,
            fixed_at=yesterday,
            scanner="dns.email",
        ),
    )

    stored_triage_p1 = StoredTriage(
        adjusted_severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        false_positive_likelihood=FalsePositiveLikelihood.LOW,
        priority=TriagePriority.P1,
        rationale=(
            "The CNAME target acme-pay-stage.s3.amazonaws.com returns NoSuchBucket while residing "
            "under the PCI-scoped payment domain. An external actor can claim the bucket name to "
            "serve attacker-controlled content or harvest session cookies."
        ),
        exploitability=(
            "Registering the unclaimed S3 bucket name in us-east-1 immediately allows serving "
            "arbitrary HTML/JS under checkout-edge-us-east-1.acme-payments.example.com."
        ),
        remediation_steps=[
            (
                "Remove the CNAME record for checkout-edge-us-east-1.acme-payments.example.com "
                "in Route53 immediately."
            ),
            (
                "If the subdomain is still needed, pre-create and lock the target bucket in your "
                "production AWS account before re-publishing the CNAME."
            ),
            "Audit cookies set on .acme-payments.example.com for overly broad Domain attributes.",
        ],
        prompt_version="triage-v2",
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-5",
        cache_key="a" * 64,
        triaged_at=two_hours_ago,
    )
    stored_triage_p2 = StoredTriage(
        adjusted_severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        false_positive_likelihood=FalsePositiveLikelihood.LOW,
        priority=TriagePriority.P2,
        rationale=(
            "Full zone transfer (AXFR) succeeded against ns1.acme-payments.example.com, exposing "
            "all 48 internal and external DNS resource records in a single query."
        ),
        exploitability=(
            "Any host on the internet can enumerate the entire zone without brute-forcing."
        ),
        remediation_steps=[
            (
                "Restrict allow-transfer on ns1.acme-payments.example.com to authenticated "
                "secondary nameservers using TSIG keys."
            )
        ],
        prompt_version="triage-v2",
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-5",
        cache_key="b" * 64,
        triaged_at=yesterday,
    )

    summary_model = StoredSummary(
        headline=(
            "Critical subdomain takeover risk on checkout-edge-us-east-1 and regressed open AXFR "
            "zone transfer on ns1 require immediate DNS remediation."
        ),
        key_risks=[
            StoredKeyRisk(
                finding_id=FINDING_1_ID,
                why=(
                    "Unclaimed S3 bucket target under the active payment domain enables "
                    "immediate subdomain takeover."
                ),
            ),
            StoredKeyRisk(
                finding_id=FINDING_2_ID,
                why=(
                    "Regressed open AXFR on ns1 exposes the complete zone inventory to "
                    "unauthenticated queries."
                ),
            ),
        ],
        notable_assets=[
            StoredNotableAsset(
                asset_id=SUBDOMAIN_ID,
                reason="Newly discovered payment edge hostname with a dangling CNAME to S3.",
            ),
            StoredNotableAsset(
                asset_id=ROOT_ID,
                reason="Primary PCI-scoped apex domain with p=none DMARC and open AXFR.",
            ),
        ],
        changes=(
            "1 new critical dangling CNAME discovered on checkout-edge-us-east-1; AXFR exposure "
            "regressed on ns1; 1 SPF configuration finding verified fixed."
        ),
        next_actions=[
            (
                "Delete the dangling CNAME record on "
                "checkout-edge-us-east-1.acme-payments.example.com."
            ),
            (
                "Disable public AXFR on ns1.acme-payments.example.com and require TSIG for "
                "secondary transfers."
            ),
            (
                "Advance _dmarc.acme-payments.example.com from p=none to p=quarantine once "
                "RUA reports are clean."
            ),
        ],
        prompt_version="summary-v1",
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-5",
        generated_at=two_hours_ago,
    )

    summary_risks = (
        summary_views.SummaryRiskView(
            finding_id=FINDING_1_ID,
            title=finding_rows[0].title,
            severity=Severity.CRITICAL,
            asset_value=subdomain_asset.value,
            why=(
                "Unclaimed S3 bucket target under the active payment domain enables "
                "immediate subdomain takeover."
            ),
        ),
        summary_views.SummaryRiskView(
            finding_id=FINDING_2_ID,
            title=finding_rows[1].title,
            severity=Severity.HIGH,
            asset_value=root_asset.value,
            why=(
                "Regressed open AXFR on ns1 exposes the complete zone inventory to "
                "unauthenticated queries."
            ),
        ),
    )

    dashboard_data = finding_views.DashboardData(
        open_findings=7,
        by_severity=(
            finding_views.SeverityCount(Severity.CRITICAL, 1),
            finding_views.SeverityCount(Severity.HIGH, 2),
            finding_views.SeverityCount(Severity.MEDIUM, 2),
            finding_views.SeverityCount(Severity.LOW, 1),
            finding_views.SeverityCount(Severity.INFO, 1),
        ),
        newest=finding_rows[:3],
        active_assets=18,
        roots=(
            finding_views.RootScanRow(
                root_id=ROOT_ID,
                root_value=root_asset.value,
                scan_id=SCAN_DONE_ID,
                scan_status=ScanStatus.COMPLETED,
                scan_at=two_hours_ago,
                scan_finished=two_hours_ago,
            ),
            finding_views.RootScanRow(
                root_id=ROOT_2_ID,
                root_value=root_2_asset.value,
                scan_id=SCAN_RUNNING_ID,
                scan_status=ScanStatus.RUNNING,
                scan_at=two_hours_ago,
                scan_finished=None,
            ),
        ),
    )

    root_summaries = (
        summary_views.RootSummaryCard(
            root_id=ROOT_ID,
            root_value=root_asset.value,
            scan_id=SCAN_DONE_ID,
            summary=summary_model,
            top_risks=summary_risks,
            notable_count=2,
        ),
    )

    def _get_asset_detail(
        _session: object, _org_id: UUID, asset_id: UUID
    ) -> asset_views.AssetDetail:
        asset = assets_by_id.get(asset_id, root_asset)
        if asset.id == SUBDOMAIN_ID:
            return asset_views.AssetDetail(
                asset=subdomain_asset,
                outgoing=(
                    asset_views.RelationRow(
                        kind=RelationKind.RESOLVES_TO,
                        peer_id=IP_ID,
                        peer_type=AssetType.IP,
                        peer_value=ip_asset.value,
                        first_seen=three_days_ago,
                        last_seen=two_hours_ago,
                    ),
                ),
                incoming=(
                    asset_views.RelationRow(
                        kind=RelationKind.SUBDOMAIN_OF,
                        peer_id=ROOT_ID,
                        peer_type=AssetType.DOMAIN,
                        peer_value=root_asset.value,
                        first_seen=three_days_ago,
                        last_seen=two_hours_ago,
                    ),
                ),
                discovered=0,
                dns=asset_views.DnsDetails(
                    chain=(
                        "checkout-edge-us-east-1.acme-payments.example.com",
                        "acme-pay-stage.s3.amazonaws.com",
                        "198.51.100.42",
                    ),
                    records=(
                        asset_views.DnsRecordRow("CNAME", ("acme-pay-stage.s3.amazonaws.com.",)),
                        asset_views.DnsRecordRow("A", ("198.51.100.42",)),
                    ),
                    private_ips=(),
                ),
                ip=asset_views.IpDetails(
                    ptr="ec2-198-51-100-42.compute-1.amazonaws.com",
                    asn=16509,
                    org="Amazon.com, Inc.",
                    country="US",
                ),
            )
        return asset_views.AssetDetail(
            asset=root_asset,
            outgoing=(
                asset_views.RelationRow(
                    kind=RelationKind.RESOLVES_TO,
                    peer_id=IP_ID,
                    peer_type=AssetType.IP,
                    peer_value=ip_asset.value,
                    first_seen=seven_days_ago,
                    last_seen=two_hours_ago,
                ),
            ),
            incoming=(
                asset_views.RelationRow(
                    kind=RelationKind.SUBDOMAIN_OF,
                    peer_id=SUBDOMAIN_ID,
                    peer_type=AssetType.SUBDOMAIN,
                    peer_value=subdomain_asset.value,
                    first_seen=three_days_ago,
                    last_seen=two_hours_ago,
                ),
            ),
            discovered=14,
            dns=asset_views.DnsDetails(
                chain=(
                    "acme-payments.example.com",
                    "edge-lb.acme-payments.example.com",
                    "198.51.100.42",
                ),
                records=(
                    asset_views.DnsRecordRow("A", ("198.51.100.42", "198.51.100.43")),
                    asset_views.DnsRecordRow(
                        "MX",
                        ("10 aspmx.l.google.com.", "20 alt1.aspmx.l.google.com."),
                    ),
                    asset_views.DnsRecordRow(
                        "TXT",
                        (
                            "v=spf1 include:_spf.google.com -all",
                            "_attacksurf-challenge=as-verify-9f2c8d1e4a7b6c5d3e2f1a0b",
                        ),
                    ),
                    asset_views.DnsRecordRow(
                        "NS",
                        ("ns1.acme-payments.example.com.", "ns2.acme-payments.example.com."),
                    ),
                ),
                private_ips=("10.24.0.15", "192.168.100.1"),
            ),
            ip=None,
            uploaded_as=None,
        )

    asset_finding_rows = tuple(
        asset_views.FindingRow(
            id=f.id,
            rule_id=f.rule_id,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            status=f.status,
            location=f.location,
            first_seen=f.first_seen,
            last_seen=f.last_seen,
        )
        for f in finding_rows
    )

    asset_scan_rows = (
        asset_views.ScanRow(
            id=SCAN_DONE_ID,
            profile="dns_passive",
            status=ScanStatus.COMPLETED,
            triggered_by=ScanTrigger.USER,
            created_at=two_hours_ago,
            started_at=two_hours_ago,
            finished_at=two_hours_ago,
        ),
        asset_views.ScanRow(
            id=SCAN_RUNNING_ID,
            profile="dns_scheduled",
            status=ScanStatus.RUNNING,
            triggered_by=ScanTrigger.SCHEDULE,
            created_at=yesterday,
            started_at=yesterday,
            finished_at=None,
        ),
    )

    scan_rows = (
        scan_views.ScanRow(
            id=SCAN_RUNNING_ID,
            root_asset_id=ROOT_ID,
            root_value=root_asset.value,
            profile="dns_passive",
            status=ScanStatus.RUNNING,
            triggered_by=ScanTrigger.USER,
            created_at=two_hours_ago,
            started_at=two_hours_ago,
            finished_at=None,
            jobs_finished=3,
            jobs_total=6,
        ),
        scan_views.ScanRow(
            id=SCAN_DONE_ID,
            root_asset_id=ROOT_ID,
            root_value=root_asset.value,
            profile="dns_passive",
            status=ScanStatus.COMPLETED,
            triggered_by=ScanTrigger.SCHEDULE,
            created_at=yesterday,
            started_at=yesterday,
            finished_at=yesterday,
            jobs_finished=6,
            jobs_total=6,
        ),
        scan_views.ScanRow(
            id=UUID("01934e20-0000-7000-8000-000000000003"),
            root_asset_id=ROOT_2_ID,
            root_value=root_2_asset.value,
            profile="dns_passive",
            status=ScanStatus.FAILED,
            triggered_by=ScanTrigger.USER,
            created_at=three_days_ago,
            started_at=three_days_ago,
            finished_at=three_days_ago,
            jobs_finished=2,
            jobs_total=5,
        ),
    )

    def _get_scan_detail(_session: object, _org_id: UUID, scan_id: UUID) -> scan_views.ScanDetail:
        if scan_id == SCAN_RUNNING_ID:
            return scan_views.ScanDetail(
                scan=scan_rows[0],
                jobs=(
                    scan_views.JobRow(
                        id=UUID("01934e40-0000-7000-8000-000000000001"),
                        stage="discovery",
                        scanner="dns.crtsh",
                        asset_id=ROOT_ID,
                        asset_value=root_asset.value,
                        status=JobStatus.COMPLETED,
                        attempts=1,
                        error=None,
                        started_at=two_hours_ago,
                        finished_at=two_hours_ago,
                    ),
                    scan_views.JobRow(
                        id=UUID("01934e40-0000-7000-8000-000000000002"),
                        stage="resolve",
                        scanner="dns.records",
                        asset_id=SUBDOMAIN_ID,
                        asset_value=subdomain_asset.value,
                        status=JobStatus.RUNNING,
                        attempts=1,
                        error=None,
                        started_at=two_hours_ago,
                        finished_at=None,
                    ),
                    scan_views.JobRow(
                        id=UUID("01934e40-0000-7000-8000-000000000003"),
                        stage="checks",
                        scanner="dns.takeover",
                        asset_id=SUBDOMAIN_ID,
                        asset_value=subdomain_asset.value,
                        status=JobStatus.QUEUED,
                        attempts=0,
                        error=None,
                        started_at=None,
                        finished_at=None,
                    ),
                ),
                jobs_finished=3,
                jobs_total=6,
                by_status=(("completed", 3), ("running", 1), ("queued", 2)),
                can_cancel=True,
                diff=None,
            )
        sev_zero = (("critical", 0), ("high", 0), ("medium", 0), ("low", 0), ("info", 0))
        return scan_views.ScanDetail(
            scan=scan_rows[1],
            jobs=(
                scan_views.JobRow(
                    id=UUID("01934e40-0000-7000-8000-000000000004"),
                    stage="discovery",
                    scanner="dns.crtsh",
                    asset_id=ROOT_ID,
                    asset_value=root_asset.value,
                    status=JobStatus.COMPLETED,
                    attempts=1,
                    error=None,
                    started_at=yesterday,
                    finished_at=yesterday,
                ),
                scan_views.JobRow(
                    id=UUID("01934e40-0000-7000-8000-000000000005"),
                    stage="checks",
                    scanner="dns.takeover",
                    asset_id=SUBDOMAIN_ID,
                    asset_value=subdomain_asset.value,
                    status=JobStatus.COMPLETED,
                    attempts=1,
                    error=None,
                    started_at=yesterday,
                    finished_at=yesterday,
                ),
                scan_views.JobRow(
                    id=UUID("01934e40-0000-7000-8000-000000000006"),
                    stage="checks",
                    scanner="dns.axfr",
                    asset_id=ROOT_ID,
                    asset_value=root_asset.value,
                    status=JobStatus.FAILED,
                    attempts=3,
                    error="Authoritative nameserver timed out after 3 retries.",
                    started_at=yesterday,
                    finished_at=yesterday,
                ),
            ),
            jobs_finished=6,
            jobs_total=6,
            by_status=(("completed", 5), ("failed", 1)),
            can_cancel=False,
            diff=scan_views.DiffSummary(
                new_findings=scan_views.SeverityBucket(
                    total=2,
                    by_severity=(
                        ("critical", 1),
                        ("high", 0),
                        ("medium", 1),
                        ("low", 0),
                        ("info", 0),
                    ),
                ),
                fixed_findings=scan_views.SeverityBucket(
                    total=1,
                    by_severity=(
                        ("critical", 0),
                        ("high", 0),
                        ("medium", 0),
                        ("low", 0),
                        ("info", 1),
                    ),
                ),
                regressed_findings=scan_views.SeverityBucket(
                    total=1,
                    by_severity=(
                        ("critical", 0),
                        ("high", 1),
                        ("medium", 0),
                        ("low", 0),
                        ("info", 0),
                    ),
                ),
                total_findings=scan_views.SeverityBucket(total=5, by_severity=sev_zero),
                new_assets=scan_views.DiffAssetBucket(
                    total=1,
                    assets=(
                        scan_views.DiffAsset(
                            id=str(SUBDOMAIN_ID),
                            type="subdomain",
                            value=subdomain_asset.value,
                        ),
                    ),
                    truncated=False,
                ),
                disappeared_assets=scan_views.DiffAssetBucket(
                    total=1,
                    assets=(
                        scan_views.DiffAsset(
                            id=str(IP_ID),
                            type="ip",
                            value="198.51.100.99",
                        ),
                    ),
                    truncated=False,
                ),
            ),
        )

    def _get_scan_summary(
        _session: object, _org_id: UUID, scan_id: UUID
    ) -> summary_views.ScanSummaryView:
        if scan_id == SCAN_RUNNING_ID:
            return summary_views.ScanSummaryView(
                state=summary_views.SummaryState.RUNNING,
                notice=None,
                summary=None,
                key_risks=(),
                notable_assets=(),
            )
        return summary_views.ScanSummaryView(
            state=summary_views.SummaryState.DONE,
            notice=None,
            summary=summary_model,
            key_risks=summary_risks,
            notable_assets=(
                summary_views.SummaryNotableAssetView(
                    asset_id=SUBDOMAIN_ID,
                    value=subdomain_asset.value,
                    asset_type=AssetType.SUBDOMAIN,
                    reason="Newly discovered payment edge hostname with a dangling CNAME to S3.",
                ),
                summary_views.SummaryNotableAssetView(
                    asset_id=ROOT_ID,
                    value=root_asset.value,
                    asset_type=AssetType.DOMAIN,
                    reason="Primary PCI-scoped apex domain with p=none DMARC and open AXFR.",
                ),
            ),
        )

    def _get_scan_triage(_session: object, _org_id: UUID, scan_id: UUID) -> triage_views.ScanTriage:
        if scan_id == SCAN_RUNNING_ID:
            return triage_views.ScanTriage(
                state=triage_views.TriageState.RUNNING,
                notice=None,
                batches_done=2,
                batches_total=5,
                rows=(),
                total=0,
            )
        return triage_views.ScanTriage(
            state=triage_views.TriageState.DONE,
            notice=None,
            batches_done=5,
            batches_total=5,
            rows=(
                triage_views.TriageRow(
                    finding_id=FINDING_1_ID,
                    title=finding_rows[0].title,
                    asset_value=subdomain_asset.value,
                    location=finding_rows[0].location,
                    severity=Severity.CRITICAL,
                    triage=stored_triage_p1,
                    stale=False,
                ),
                triage_views.TriageRow(
                    finding_id=FINDING_2_ID,
                    title=finding_rows[1].title,
                    asset_value=root_asset.value,
                    location=finding_rows[1].location,
                    severity=Severity.HIGH,
                    triage=stored_triage_p2,
                    stale=True,
                ),
            ),
            total=2,
        )

    finding_detail_view = finding_views.FindingDetail(
        finding=finding_rows[0],
        description=(
            "A CNAME record on checkout-edge-us-east-1.acme-payments.example.com delegates "
            "resolution to acme-pay-stage.s3.amazonaws.com, which responds with an HTTP 404 "
            "NoSuchBucket error.\n\n"
            "Because the DNS record remains live in the authoritative zone while the target cloud "
            "resource has been deprovisioned, any third party can claim the bucket name in AWS "
            "S3 and serve arbitrary content under your domain."
        ),
        remediation=(
            "1. Delete the dangling CNAME record from the acme-payments.example.com "
            "DNS zone immediately.\n"
            "2. If the hostname is still required, provision and lock the target S3 bucket before "
            "re-creating the DNS record.\n"
            "3. Review CI/CD teardown scripts so DNS records are removed before cloud buckets "
            "are deleted."
        ),
        references=(
            (
                "https://owasp.org/www-project-web-security-testing-guide/latest/"
                "4-Web_Application_Security_Testing/"
                "02-Configuration_and_Deployment_Management_Testing/"
                "10-Test_for_Subdomain_Takeover"
            ),
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html",
        ),
        ai_triage=stored_triage_p1,
        ai_triage_stale=True,
        evidence=(
            finding_views.EvidenceRow(
                id=UUID("01934e50-0000-7000-8000-000000000001"),
                kind=EvidenceKind.DNS_RECORD,
                title="DNS CNAME chain & HTTP fingerprint",
                fields=(
                    finding_views.EvidenceField(
                        "QNAME", "checkout-edge-us-east-1.acme-payments.example.com"
                    ),
                    finding_views.EvidenceField("CNAME target", "acme-pay-stage.s3.amazonaws.com."),
                    finding_views.EvidenceField("Provider", "AWS S3 (NoSuchBucket)"),
                    finding_views.EvidenceField("Resolver", "9.9.9.9 (UDP/53)"),
                ),
                body=(
                    ";; QUESTION SECTION:\n"
                    ";checkout-edge-us-east-1.acme-payments.example.com. IN A\n\n"
                    ";; ANSWER SECTION:\n"
                    "checkout-edge-us-east-1.acme-payments.example.com. 300 IN CNAME "
                    "acme-pay-stage.s3.amazonaws.com.\n"
                    "acme-pay-stage.s3.amazonaws.com. 60 IN A 52.217.168.105\n\n"
                    "HTTP/1.1 404 Not Found\n"
                    "Server: AmazonS3\n"
                    "<Error><Code>NoSuchBucket</Code>"
                    "<Message>The specified bucket does not exist</Message>"
                    "<BucketName>acme-pay-stage</BucketName></Error>"
                ),
                truncated=True,
                captured_at=two_hours_ago,
            ),
            finding_views.EvidenceRow(
                id=UUID("01934e50-0000-7000-8000-000000000002"),
                kind=EvidenceKind.DNS_RECORD,
                title="Previous observation on authoritative nameserver",
                fields=(
                    finding_views.EvidenceField("Nameserver", "ns1.acme-payments.example.com"),
                    finding_views.EvidenceField("TTL", "300s"),
                ),
                body=(
                    "checkout-edge-us-east-1.acme-payments.example.com. 300 IN CNAME "
                    "acme-pay-stage.s3.amazonaws.com."
                ),
                truncated=False,
                captured_at=three_days_ago,
            ),
        ),
        evidence_total=3,
        events=(
            finding_views.FindingEvent(
                action="Marked open after regression check",
                actor="alice@acme.example.com",
                at=yesterday,
                comment=(
                    "Verified with infra team that staging S3 teardown ran without "
                    "removing Route53 record."
                ),
            ),
        ),
        observations=4,
    )

    populated_settings = org_settings.OrgSettingsView(
        ai_enabled=True,
        provider=ProviderKind.ANTHROPIC,
        model="claude-sonnet-4-5",
        base_url=None,
        has_api_key=True,
        api_key_last4="9xQ2",
        monthly_token_budget=500_000,
    )
    populated_overview = org_settings.OrgBudgetOverview(
        status="org_key",
        key_source=KeySource.ORG,
        budget=org_settings.BudgetStatus(
            allowed=True,
            used_tokens=142_850,
            limit_tokens=500_000,
            reason=None,
        ),
    )
    populated_usage = llm_usage.UsageSummary(
        months=6,
        current_month="2026-11",
        current_month_tokens=142_850,
        current_month_instance_tokens=0,
        current_month_org_tokens=142_850,
        current_month_cost_usd=Decimal("0.684200"),
        total_tokens=418_200,
        total_cost_usd=Decimal("1.942150"),
        rows=(
            llm_usage.UsageBreakdownRow(
                month="2026-11",
                purpose="triage",
                provider=ProviderKind.ANTHROPIC,
                model="claude-sonnet-4-5",
                key_source=KeySource.ORG,
                calls=24,
                failed_calls=0,
                input_tokens=98_400,
                output_tokens=22_150,
                total_tokens=120_550,
                estimated_cost_usd=Decimal("0.574100"),
                has_unreported_usage=False,
                has_unpriced_calls=False,
            ),
            llm_usage.UsageBreakdownRow(
                month="2026-11",
                purpose="summary",
                provider=ProviderKind.ANTHROPIC,
                model="claude-sonnet-4-5",
                key_source=KeySource.ORG,
                calls=6,
                failed_calls=1,
                input_tokens=18_200,
                output_tokens=4_100,
                total_tokens=22_300,
                estimated_cost_usd=Decimal("0.110100"),
                has_unreported_usage=False,
                has_unpriced_calls=False,
            ),
        ),
    )

    proof_view = verifications.VerificationView(
        asset_id=ROOT_ID,
        status=VerificationStatus.VERIFIED,
        state=OwnershipState.VERIFIED,
        method=VerificationMethod.DNS_TXT,
        record_name="_attacksurf-challenge.acme-payments.example.com",
        record_value="as-verify-9f2c8d1e4a7b6c5d3e2f1a0b",
        verified_at=three_days_ago,
        last_checked_at=two_hours_ago,
        expires_at=in_five_days,
    )

    finding_total = 10_500 if export_warning else len(finding_rows)

    with ExitStack() as stack:
        stack.enter_context(patch.object(auth_service, "has_users", lambda *_a, **_kw: True))
        stack.enter_context(patch.object(auth_service, "authenticate", _raise_invalid_credentials))
        stack.enter_context(
            patch.object(
                asset_views,
                "list_assets",
                lambda *_a, **_kw: asset_views.AssetPage(
                    items=tuple(assets_by_id.values()),
                    page=1,
                    pages=3,
                    total=18,
                ),
            )
        )
        stack.enter_context(
            patch.object(
                asset_views,
                "list_root_domains",
                lambda *_a, **_kw: (
                    asset_views.RootOption(id=ROOT_ID, value=root_asset.value, is_active=True),
                    asset_views.RootOption(id=ROOT_2_ID, value=root_2_asset.value, is_active=False),
                ),
            )
        )
        stack.enter_context(
            patch.object(
                asset_views,
                "get_asset",
                lambda _s, _o, aid: assets_by_id.get(aid, root_asset),
            )
        )
        stack.enter_context(patch.object(asset_views, "get_asset_detail", _get_asset_detail))
        stack.enter_context(
            patch.object(
                asset_views,
                "list_asset_findings",
                lambda *_a, **_kw: asset_finding_rows,
            )
        )
        stack.enter_context(
            patch.object(
                asset_views,
                "list_asset_scans",
                lambda *_a, **_kw: asset_scan_rows,
            )
        )
        stack.enter_context(
            patch.object(
                verifications,
                "read_verification",
                lambda *_a, **_kw: proof_view,
            )
        )
        stack.enter_context(
            patch.object(
                verifications,
                "check_in_flight",
                lambda *_a, **_kw: verifications.InFlightCheck(verifications.CheckState.NONE),
            )
        )
        stack.enter_context(
            patch.object(
                scan_schedules,
                "get_schedule",
                lambda *_a, **_kw: FakeSchedule(
                    enabled=True,
                    frequency=ScheduleFrequency.WEEKLY,
                    next_run_at=in_five_days,
                ),
            )
        )
        stack.enter_context(
            patch.object(
                scan_views,
                "list_scans",
                lambda *_a, **_kw: scan_views.ScanPage(
                    items=scan_rows,
                    page=1,
                    pages=2,
                    total=9,
                ),
            )
        )
        stack.enter_context(
            patch.object(scan_views, "active_scan_for_root", lambda *_a, **_kw: None)
        )
        stack.enter_context(patch.object(scan_views, "get_scan_detail", _get_scan_detail))
        stack.enter_context(patch.object(summary_views, "get_scan_summary", _get_scan_summary))
        stack.enter_context(patch.object(triage_views, "get_scan_triage", _get_scan_triage))
        stack.enter_context(
            patch.object(
                finding_views,
                "list_findings",
                lambda *_a, **_kw: finding_views.FindingPage(
                    items=finding_rows,
                    page=1,
                    pages=2,
                    total=finding_total,
                    latest_scan_id=SCAN_DONE_ID,
                    latest_scan_at=two_hours_ago,
                ),
            )
        )
        stack.enter_context(
            patch.object(
                finding_views,
                "list_filter_options",
                lambda *_a, **_kw: finding_views.FindingFilterOptions(
                    roots=(
                        asset_views.RootOption(id=ROOT_ID, value=root_asset.value, is_active=True),
                        asset_views.RootOption(
                            id=ROOT_2_ID, value=root_2_asset.value, is_active=False
                        ),
                    ),
                    rules=(
                        finding_views.RuleOption(
                            id="dns.takeover.dangling_cname",
                            title="Dangling CNAME points to unclaimed cloud bucket",
                        ),
                        finding_views.RuleOption(
                            id="dns.zone_transfer.axfr_open",
                            title="Authoritative nameserver permits AXFR",
                        ),
                    ),
                ),
            )
        )
        stack.enter_context(
            patch.object(
                finding_views, "get_finding_detail", lambda *_a, **_kw: finding_detail_view
            )
        )
        stack.enter_context(
            patch.object(finding_views, "get_dashboard", lambda *_a, **_kw: dashboard_data)
        )
        stack.enter_context(
            patch.object(
                summary_views, "list_latest_root_summaries", lambda *_a, **_kw: root_summaries
            )
        )
        stack.enter_context(
            patch.object(org_settings, "get_org_settings", lambda *_a, **_kw: populated_settings)
        )
        stack.enter_context(
            patch.object(
                org_settings, "get_org_budget_overview", lambda *_a, **_kw: populated_overview
            )
        )
        stack.enter_context(
            patch.object(
                org_settings,
                "get_ai_test_status",
                lambda *_a, **_kw: org_settings.AITestStatus(
                    org_settings.AITestState.COMPLETED,
                    message="Connected to claude-sonnet-4-5 (312 ms).",
                    updated_at=two_hours_ago,
                ),
            )
        )
        stack.enter_context(
            patch.object(llm_usage, "get_usage_summary", lambda *_a, **_kw: populated_usage)
        )
        stack.enter_context(
            patch.object(
                notifications,
                "get_notification_preference",
                lambda *_a, **_kw: notifications.NotificationPreferenceView(
                    email_enabled=True, min_severity=Severity.HIGH
                ),
            )
        )
        yield
