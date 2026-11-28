"""Full-stack Chromium E2E test (#30): signup → domain → verify → scan → AI → FP → rescan diff.

Runs real Flask templates, CSRF, CSP, HTMX polling, Alpine CSP components, PostgreSQL 18,
ScopeGuard, all DNS passive/verified-active plugins, finding diffing, and AI triage/summary
against zero-network DNS/HTTP fakes and a deterministic fake LLM provider.
"""

import importlib
import json
import os
import re
import threading
import time
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from celery.backends.cache import CacheBackend
from playwright.sync_api import Browser, Error, Page, expect, sync_playwright
from pydantic import BaseModel, SecretStr
from sqlalchemy import Engine, create_engine, delete, make_url, select
from sqlalchemy.orm import Session
from werkzeug.serving import make_server

from attacksurf.ai.structured import complete_structured
from attacksurf.app import create_app
from attacksurf.domain.jobs import JobTask
from attacksurf.domain.llm import Completion, LLMResult, Message, TokenUsage
from attacksurf.domain.net import HttpBody
from attacksurf.infra.authoritative_dns import AuthoritativeTxtLookup
from attacksurf.infra.db.models import Org, User
from attacksurf.infra.db.session import create_session_factory
from attacksurf.infra.rdap import IANA_BOOTSTRAP_URL
from attacksurf.infra.scope_guard import ScopeGuard
from attacksurf.services import summary as summary_service
from attacksurf.services import triage as triage_service
from attacksurf.services.ownership import DbOwnershipChecker
from attacksurf.web import ui as ui_module
from attacksurf.web.api import v1 as api_module
from attacksurf.workers import runtime as worker_runtime
from attacksurf.workers.app import TASK_MODULES
from attacksurf.workers.app import app as celery_app
from attacksurf.workers.tasks import ai as ai_tasks
from attacksurf.workers.tasks import pipeline as pipeline_tasks
from tests.dns_fakes import FakeScopeHttp, MutableDnsZone, patch_dnspython_wire
from tests.fakes import FakeCache
from tests.helpers import make_settings

pytestmark = [
    pytest.mark.web_e2e,
    pytest.mark.skipif(
        os.environ.get("RUN_WEB_E2E") != "1",
        reason="needs RUN_WEB_E2E=1 + `uv run playwright install chromium`",
    ),
]

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"
WHOIS_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "dns" / "whois"
TAKEOVER_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "dns" / "takeover"
DOMAIN = "acme-e2e.example.com"


class _InProcessWorkerQueue:
    """Dispatches real Celery tasks asynchronously on a background worker thread."""

    def __init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="e2e-worker")
        self._futures: list[Any] = []

    def enqueue(self, task_name: str, *, org_id: UUID, job_id: UUID) -> str:
        future = self._executor.submit(self._run_task, task_name, str(org_id), str(job_id))
        self._futures.append(future)
        return f"e2e-{job_id}"

    def enqueue_workflow(
        self,
        header: tuple[JobTask, ...],
        tail: tuple[JobTask, ...],
        error: JobTask,
    ) -> None:
        future = self._executor.submit(self._run_workflow, header, tail, error)
        self._futures.append(future)

    def shutdown(self) -> None:
        for future in list(self._futures):
            future.result(timeout=30)
        self._executor.shutdown(wait=True)

    def _run_task(self, task_name: str, org_id: str, job_id: str) -> None:
        task = celery_app.tasks[task_name]
        task.apply(kwargs={"org_id": org_id, "job_id": job_id})

    def _run_workflow(
        self,
        header: tuple[JobTask, ...],
        tail: tuple[JobTask, ...],
        error: JobTask,
    ) -> None:
        for item in header:
            result = celery_app.tasks[item.task_name].apply(
                kwargs={"org_id": str(item.org_id), "job_id": str(item.job_id)}
            )
            if result.failed():
                celery_app.tasks[error.task_name].apply(
                    kwargs={"org_id": str(error.org_id), "job_id": str(error.job_id)}
                )
                return
        for item in tail:
            result = celery_app.tasks[item.task_name].apply(
                kwargs={"org_id": str(item.org_id), "job_id": str(item.job_id)}
            )
            if result.failed():
                celery_app.tasks[error.task_name].apply(
                    kwargs={"org_id": str(error.org_id), "job_id": str(error.job_id)}
                )
                return


def _extract_scan_data(messages: Sequence[Message]) -> dict[str, Any]:
    content = messages[-1].content
    match = re.search(r"<scan_data>\s*(.*?)\s*</scan_data>", content, flags=re.S)
    assert match is not None, "Expected <scan_data> block in prompt"
    return json.loads(match.group(1))


class _DynamicTriageProvider:
    """Fake LLM returning valid `TriageReply` JSON for every finding in the batch."""

    def complete[T: BaseModel](
        self,
        messages: Sequence[Message],
        *,
        schema: type[T],
        max_tokens: int,
    ) -> LLMResult[T]:
        def send(_conversation: Sequence[Message]) -> Completion:
            data = _extract_scan_data(messages)
            judgments = [
                {
                    "ref": item["ref"],
                    "adjusted_severity": item.get("severity", "medium"),
                    "confidence": "high",
                    "false_positive_likelihood": "low",
                    "priority": "P2",
                    "rationale": f"Verified issue for {item['rule_id']} in E2E triage.",
                    "exploitability": "Exposed via public DNS configuration.",
                    "remediation_steps": ["Update the DNS record and confirm propagation."],
                }
                for item in data.get("findings", [])
            ]
            return Completion(
                json.dumps({"findings": judgments}),
                TokenUsage(input_tokens=40, output_tokens=20),
            )

        return complete_structured(send, messages, schema)


class _DynamicSummaryProvider:
    """Fake LLM returning valid `ExposureSummary` JSON referencing the scan's top finding/asset."""

    def complete[T: BaseModel](
        self,
        messages: Sequence[Message],
        *,
        schema: type[T],
        max_tokens: int,
    ) -> LLMResult[T]:
        def send(_conversation: Sequence[Message]) -> Completion:
            data = _extract_scan_data(messages)
            findings = data.get("findings", [])
            assets = data.get("assets", [])
            key_risks = (
                [
                    {
                        "finding_ref": findings[0]["ref"],
                        "why": "Primary actionable exposure detected in this scan.",
                    }
                ]
                if findings
                else []
            )
            notable_assets = (
                [
                    {
                        "asset_ref": assets[0]["ref"],
                        "reason": "Primary internet-facing domain in scope.",
                    }
                ]
                if assets
                else []
            )
            payload = {
                "headline": f"Exposure summary for {data.get('root', DOMAIN)}.",
                "web_exposure": "",
                "key_risks": key_risks,
                "risk_chains": [],
                "notable_assets": notable_assets,
                "changes": "Compared against baseline scan observations.",
                "next_actions": ["Remediate high-priority DNS and takeover findings."],
            }
            return Completion(
                json.dumps(payload),
                TokenUsage(input_tokens=50, output_tokens=25),
            )

        return complete_structured(send, messages, schema)


@dataclass
class E2EHarness:
    base_url: str
    zone: MutableDnsZone
    email: str


def _migrate_test_db(engine: Engine) -> None:
    config = Config(ALEMBIC_INI)
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


def _seed_zone_and_http() -> tuple[MutableDnsZone, FakeScopeHttp]:
    zone = MutableDnsZone()
    zone.set_records(DOMAIN, "A", ["93.184.216.34"])
    zone.set_records(DOMAIN, "NS", [f"ns1.{DOMAIN}", f"ns2.{DOMAIN}"])
    zone.set_records(f"ns1.{DOMAIN}", "A", ["93.184.216.10"])
    zone.set_records(f"ns2.{DOMAIN}", "A", ["93.184.216.11"])
    zone.set_records(
        DOMAIN, "SOA", [f"ns1.{DOMAIN}. hostmaster.{DOMAIN}. 2026112201 3600 600 604800 300"]
    )
    zone.set_records(DOMAIN, "CAA", ['0 issue "letsencrypt.org"'])
    zone.set_records(f"default._domainkey.{DOMAIN}", "TXT", ["v=DKIM1; k=rsa; p=MIIBIjAN"])
    # Intentionally omit SPF and DMARC on Scan #1 so email findings are created.

    # Subdomains discovered via CT:
    # 1. www -> live A record
    zone.set_records(f"www.{DOMAIN}", "A", ["93.184.216.34"])
    # 2. gone -> resolves in Scan #1, loses records in Scan #2 (tests disappeared asset in diff)
    zone.set_records(f"gone.{DOMAIN}", "A", ["93.184.216.35"])
    # 3. old-blog -> CNAMEs to s3.amazonaws.com (NoSuchBucket; verified active takeover check)
    zone.set_records(f"old-blog.{DOMAIN}", "CNAME", ["old-blog-bucket.s3.amazonaws.com"])
    zone.set_records("old-blog-bucket.s3.amazonaws.com", "A", ["93.184.216.80"])

    # Public service hosts needed by ScopeGuard / CT / RDAP
    zone.set_records("crt.sh", "A", ["93.184.216.50"])
    zone.set_records("data.iana.org", "A", ["93.184.216.51"])
    zone.set_records("rdap.verisign.com", "A", ["93.184.216.52"])

    ct_payload = [
        {
            "name_value": f"www.{DOMAIN}\ngone.{DOMAIN}\nold-blog.{DOMAIN}",
            "common_name": f"www.{DOMAIN}",
        }
    ]
    bootstrap = (WHOIS_FIXTURES / "iana_bootstrap.json").read_text(encoding="utf-8")
    rdap = json.dumps(
        {
            "objectClassName": "domain",
            "status": ["client transfer prohibited"],
            "events": [{"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                }
            ],
        }
    )
    takeover_body = (TAKEOVER_FIXTURES / "s3-no-such-bucket.xml").read_bytes()
    http = FakeScopeHttp(
        {
            f"https://crt.sh/?q=%25.{DOMAIN}&output=json": HttpBody(
                200, json.dumps(ct_payload).encode()
            ),
            IANA_BOOTSTRAP_URL: HttpBody(200, bootstrap.encode()),
            "https://rdap.verisign.com/com/v1/domain/example.com": HttpBody(200, rdap.encode()),
            f"http://old-blog.{DOMAIN}/": HttpBody(404, takeover_body),
        },
        resolver=zone,
    )
    return zone, http


@pytest.fixture(scope="module")
def browser() -> Iterator[Browser]:
    with sync_playwright() as playwright:
        try:
            instance = playwright.chromium.launch()
        except Error as exc:
            pytest.skip(f"Playwright chromium is not installed ({exc})")
        yield instance
        instance.close()


def _configure_e2e_runtime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    settings: Any,
    session_factory: Any,
    zone: MutableDnsZone,
    http: FakeScopeHttp,
    worker_queue: _InProcessWorkerQueue,
) -> None:
    for module_name in TASK_MODULES:
        importlib.import_module(module_name)
    monkeypatch.setattr(ui_module, "get_task_queue", lambda: worker_queue)
    monkeypatch.setattr(api_module, "get_task_queue", lambda: worker_queue)
    monkeypatch.setattr(pipeline_tasks, "CeleryTaskQueue", lambda _app: worker_queue)
    monkeypatch.setattr(ai_tasks, "CeleryTaskQueue", lambda _app: worker_queue)
    monkeypatch.setattr(worker_runtime, "session_factory", lambda: session_factory)
    monkeypatch.setattr(worker_runtime, "settings", lambda: settings)
    monkeypatch.setattr(worker_runtime, "txt_lookup", lambda: AuthoritativeTxtLookup(zone))
    monkeypatch.setattr(worker_runtime, "email_sender", lambda: None)
    monkeypatch.setattr(
        worker_runtime,
        "scanner_gate",
        lambda: ScopeGuard(
            dns=zone,
            http=http,
            ownership=DbOwnershipChecker(session_factory),
            cache=FakeCache(),
            active_scans_enabled=True,
        ),
    )
    monkeypatch.setattr(triage_service, "build_provider", lambda _cfg: _DynamicTriageProvider())
    monkeypatch.setattr(summary_service, "build_provider", lambda _cfg: _DynamicSummaryProvider())
    monkeypatch.setitem(celery_app.conf, "task_always_eager", True)
    monkeypatch.setitem(celery_app.conf, "task_eager_propagates", False)
    monkeypatch.setattr(
        celery_app.__dict__["_local"],
        "backend",
        CacheBackend(app=celery_app, backend="memory"),
        raising=False,
    )


def _cleanup_e2e_data(engine: Engine, email: str) -> None:
    with Session(engine) as session:
        user = session.scalars(select(User).where(User.email == email)).one_or_none()
        if user is not None:
            org_ids = session.scalars(select(Org.id).where(Org.slug.like("mvp-e2e-%"))).all()
            if org_ids:
                session.execute(delete(Org).where(Org.id.in_(org_ids)))
            session.execute(delete(User).where(User.id == user.id))
            session.commit()


@pytest.fixture
def e2e_server(monkeypatch: pytest.MonkeyPatch) -> Iterator[E2EHarness]:
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        if os.environ.get("CI"):
            pytest.fail("TEST_DATABASE_URL must be set in CI")
        pytest.skip("TEST_DATABASE_URL not set (see docs/development.md)")
    database = make_url(url).database or ""
    if not database.endswith("_test"):
        pytest.fail(f"TEST_DATABASE_URL must point at a *_test database, got {database!r}")

    engine = create_engine(url)
    _migrate_test_db(engine)
    session_factory = create_session_factory(engine)
    zone, http = _seed_zone_and_http()
    patch_dnspython_wire(monkeypatch, zone)

    settings = make_settings(
        env="test",
        secret_key=SecretStr("e2e-test-secret-key-not-for-prod"),
        database_url=SecretStr(url),
        llm_api_key=SecretStr("fake-e2e-llm-key"),
        llm_model="muse-spark-1.3",
        llm_triage_include_info=False,
    )
    flask_app = create_app(settings)
    flask_app.extensions["db_session_factory"] = session_factory

    worker_queue = _InProcessWorkerQueue()
    _configure_e2e_runtime(
        monkeypatch,
        settings=settings,
        session_factory=session_factory,
        zone=zone,
        http=http,
        worker_queue=worker_queue,
    )

    server = make_server("127.0.0.1", 0, flask_app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    email = f"mvp-e2e-{int(time.time() * 1000)}@example.com"
    try:
        yield E2EHarness(
            base_url=f"http://127.0.0.1:{server.server_port}",
            zone=zone,
            email=email,
        )
    finally:
        worker_queue.shutdown()
        server.shutdown()
        server.server_close()
        _cleanup_e2e_data(engine, email)
        engine.dispose()


def _signup_add_and_verify(page: Page, e2e_server: E2EHarness) -> str:
    page.goto(f"{e2e_server.base_url}/signup")
    page.get_by_label("Email").fill(e2e_server.email)
    page.get_by_label("Password").fill("correct horse battery staple")
    page.get_by_label("Organization name").fill("MVP E2E Org")
    page.get_by_role("button", name="Create account").click()
    expect(page.locator("h1")).to_have_text("Dashboard")

    page.get_by_role("link", name="Assets").click()
    expect(page.locator("h1")).to_have_text("Assets")
    page.locator("#add-domain").get_by_label("Domain").fill(DOMAIN)
    page.locator("#add-domain").get_by_role("button", name="Add domain").click()
    expect(page.locator("h1")).to_have_text(DOMAIN)
    asset_url = page.url
    assert urlparse(asset_url).path.startswith("/assets/")

    page.get_by_role("button", name="Start verification").click()
    txt_code = page.locator("#ownership .copy-field code").inner_text()
    match = re.search(r'TXT "([^"]+)"', txt_code)
    assert match is not None, txt_code
    e2e_server.zone.set_records(f"_attacksurf-verify.{DOMAIN}", "TXT", [match.group(1)])
    page.get_by_role("button", name="Verify now").click()
    expect(page.locator("#ownership .pill-good")).to_have_text("Verified", timeout=20_000)
    return asset_url


def _run_first_scan_and_mark_fp(page: Page, asset_url: str) -> None:
    page.goto(asset_url)
    expect(page.locator(".page-header")).to_contain_text("Verified")
    page.get_by_role("button", name="Scan now").click()
    expect(page.locator("h1")).to_contain_text(f"Scan of {DOMAIN}")
    expect(page.locator("#scan-status")).to_contain_text("completed", timeout=20_000)
    expect(page.locator("#scan-progress")).to_contain_text(
        "Changes since the last scan", timeout=20_000
    )
    expect(page.locator("#scan-triage")).to_contain_text("AI-generated suggestions", timeout=20_000)
    expect(page.locator("#scan-summary")).to_contain_text(
        f"Exposure summary for {DOMAIN}.", timeout=20_000
    )
    expect(page.locator("#scan-summary")).to_contain_text("Key risks")

    page.get_by_role("link", name="Findings").click()
    expect(page.locator("h1")).to_have_text("Findings")
    expect(page.locator("#finding-results")).to_contain_text(
        "CNAME target reports an unclaimed service instance"
    )
    expect(page.locator("#finding-results")).to_contain_text("No SPF record published")
    expect(page.locator("#finding-results")).to_contain_text("No DMARC record published")

    page.get_by_role("link", name="No SPF record published").first.click()
    expect(page.locator("h1")).to_have_text("No SPF record published")
    expect(page.locator(".ai-panel")).to_contain_text("AI-generated with")
    expect(page.locator(".ai-panel")).to_contain_text("P2")
    expect(page.locator(".ai-panel")).to_contain_text("Verified issue for dns.email.spf_missing")

    page.get_by_label("New status").select_option("false_positive")
    page.get_by_label("Comment").fill("Intentional SPF state during E2E test.")
    page.get_by_role("button", name="Update finding").click()
    expect(page.locator(".flash-success")).to_contain_text("Finding updated.")
    expect(page.locator(".page-header")).to_contain_text("false positive")
    expect(page.locator("#finding-timeline").locator("..")).to_contain_text(
        "Intentional SPF state during E2E test."
    )


def _rescan_and_verify_diff(page: Page, e2e_server: E2EHarness, asset_url: str) -> None:
    # Fix DMARC, keep FP SPF, add broken MX, and remove `gone` subdomain before rescanning.
    e2e_server.zone.set_records(
        f"_dmarc.{DOMAIN}", "TXT", [f"v=DMARC1; p=reject; rua=mailto:dmarc@{DOMAIN}"]
    )
    e2e_server.zone.set_records(DOMAIN, "MX", [f"10 broken-mx.{DOMAIN}."])
    e2e_server.zone.clear_name(f"gone.{DOMAIN}", nxdomain=True)

    page.goto(asset_url)
    page.get_by_role("button", name="Scan now").click()
    expect(page.locator("#scan-status")).to_contain_text("completed", timeout=20_000)
    expect(page.locator("#scan-progress")).to_contain_text(
        "Changes since the last scan", timeout=20_000
    )
    expect(page.locator("#scan-summary")).to_contain_text(
        f"Exposure summary for {DOMAIN}.", timeout=20_000
    )
    assert f"gone.{DOMAIN}" in page.locator("#scan-progress").inner_text()

    page.goto(f"{e2e_server.base_url}/findings?status=fixed")
    expect(page.locator("#finding-results")).to_contain_text("No DMARC record published")
    page.goto(f"{e2e_server.base_url}/findings?status=false_positive")
    expect(page.locator("#finding-results")).to_contain_text("No SPF record published")


def test_mvp_full_user_journey(browser: Browser, e2e_server: E2EHarness) -> None:
    context = browser.new_context(viewport={"width": 1280, "height": 900})
    page: Page = context.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(f"pageerror: {exc}"))
    page.on(
        "console",
        lambda msg: (
            errors.append(f"console.{msg.type}: {msg.text}") if msg.type == "error" else None
        ),
    )
    page.add_init_script(
        "window.__cspErrors = []; "
        "document.addEventListener('securitypolicyviolation', e => "
        "window.__cspErrors.push(e.violatedDirective + ':' + e.blockedURI));"
    )
    try:
        asset_url = _signup_add_and_verify(page, e2e_server)
        _run_first_scan_and_mark_fp(page, asset_url)
        _rescan_and_verify_diff(page, e2e_server, asset_url)
        assert page.evaluate("() => window.__cspErrors") == []
        assert errors == []
    finally:
        context.close()
