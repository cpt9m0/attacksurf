"""Unit tests for `web.exposures` (#78)."""

import json
import logging
from collections.abc import Callable, Mapping
from urllib.parse import urlsplit
from uuid import uuid4

import pytest

from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import EvidenceKind, Severity
from attacksurf.domain.jobs import TransientJobError
from attacksurf.domain.net import DnsError, HttpBody, ScannerRuntime
from attacksurf.domain.rules.catalog import build_catalog
from attacksurf.domain.rules.web import WEB_RULES
from attacksurf.domain.scanners import MAX_HTTP_PATHS, AssetRef, ScanContext
from attacksurf.domain.scope import ScopeError
from attacksurf.scanners.web.exposures import (
    _DS_STORE_MAGIC,
    EXPOSURE_PATHS,
    WebExposures,
)
from tests.scanner_fixtures import StubDns


class _StubHttp:
    def __init__(
        self,
        routes: Mapping[str, HttpBody | Callable[[str], HttpBody] | Exception],
        *,
        default_body: Callable[[str, str], HttpBody] | None = None,
    ) -> None:
        self._routes = routes
        self._default_body = default_body
        self.calls: list[tuple[str, str]] = []

    def get(self, url: str, *, limit: int, headers: Mapping[str, str] | None = None) -> HttpBody:
        del headers
        return self._dispatch("GET", url, limit=limit)

    def head(self, url: str, *, headers: Mapping[str, str] | None = None) -> HttpBody:
        del headers
        return self._dispatch("HEAD", url, limit=0)

    def _dispatch(self, method: str, url: str, *, limit: int) -> HttpBody:
        self.calls.append((method, url))
        path = urlsplit(url).path or "/"
        entry = self._routes.get(path)
        if isinstance(entry, Exception):
            raise entry
        if entry is None:
            if self._default_body is not None:
                return self._default_body(method, path)
            return HttpBody(status_code=404, content=b"" if method == "HEAD" else b"Not Found")
        body = entry(path) if callable(entry) else entry
        if method == "HEAD":
            return HttpBody(
                status_code=body.status_code,
                content=b"",
                truncated=False,
                headers=body.headers,
            )
        if len(body.content) > limit:
            return HttpBody(
                status_code=body.status_code,
                content=body.content[:limit],
                truncated=True,
                headers=body.headers,
            )
        return body

    def close(self) -> None:
        pass


def _ctx(
    http: _StubHttp,
    *,
    final_url: str | None = None,
) -> ScanContext:
    target_details: dict[str, object] = {}
    if final_url is not None:
        target_details["web"] = {"final_url": final_url}
    return ScanContext(
        org_id=uuid4(),
        scan_id=uuid4(),
        root_asset=AssetRef(type=AssetType.DOMAIN, value="acme.com"),
        profile="web_active",
        runtime=ScannerRuntime(dns=StubDns(), http=http),  # type: ignore[arg-type]
        target_details=target_details,  # type: ignore[arg-type]
    )


def test_exposure_paths_stay_within_adr_0033_budget() -> None:
    scanner = WebExposures()
    assert len(EXPOSURE_PATHS) <= MAX_HTTP_PATHS
    assert scanner.grant.http_paths == EXPOSURE_PATHS
    assert scanner.grant.http_methods == frozenset({"GET", "HEAD"})
    assert scanner.grant.soft_404_probe is True
    assert scanner.grant.follow_redirects is False


def test_soft_404_catch_all_fixture_with_security_txt_produces_no_findings() -> None:
    def _catch_all(method: str, path: str) -> HttpBody:
        html = f"<html><body><h1>Page {path} not found</h1></body></html>".encode()
        return HttpBody(
            status_code=200,
            content=b"" if method == "HEAD" else html,
            headers={"Content-Type": "text/html", "Content-Length": str(len(html))},
        )

    http = _StubHttp(
        {
            "/.well-known/security.txt": HttpBody(
                status_code=200,
                content=b"Contact: mailto:security@acme.com\nExpires: 2027-01-01T00:00:00Z\n",
                headers={"Content-Type": "text/plain"},
            )
        },
        default_body=_catch_all,
    )

    out = WebExposures().run(_ctx(http), AssetRef(type=AssetType.URL, value="https://acme.com/"))

    assert out.findings == ()
    assert ("GET", "https://acme.com/security.txt") not in http.calls
    head_paths = {urlsplit(url).path for method, url in http.calls if method == "HEAD"}
    assert "/backup.zip" in head_paths
    assert "/actuator/heapdump" in head_paths
    get_paths = {urlsplit(url).path for method, url in http.calls if method == "GET"}
    assert "/backup.zip" not in get_paths
    assert "/actuator/heapdump" not in get_paths


def test_env_exposure_records_key_names_only_and_never_values_in_evidence_or_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret_a = "sk_live_canary_value_abc123"
    secret_b = "postgres://admin:TopSecretPass99@db.internal/prod"
    env_body = (
        f"# App secrets\nOPENAI_API_KEY={secret_a}\nexport DATABASE_URL={secret_b}\nEMPTY_VAR=\n"
    ).encode()
    http = _StubHttp(
        {
            "/.env": HttpBody(
                status_code=200,
                content=env_body,
                headers={"Content-Type": "text/plain"},
            ),
            "/.well-known/security.txt": HttpBody(
                status_code=200,
                content=b"Contact: https://acme.com/security\n",
                headers={"Content-Type": "text/plain"},
            ),
        }
    )

    with caplog.at_level(logging.DEBUG):
        out = WebExposures().run(
            _ctx(http), AssetRef(type=AssetType.URL, value="https://acme.com/")
        )

    assert [f.rule_id for f in out.findings] == ["web.exposure.env_file"]
    ev = out.findings[0].evidence[0]
    assert ev.kind is EvidenceKind.HTTP_RESPONSE
    assert ev.data["key_names"] == ["DATABASE_URL", "EMPTY_VAR", "OPENAI_API_KEY"]
    assert ev.data["key_count"] == 3
    serialized = json.dumps(out.model_dump(mode="json"))
    assert secret_a not in serialized
    assert secret_b not in serialized
    assert secret_a not in caplog.text
    assert secret_b not in caplog.text


def test_git_svn_and_ds_store_validators_and_credential_redaction() -> None:
    http = _StubHttp(
        {
            "/.git/HEAD": HttpBody(
                status_code=200,
                content=b"ref: refs/heads/main\n",
                headers={"Content-Type": "text/plain"},
            ),
            "/.git/config": HttpBody(
                status_code=200,
                content=(
                    b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
                    b"[http]\n\textraheader = AUTHORIZATION: basic dXNlcjpzZWNyZXQ=\n"
                    b'[remote "origin"]\n\turl = https://ci:ghp_secret123@git.acme.com/app.git\n'
                ),
                headers={"Content-Type": "text/plain"},
            ),
            "/.svn/entries": HttpBody(
                status_code=200,
                content=b"10\n\ndir\n42\nhttps://svn.acme.com/repo\n",
                headers={"Content-Type": "text/plain"},
            ),
            "/.DS_Store": HttpBody(
                status_code=200,
                content=_DS_STORE_MAGIC + b"\x00\x00\x10\x00",
                headers={"Content-Type": "application/octet-stream"},
            ),
            "/.well-known/security.txt": HttpBody(
                status_code=200,
                content=b"Contact: mailto:sec@acme.com\n",
                headers={"Content-Type": "text/plain"},
            ),
        }
    )

    out = WebExposures().run(_ctx(http), AssetRef(type=AssetType.URL, value="https://acme.com/app"))

    by_loc = {f.location: f for f in out.findings}
    assert set(by_loc) == {"/.git/HEAD", "/.git/config", "/.svn/entries", "/.DS_Store"}
    assert by_loc["/.git/HEAD"].rule_id == "web.exposure.git_repo"
    assert by_loc["/.git/config"].rule_id == "web.exposure.git_repo"
    cfg_data = by_loc["/.git/config"].evidence[0].data
    assert cfg_data["sections"] == ["core", "http", "remote"]
    assert cfg_data["core_keys"] == ["filemode", "repositoryformatversion"]
    assert cfg_data["remote_count"] == 1
    assert "excerpt" not in cfg_data
    serialized = json.dumps(out.model_dump(mode="json"))
    assert "ghp_secret123" not in serialized
    assert "dXNlcjpzZWNyZXQ=" not in serialized
    assert "extraheader" not in serialized
    assert "git.acme.com" not in serialized
    assert by_loc["/.DS_Store"].rule_id == "web.exposure.backup_archive"
    assert by_loc["/.DS_Store"].severity is Severity.LOW


def test_head_backups_debug_api_docs_admin_and_security_txt_missing() -> None:
    http = _StubHttp(
        {
            "/backup.zip": HttpBody(
                status_code=200,
                content=b"SHOULD_NOT_DOWNLOAD",
                headers={"Content-Type": "application/zip", "Content-Length": "10485760"},
            ),
            "/actuator/heapdump": HttpBody(
                status_code=200,
                content=b"SHOULD_NOT_DOWNLOAD",
                headers={
                    "Content-Type": "application/octet-stream",
                    "Content-Length": "67108864",
                    "Content-Disposition": 'attachment; filename="heapdump"',
                },
            ),
            "/actuator/env": HttpBody(
                status_code=200,
                content=json.dumps(
                    {
                        "activeProfiles": ["prod"],
                        "propertySources": [
                            {
                                "name": "applicationConfig: [classpath:/application.yml]",
                                "properties": {"db.password": {"value": "hidden-pw-value"}},
                            }
                        ],
                    }
                ).encode(),
                headers={"Content-Type": "application/json"},
            ),
            "/phpinfo.php": HttpBody(
                status_code=200,
                content=b"<html><h1>PHP Version 8.2.15</h1><title>phpinfo()</title></html>",
                headers={"Content-Type": "text/html"},
            ),
            "/openapi.json": HttpBody(
                status_code=200,
                content=json.dumps(
                    {
                        "openapi": "3.0.3",
                        "info": {"title": "Acme Internal API"},
                        "paths": {"/v1/users": {}, "/v1/tokens": {}},
                    }
                ).encode(),
                headers={"Content-Type": "application/json"},
            ),
            "/admin": HttpBody(
                status_code=200,
                content=b'<html><form><input type="password" name="pw"></form></html>',
                headers={"Content-Type": "text/html"},
            ),
            "/admin/": HttpBody(
                status_code=200,
                content=b'<html><form><input type="password" name="pw"></form></html>',
                headers={"Content-Type": "text/html"},
            ),
            "/phpmyadmin/": HttpBody(
                status_code=401,
                content=b"",
                headers={"WWW-Authenticate": 'Basic realm="phpMyAdmin"'},
            ),
        }
    )

    out = WebExposures().run(_ctx(http), AssetRef(type=AssetType.URL, value="https://acme.com/"))

    by_loc = {f.location: f for f in out.findings}
    assert set(by_loc) == {
        "/backup.zip",
        "/actuator/heapdump",
        "/actuator/env",
        "/phpinfo.php",
        "/openapi.json",
        "/admin",
        "/phpmyadmin/",
        "",
    }
    assert by_loc["/backup.zip"].evidence[0].data["method"] == "HEAD"
    assert by_loc["/backup.zip"].evidence[0].data["content_length"] == 10485760
    assert by_loc["/actuator/heapdump"].rule_id == "web.exposure.debug_endpoint"
    assert by_loc["/actuator/heapdump"].evidence[0].data["method"] == "HEAD"
    assert "hidden-pw-value" not in json.dumps(by_loc["/actuator/env"].model_dump(mode="json"))
    assert by_loc["/actuator/env"].evidence[0].data["active_profiles"] == ["prod"]
    assert by_loc["/phpinfo.php"].severity is Severity.MEDIUM
    assert by_loc["/phpinfo.php"].evidence[0].data["php_version"] == "8.2.15"
    assert by_loc["/openapi.json"].evidence[0].data["path_count"] == 2
    assert by_loc["/admin"].rule_id == "web.exposure.admin_panel"
    assert by_loc["/phpmyadmin/"].evidence[0].data["auth_scheme"] == "Basic"
    assert by_loc[""].rule_id == "web.security.security_txt_missing"


def test_network_and_scope_errors_raise_transient_job_error() -> None:
    def _raise_dns(_method: str, _path: str) -> HttpBody:
        raise DnsError("timeout")

    dns_fail = _StubHttp({}, default_body=_raise_dns)
    with pytest.raises(TransientJobError):
        WebExposures().run(_ctx(dns_fail), AssetRef(type=AssetType.URL, value="https://acme.com/"))

    scope_fail = _StubHttp({"/.git/HEAD": ScopeError("blocked")})
    with pytest.raises(TransientJobError):
        WebExposures().run(
            _ctx(scope_fail), AssetRef(type=AssetType.URL, value="https://acme.com/")
        )


def test_web_rules_catalog_includes_all_issue_78_rules_with_expected_severities() -> None:
    catalog = build_catalog(WEB_RULES)
    expected = {
        "web.exposure.git_repo": Severity.HIGH,
        "web.exposure.env_file": Severity.CRITICAL,
        "web.exposure.backup_archive": Severity.HIGH,
        "web.exposure.debug_endpoint": Severity.HIGH,
        "web.exposure.api_docs": Severity.INFO,
        "web.exposure.admin_panel": Severity.INFO,
        "web.security.security_txt_missing": Severity.INFO,
    }
    for rule_id, severity in expected.items():
        assert catalog[rule_id].default_severity is severity
