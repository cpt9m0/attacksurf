"""CSV/JSON finding exports: formula neutralization and file shape."""

import csv
import io
import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from attacksurf.domain.assets import AssetType
from attacksurf.domain.findings import Confidence, FindingStatus, Severity
from attacksurf.services.finding_views import FindingExport, FindingRow
from attacksurf.web.export import csv_cell, findings_csv, findings_json

ROW = FindingRow(
    id=uuid4(),
    rule_id="dns.email.dmarc_missing",
    title="=SUM(A1)",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    status=FindingStatus.OPEN,
    location="-1",
    asset_id=uuid4(),
    asset_type=AssetType.DOMAIN,
    asset_value="example.com",
    root_id=None,
    root_value="example.com",
    first_seen=datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
    last_seen=datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
    fixed_at=None,
    scanner="dns.email",
)


@pytest.mark.parametrize("value", ["=1+1", "+CMD", "-2+3", "@SUM", "\t=1", "\r=1"])
def test_csv_cell_prefixes_every_formula_trigger(value: str) -> None:
    assert csv_cell(value) == f"'{value}"


@pytest.mark.parametrize("value", ["plain", "https://example.com", "", "a=b"])
def test_csv_cell_leaves_other_values_alone(value: str) -> None:
    assert csv_cell(value) == value


def test_findings_csv_has_a_header_and_neutralized_scan_data() -> None:
    rows = list(csv.reader(io.StringIO(findings_csv(FindingExport((ROW,), False)))))

    assert rows[0][:4] == ["ID", "Severity", "Status", "Title"]
    assert rows[1][3] == "'=SUM(A1)"
    assert rows[1][5] == "'-1"
    assert rows[1][6] == "example.com"


def test_findings_json_reports_the_count_and_truncation() -> None:
    payload = json.loads(findings_json(FindingExport((ROW,), True)))

    assert payload["count"] == 1
    assert payload["truncated"] is True
    assert payload["findings"][0]["severity"] == "high"
    assert payload["findings"][0]["first_seen"] == "2026-10-01T12:00:00+00:00"
