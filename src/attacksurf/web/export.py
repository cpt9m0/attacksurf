"""Finding export files: CSV (formula-safe) and JSON."""

import csv
import json
from datetime import datetime
from io import StringIO

from attacksurf.services.finding_views import FindingExport, FindingRow

CSV_COLUMNS = (
    ("id", "ID"),
    ("severity", "Severity"),
    ("status", "Status"),
    ("title", "Title"),
    ("rule_id", "Rule"),
    ("location", "Location"),
    ("asset", "Asset"),
    ("asset_type", "Asset type"),
    ("root", "Root domain"),
    ("confidence", "Confidence"),
    ("first_seen", "First seen"),
    ("last_seen", "Last seen"),
    ("fixed_at", "Fixed at"),
    ("scanner", "Scanner"),
)
# A spreadsheet treats a cell starting with one of these as a formula. Scan data is untrusted,
# so every text cell that could carry one is prefixed with an apostrophe.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def findings_csv(export: FindingExport) -> str:
    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([label for _, label in CSV_COLUMNS])
    for row in export.items:
        writer.writerow([csv_cell(_value(row, key)) for key, _ in CSV_COLUMNS])
    return buffer.getvalue()


def findings_json(export: FindingExport) -> str:
    payload = {
        "findings": [{key: _value(row, key) for key, _ in CSV_COLUMNS} for row in export.items],
        "count": len(export.items),
        "truncated": export.truncated,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def csv_cell(value: str) -> str:
    """Neutralize spreadsheet formulas in one cell; everything else passes through."""
    return f"'{value}" if value.startswith(_FORMULA_PREFIXES) else value


def _value(row: FindingRow, key: str) -> str:
    match key:
        case "asset":
            return row.asset_value
        case "asset_type":
            return row.asset_type.value
        case "root":
            return row.root_value
        case _:
            value = getattr(row, key, None)
            if isinstance(value, datetime):
                return value.isoformat()
            return "" if value is None else str(value)
