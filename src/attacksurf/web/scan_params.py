"""Query-string parsing shared by the scan pages and `/api/v1/scans`."""

from uuid import UUID

from flask import abort
from werkzeug.datastructures import MultiDict

from attacksurf.domain.scans import ScanStatus
from attacksurf.services.scan_views import ScanFilter


def parse_scan_filter(args: MultiDict[str, str]) -> tuple[ScanFilter, int]:
    """`(filter, page)` from `root`, `status`, `page`; 400 on bad values.

    Empty values mean "no filter", so a submitted filter form with blank fields works.
    """
    try:
        flt = ScanFilter(
            root_id=UUID(raw) if (raw := args.get("root")) else None,
            status=ScanStatus(raw) if (raw := args.get("status")) else None,
        )
    except ValueError:
        abort(400)
    page = args.get("page", 1, type=int) or 1
    return flt, max(page, 1)
