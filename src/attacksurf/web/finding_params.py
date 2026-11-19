"""Query-string parsing shared by the findings pages and `/api/v1/findings`."""

from uuid import UUID

from flask import abort
from werkzeug.datastructures import MultiDict

from attacksurf.domain.assets import MAX_HOSTNAME_LENGTH
from attacksurf.domain.findings import Severity
from attacksurf.domain.rules.catalog import MAX_RULE_ID_LENGTH
from attacksurf.services.finding_views import FindingFilter, FindingSort, FindingStatusFilter

_TRUE = {"1", "true", "on", "yes"}


def parse_finding_filter(args: MultiDict[str, str]) -> tuple[FindingFilter, int]:
    """`(filter, page)` from the finding filters; 400 on bad enum/UUID values.

    Empty values mean "no filter", so a submitted filter form with blank fields works. A
    `new=1` checkbox only ever adds the "new since last scan" restriction.
    """
    rule_id = args.get("rule", "").strip() or None
    asset = args.get("asset", "").strip() or None
    if (rule_id and len(rule_id) > MAX_RULE_ID_LENGTH) or (
        asset and len(asset) > MAX_HOSTNAME_LENGTH
    ):
        abort(400)
    try:
        flt = FindingFilter(
            severity=Severity(raw) if (raw := args.get("severity")) else None,
            status=FindingStatusFilter(args.get("status") or FindingStatusFilter.ACTIVE),
            rule_id=rule_id,
            asset=asset,
            root_id=UUID(raw) if (raw := args.get("root")) else None,
            new_since_last_scan=(args.get("new", "") or "").lower() in _TRUE,
            sort=FindingSort(args.get("sort") or FindingSort.SEVERITY),
        )
    except ValueError:
        abort(400)
    page = args.get("page", 1, type=int) or 1
    return flt, max(page, 1)


def filter_args(flt: FindingFilter) -> dict[str, str]:
    """The non-default filter values as query args, for pagination and export links."""
    args: dict[str, str] = {}
    if flt.severity is not None:
        args["severity"] = flt.severity.value
    if flt.status is not FindingStatusFilter.ACTIVE:
        args["status"] = flt.status.value
    if flt.rule_id:
        args["rule"] = flt.rule_id
    if flt.asset:
        args["asset"] = flt.asset
    if flt.root_id is not None:
        args["root"] = str(flt.root_id)
    if flt.new_since_last_scan:
        args["new"] = "1"
    if flt.sort is not FindingSort.SEVERITY:
        args["sort"] = flt.sort.value
    return args
