"""Finding query-string parsing and link-building helpers."""

from uuid import uuid4

import pytest
from flask import Flask, request
from werkzeug.exceptions import BadRequest

from attacksurf.domain.findings import FindingStatus, Severity
from attacksurf.services.finding_views import FindingFilter, FindingSort, FindingStatusFilter
from attacksurf.web.finding_params import filter_args, parse_finding_filter


def test_parse_finding_filter_defaults(app: Flask) -> None:
    with app.test_request_context("/findings"):
        flt, page = parse_finding_filter(request.args)

    assert flt == FindingFilter()
    assert page == 1


def test_parse_finding_filter_reads_every_filter(app: Flask) -> None:
    root = uuid4()
    with app.test_request_context(
        f"/findings?severity=high&status=fixed&rule=dns.x.y&asset=www&root={root}"
        "&new=1&sort=last_seen&page=3"
    ):
        flt, page = parse_finding_filter(request.args)

    assert flt.severity is Severity.HIGH
    assert flt.status is FindingStatusFilter.FIXED
    assert flt.rule_id == "dns.x.y"
    assert flt.asset == "www"
    assert flt.root_id == root
    assert flt.new_since_last_scan is True
    assert flt.sort is FindingSort.LAST_SEEN
    assert page == 3


@pytest.mark.parametrize("query", ["severity=urgent", "status=nope", "sort=random", "root=nope"])
def test_parse_finding_filter_rejects_bad_values(app: Flask, query: str) -> None:
    with app.test_request_context(f"/findings?{query}"), pytest.raises(BadRequest):
        parse_finding_filter(request.args)


def test_filter_args_keeps_only_non_defaults() -> None:
    assert filter_args(FindingFilter()) == {}
    assert filter_args(
        FindingFilter(
            severity=Severity.CRITICAL,
            status=FindingStatusFilter.OPEN,
            new_since_last_scan=True,
        )
    ) == {"severity": "critical", "status": "open", "new": "1"}


def test_status_filter_matches_finding_statuses() -> None:
    # The extra `active`/`all` members must not shadow a real status value.
    assert FindingStatus.ACCEPTED_RISK.value == FindingStatusFilter.ACCEPTED_RISK
    assert FindingStatus("open") is FindingStatus.OPEN
