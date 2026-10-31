from datetime import UTC, datetime, timedelta, timezone

import pytest

from attacksurf.web.formatting import exact_time, humanize_delta

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("ago", "text"),
    [
        (timedelta(seconds=0), "just now"),
        (timedelta(seconds=59), "just now"),
        (timedelta(minutes=1), "1 minute ago"),
        (timedelta(minutes=59, seconds=59), "59 minutes ago"),
        (timedelta(hours=2), "2 hours ago"),
        (timedelta(days=1), "1 day ago"),
        (timedelta(days=29), "29 days ago"),
        (timedelta(days=30), "1 month ago"),
        (timedelta(days=364), "12 months ago"),
        (timedelta(days=365 * 3), "3 years ago"),
    ],
)
def test_humanize_delta(ago: timedelta, text: str) -> None:
    assert humanize_delta(NOW - ago, NOW) == text


def test_humanize_delta_treats_future_times_as_just_now() -> None:
    # Small clock skew between DB and app servers must not render "-1 minutes ago".
    assert humanize_delta(NOW + timedelta(minutes=5), NOW) == "just now"


def test_exact_time_is_utc() -> None:
    tehran = timezone(timedelta(hours=3, minutes=30))

    assert exact_time(datetime(2026, 10, 31, 15, 30, tzinfo=tehran)) == "2026-10-31 12:00 UTC"
