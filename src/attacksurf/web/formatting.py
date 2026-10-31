"""Display formatting for templates (DESIGN.md §7: relative dates, exact time on hover)."""

from datetime import UTC, datetime

_MINUTE = 60
_HOUR = 60 * _MINUTE
_DAY = 24 * _HOUR
_MONTH = 30 * _DAY
_YEAR = 365 * _DAY
_UNITS = ((_YEAR, "year"), (_MONTH, "month"), (_DAY, "day"), (_HOUR, "hour"), (_MINUTE, "minute"))


def humanize_delta(then: datetime, now: datetime) -> str:
    """ "3 days ago". Anything under a minute, or in the future (clock skew), is "just now"."""
    seconds = (now - then).total_seconds()
    for size, unit in _UNITS:
        if seconds >= size:
            count = int(seconds // size)
            return f"{count} {unit}{'' if count == 1 else 's'} ago"
    return "just now"


def exact_time(value: datetime) -> str:
    """Unambiguous UTC timestamp for tooltips, e.g. `2026-10-31 14:05 UTC`."""
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
