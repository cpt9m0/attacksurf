"""Scan-derived data inside prompts (ADR 0029, AGENTS.md rule 8).

Everything a scan observed (DNS records, HTTP bodies, hostnames) is attacker-influenced. It
enters a prompt only through `scan_data_block`: one JSON document between `<scan_data>` tags.
`<`, `>` and `&` are written as JSON escapes and all non-ASCII text is escaped, so no value can
close the block, open a tag, or hide invisible characters; strings, collections and nesting
are capped, so a hostile record can't flood the prompt. The JSON still decodes to the original
values (minus what was capped), so the model reads the data as it is.
"""

import json
from collections.abc import Mapping
from typing import Any

SCAN_DATA_TAG = "scan_data"
TRUNCATION_MARKER = " [truncated]"
TOO_DEEP = "[too deep]"
_ESCAPES = {ord("<"): "\\u003c", ord(">"): "\\u003e", ord("&"): "\\u0026"}


def cap(text: str, limit: int) -> str:
    """`text` cut to at most `limit` characters, ending in `TRUNCATION_MARKER` when cut."""
    if limit <= len(TRUNCATION_MARKER):
        raise ValueError("the limit must leave room for the truncation marker")
    if len(text) <= limit:
        return text
    return text[: limit - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER


def scan_data_block(
    payload: Mapping[str, Any] | list[Any] | tuple[Any, ...],
    *,
    max_string_length: int = 2000,
    max_items: int = 50,
    max_depth: int = 8,
) -> str:
    """`payload` as escaped, capped JSON between `<scan_data>` tags.

    Strings (keys too) longer than `max_string_length` are cut and marked; lists and objects
    keep their first `max_items` entries plus a note of how many were left out; containers
    nested deeper than `max_depth` become `TOO_DEEP`. Values JSON can't hold raise `TypeError`
    (or `ValueError` for NaN and infinity). `payload` itself is never changed.
    """
    if max_items < 1 or max_depth < 1:
        raise ValueError("max_items and max_depth must be at least 1")
    cap("", max_string_length)  # rejects a limit too small for the marker
    capped = _capped(payload, max_string_length, max_items, max_depth, depth=1)
    text = json.dumps(capped, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    # These characters can only occur inside JSON strings, where the escapes mean the same.
    return f"<{SCAN_DATA_TAG}>\n{text.translate(_ESCAPES)}\n</{SCAN_DATA_TAG}>"


def _capped(value: Any, max_string_length: int, max_items: int, max_depth: int, depth: int) -> Any:
    if isinstance(value, str):
        return cap(value, max_string_length)
    if isinstance(value, Mapping | list | tuple) and depth > max_depth:
        return TOO_DEEP
    if isinstance(value, Mapping):
        entries = list(value.items())
        result: dict[Any, Any] = {
            (cap(key, max_string_length) if isinstance(key, str) else key): _capped(
                item, max_string_length, max_items, max_depth, depth + 1
            )
            for key, item in entries[:max_items]
        }
        if len(entries) > max_items:
            result["[truncated]"] = f"{len(entries) - max_items} more entries"
        return result
    if isinstance(value, list | tuple):
        items = list(value)
        result_items = [
            _capped(item, max_string_length, max_items, max_depth, depth + 1)
            for item in items[:max_items]
        ]
        if len(items) > max_items:
            result_items.append(f"[{len(items) - max_items} more items]")
        return result_items
    return value
