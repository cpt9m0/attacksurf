"""Automated WCAG 2.2 AA contrast and light/dark parity checks for tokens.css."""

import re
from pathlib import Path

import pytest

import attacksurf.web

TOKENS_CSS = Path(attacksurf.web.__file__).parent / "static" / "css" / "tokens.css"

# Every foreground/background pair that renders text in light and dark mode (WCAG AA >= 4.5:1).
TEXT_PAIRS: tuple[tuple[str, str], ...] = (
    ("--color-text", "--color-bg"),
    ("--color-text", "--color-surface"),
    ("--color-text", "--color-surface-2"),
    ("--color-text", "--color-surface-hover"),
    ("--color-text-muted", "--color-bg"),
    ("--color-text-muted", "--color-surface"),
    ("--color-text-muted", "--color-surface-2"),
    ("--color-primary", "--color-bg"),
    ("--color-primary", "--color-surface"),
    ("--color-primary", "--color-primary-subtle"),
    ("--color-primary-contrast", "--color-primary"),
    ("--color-primary-contrast", "--color-primary-hover"),
    ("--color-primary-contrast", "--color-danger"),
    ("--color-primary-contrast", "--color-danger-hover"),
    ("--color-danger", "--color-surface"),
    ("--color-danger", "--color-danger-bg"),
    ("--color-warning", "--color-surface"),
    ("--color-warning", "--color-warning-bg"),
    ("--color-success", "--color-surface"),
    ("--sev-critical-fg", "--sev-critical-bg"),
    ("--sev-high-fg", "--sev-high-bg"),
    ("--sev-medium-fg", "--sev-medium-bg"),
    ("--sev-low-fg", "--sev-low-bg"),
    ("--sev-info-fg", "--sev-info-bg"),
    ("--pill-good-fg", "--pill-good-bg"),
    ("--pill-bad-fg", "--pill-bad-bg"),
    ("--pill-active-fg", "--pill-active-bg"),
)


def _extract_block(css: str, selector: str) -> dict[str, str]:
    idx = css.index(selector)
    brace_start = css.index("{", idx)
    depth = 0
    end = brace_start
    for i in range(brace_start, len(css)):
        if css[i] == "{":
            depth += 1
        elif css[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    block = css[brace_start + 1 : end]
    return dict(re.findall(r"(--[a-z0-9-]+)\s*:\s*([^;]+);", block))


def _hex_to_rgb(value: str) -> tuple[float, float, float]:
    raw = value.strip().lstrip("#")
    if len(raw) == 3:
        raw = "".join(ch * 2 for ch in raw)
    return (
        int(raw[0:2], 16) / 255.0,
        int(raw[2:4], 16) / 255.0,
        int(raw[4:6], 16) / 255.0,
    )


def _relative_luminance(hex_color: str) -> float:
    def _channel(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = _hex_to_rgb(hex_color)
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def _contrast_ratio(fg_hex: str, bg_hex: str) -> float:
    l1 = _relative_luminance(fg_hex)
    l2 = _relative_luminance(bg_hex)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize(("fg_token", "bg_token"), TEXT_PAIRS)
def test_token_pair_meets_wcag_aa_contrast(theme: str, fg_token: str, bg_token: str) -> None:
    css = TOKENS_CSS.read_text(encoding="utf-8")
    tokens = _extract_block(css, ":root")
    if theme == "dark":
        tokens.update(_extract_block(css, '[data-theme="dark"]'))

    fg = tokens[fg_token].strip()
    bg = tokens[bg_token].strip()
    ratio = _contrast_ratio(fg, bg)

    assert ratio >= 4.5, (
        f"{theme}: {fg_token} ({fg}) on {bg_token} ({bg}) is {ratio:.2f}:1 (< 4.5:1)"
    )


def test_dark_theme_and_prefers_color_scheme_dark_stay_in_sync() -> None:
    css = TOKENS_CSS.read_text(encoding="utf-8")
    explicit_dark = _extract_block(css, '[data-theme="dark"]')
    media_dark = _extract_block(css, ':root:not([data-theme="light"])')

    assert explicit_dark == media_dark
