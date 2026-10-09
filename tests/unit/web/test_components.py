import pytest
from flask import Flask, flash, render_template_string


def render(app: Flask, source: str, **context: object) -> str:
    with app.test_request_context("/"):
        return render_template_string(source, **context)


@pytest.mark.parametrize("level", ["critical", "high", "medium", "low", "info"])
def test_severity_badge_has_text_icon_and_color_class(app: Flask, level: str) -> None:
    html = render(
        app,
        '{% from "components/badges.html" import severity_badge %}{{ severity_badge(s) }}',
        s=level,
    )

    assert f'class="badge sev-{level}"' in html
    assert level.capitalize() in html
    assert 'aria-hidden="true"' in html


def test_unknown_severity_renders_as_info(app: Flask) -> None:
    html = render(
        app,
        '{% from "components/badges.html" import severity_badge %}{{ severity_badge(s) }}',
        s="<script>x</script>",
    )

    assert "sev-info" in html
    assert "<script>" not in html


@pytest.mark.parametrize(
    ("status", "tone", "label"),
    [
        ("fixed", "good", "fixed"),
        ("failed", "bad", "failed"),
        ("accepted_risk", "neutral", "accepted risk"),
    ],
)
def test_status_pill_tone_and_label(app: Flask, status: str, tone: str, label: str) -> None:
    html = render(
        app, '{% from "components/badges.html" import status_pill %}{{ status_pill(s) }}', s=status
    )

    assert f"pill-{tone}" in html
    assert label in html


def test_data_table_escapes_untrusted_cells(app: Flask) -> None:
    html = render(
        app,
        '{% from "components/table.html" import data_table %}'
        '{{ data_table([("host", "Host")], rows, "Hosts") }}',
        rows=[{"host": '<img src=x onerror="alert(1)">'}],
    )

    assert '<th scope="col">Host</th>' in html
    assert "&lt;img src=x onerror=" in html
    assert "<img" not in html


def test_data_table_without_rows_shows_empty_state(app: Flask) -> None:
    html = render(
        app,
        '{% from "components/table.html" import data_table %}'
        '{{ data_table([("host", "Host")], [], "Hosts", "No hosts", "Add one.") }}',
    )

    assert "<table" not in html
    assert 'class="empty-state"' in html
    assert "No hosts" in html


def test_pagination_links(app: Flask) -> None:
    html = render(
        app,
        '{% from "components/table.html" import pagination %}'
        '{{ pagination(2, 3, "ui.findings", severity="high") }}',
    )

    assert "Page 2 of 3" in html
    assert 'href="/findings?page=1&amp;severity=high"' in html
    assert 'href="/findings?page=3&amp;severity=high"' in html


def test_pagination_hidden_for_single_page(app: Flask) -> None:
    html = render(
        app,
        '{% from "components/table.html" import pagination %}{{ pagination(1, 1, "ui.findings") }}',
    )

    assert html.strip() == ""


def test_button_variants_and_attributes(app: Flask) -> None:
    html = render(
        app,
        '{% from "components/button.html" import button %}'
        '{{ button("Delete", "danger", hx_delete="/x") }}{{ button("Odd", "weird") }}',
    )

    assert 'class="btn btn-danger"' in html
    # HTMX only recognizes the hyphenated attribute name.
    assert 'hx-delete="/x"' in html
    assert "hx_delete" not in html
    assert 'class="btn btn-secondary"' in html


def test_flash_messages_render_with_safe_category(app: Flask) -> None:
    with app.test_request_context("/"):
        flash("Saved", "success")
        flash("Odd", "<bad>")
        html = render_template_string(
            '{% from "components/flash.html" import flash_messages %}{{ flash_messages() }}'
        )

    assert 'role="status"' in html
    assert 'class="flash flash-success">Saved' in html
    assert 'class="flash flash-info">Odd' in html
