import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from flask import Flask, flash, render_template_string

import attacksurf.web


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


def test_data_table_call_block_renders_rich_cells_still_escaped(app: Flask) -> None:
    html = render(
        app,
        '{% from "components/table.html" import data_table %}'
        '{% call(row, key) data_table([("host", "Host"), ("n", "N")], rows, "Hosts") %}'
        '{% if key == "host" %}<code>{{ row.host }}</code>{% else %}{{ row.n }}{% endif %}'
        "{% endcall %}",
        rows=[{"host": "<b>x</b>", "n": 3}],
    )

    assert "<td><code>&lt;b&gt;x&lt;/b&gt;</code></td><td>3</td>" in html


def test_select_field_marks_the_selected_option(app: Flask) -> None:
    html = render(
        app,
        '{% from "components/form.html" import select_field %}'
        '{{ select_field("type", "Type", [("", "All"), ("ip", "IP")], "ip") }}',
    )

    assert '<label for="f-type">Type</label>' in html
    assert '<option value="">All</option>' in html
    assert '<option value="ip" selected>IP</option>' in html


def test_form_field_autofocus_is_opt_in(app: Flask) -> None:
    source = (
        '{% from "components/form.html" import form_field %}{{ form_field("v", "V", autofocus=f) }}'
    )

    assert " autofocus" in render(app, source, f=True)
    assert " autofocus" not in render(app, source, f=False)


def test_confirm_dialog_uses_registered_alpine_component_and_csrf(app: Flask) -> None:
    html = render(
        app,
        '{% from "components/confirm.html" import confirm_dialog %}'
        '{{ confirm_dialog("arch", "Archive", "Archive <x>?", "Gone.", "/a/1/archive", "Do it") }}',
    )

    assert 'x-data="confirmDialog"' in html
    assert '@click="open"' in html
    assert '@click="close"' in html
    assert 'aria-labelledby="arch-title"' in html
    assert "Archive &lt;x&gt;?" in html
    assert '<form method="post" action="/a/1/archive"' in html
    assert 'name="csrf_token"' in html
    assert not re.search(r"\son[a-z]+\s*=|\sstyle\s*=|<script", html)


def test_confirm_dialog_component_is_registered_in_app_js() -> None:
    # Alpine's CSP build only runs components registered in app.js.
    js = (Path(attacksurf.web.__file__).parent / "static" / "js" / "app.js").read_text()

    assert 'Alpine.data("confirmDialog"' in js


def test_relative_time_shows_exact_utc_on_hover(app: Flask) -> None:
    value = datetime.now(UTC) - timedelta(days=3, minutes=1)
    html = render(
        app, '{% from "components/time.html" import relative_time %}{{ relative_time(v) }}', v=value
    )

    assert f'<time datetime="{value.isoformat()}"' in html
    assert f'title="{value:%Y-%m-%d %H:%M} UTC"' in html
    assert ">3 days ago</time>" in html


def test_relative_time_without_a_value_renders_a_dash(app: Flask) -> None:
    html = render(
        app, '{% from "components/time.html" import relative_time %}{{ relative_time(none) }}'
    )

    assert "—" in html
    assert "<time" not in html
