import subprocess


def test_alembic_offline_mode_renders_sql_without_a_database() -> None:
    result = subprocess.run(
        ["alembic", "upgrade", "head", "--sql"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    )

    assert "CREATE TABLE orgs" in result.stdout
