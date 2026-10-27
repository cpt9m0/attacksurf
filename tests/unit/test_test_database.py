"""How the pre-push hook picks the test database (`.github/scripts/test_database.py`)."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "test_database.py"

pytestmark = pytest.mark.skipif(not SCRIPT.is_file(), reason="hook script is not in this checkout")


def _load() -> ModuleType:
    """Import the hook's module by path: it lives outside the installed package."""
    spec = importlib.util.spec_from_file_location("test_database", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


hook = _load()

LOCAL = "postgresql+psycopg://attacksurf:attacksurf@localhost:5432/attacksurf"


def test_shell_variable_wins_over_dotenv() -> None:
    url = hook.test_database_url(
        {"TEST_DATABASE_URL": "postgresql+psycopg://u:p@db:5432/shell_test"},
        {"TEST_DATABASE_URL": "postgresql+psycopg://u:p@db:5432/dotenv_test"},
    )

    assert url.endswith("/shell_test")


def test_dotenv_variable_used_when_the_shell_has_none() -> None:
    url = hook.test_database_url(
        {}, {"TEST_DATABASE_URL": "postgresql+psycopg://u:p@db:5432/x_test"}
    )

    assert url == "postgresql+psycopg://u:p@db:5432/x_test"


def test_dotenv_app_database_is_renamed_to_the_test_database() -> None:
    """A developer who configured DATABASE_URL gets a working hook without extra setup."""
    url = hook.test_database_url({}, {"DATABASE_URL": LOCAL})

    assert url == f"{LOCAL}_test"


def test_derived_url_keeps_host_port_and_credentials() -> None:
    url = hook.test_database_url(
        {"DATABASE_URL": "postgresql+psycopg://user:secret@db.internal:6543/prod"},
        {},
    )

    assert url == "postgresql+psycopg://user:secret@db.internal:6543/prod_test"


def test_falls_back_to_the_documented_local_default() -> None:
    assert hook.test_database_url({}, {}) == hook.DEFAULT_TEST_DATABASE_URL
    assert hook.DEFAULT_TEST_DATABASE_URL.endswith("_test")


@pytest.mark.parametrize(
    "url",
    [
        LOCAL,  # the app database
        "postgresql+psycopg://u:p@db:5432/production",
        "postgresql+psycopg://u:p@db:5432/attacksurf_test_old",
    ],
)
def test_refuses_a_database_that_is_not_a_test_database(url: str) -> None:
    """The fixtures wipe the schema: anything outside `*_test` must never run."""
    with pytest.raises(hook.DatabaseNotResolved, match="_test"):
        hook.check_test_database(url)
    with pytest.raises(hook.DatabaseNotResolved):
        hook.test_database_url({"TEST_DATABASE_URL": url}, {})


def test_refuses_an_app_url_without_a_database_name() -> None:
    with pytest.raises(hook.DatabaseNotResolved, match="no database name"):
        hook.test_database_url({"DATABASE_URL": "postgresql+psycopg://u:p@host:5432"}, {})


def test_dotenv_reader_handles_quotes_comments_and_exports(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text(
        "# comment\n"
        "DATABASE_URL=postgresql+psycopg://u:p@localhost:5432/attacksurf\n"
        "export TEST_DATABASE_URL='postgresql+psycopg://u:p@localhost:5432/attacksurf_test'\n"
        'QUOTED="sealed"\n'
        "\n"
        "NOT_AN_ASSIGNMENT\n"
    )

    values = hook.read_dotenv(env)

    assert values["DATABASE_URL"] == "postgresql+psycopg://u:p@localhost:5432/attacksurf"
    assert values["TEST_DATABASE_URL"] == "postgresql+psycopg://u:p@localhost:5432/attacksurf_test"
    assert values["QUOTED"] == "sealed"
    assert "NOT_AN_ASSIGNMENT" not in values


def test_dotenv_reader_is_empty_when_the_file_is_missing(tmp_path: Path) -> None:
    assert hook.read_dotenv(tmp_path / "missing") == {}
