"""Keep the scanner, rule, and profile documentation in sync with the codebase."""

import re
from pathlib import Path

from pydantic import SecretStr

from attacksurf.app import create_app
from attacksurf.domain.rules import RULES
from attacksurf.scanners.profiles import PROFILES, WORKER_PROFILES
from attacksurf.scanners.registry import registry
from tests.helpers import make_settings

REPO_ROOT = Path(__file__).resolve().parents[3]
SCANNERS_DOC = REPO_ROOT / "docs" / "scanners.md"


def test_docs_scanners_lists_every_registered_scanner_rule_and_profile() -> None:
    create_app(make_settings(env="test", secret_key=SecretStr("test-secret-key")))
    doc = SCANNERS_DOC.read_text(encoding="utf-8")

    for profile in (*PROFILES, *WORKER_PROFILES):
        assert f"`{profile}`" in doc, f"Missing profile `{profile}` in docs/scanners.md"
    for scanner_name in sorted(registry._scanners):
        assert f"`{scanner_name}`" in doc, f"Missing scanner `{scanner_name}` in docs/scanners.md"
    for rule_id in sorted(RULES):
        assert f"`{rule_id}`" in doc, f"Missing rule `{rule_id}` in docs/scanners.md"


def test_top_level_and_mvp_docs_have_no_broken_local_links() -> None:
    docs_to_check = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "CONTRIBUTING.md",
        REPO_ROOT / "docs" / "README.md",
        REPO_ROOT / "docs" / "architecture.md",
        REPO_ROOT / "docs" / "development.md",
        REPO_ROOT / "docs" / "security.md",
        REPO_ROOT / "docs" / "scanners.md",
        REPO_ROOT / "docs" / "writing-a-scanner.md",
        REPO_ROOT / "docs" / "self-hosting.md",
        REPO_ROOT / "docs" / "responsible-use.md",
    ]
    link_re = re.compile(r"\[[^\]]+\]\(([^)#]+)(?:#[^)]*)?\)")
    for doc_path in docs_to_check:
        text = doc_path.read_text(encoding="utf-8")
        for target in link_re.findall(text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            resolved = (doc_path.parent / target).resolve()
            assert resolved.exists(), f"Broken link {target!r} in {doc_path.relative_to(REPO_ROOT)}"
