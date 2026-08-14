from __future__ import annotations

from pathlib import Path


def healthy_repo(root: Path) -> None:
    (root / "README.md").write_text("# Demo\n", encoding="utf-8")
    (root / "LICENSE").write_text("synthetic license\n", encoding="utf-8")
    (root / "SECURITY.md").write_text("report privately\n", encoding="utf-8")
    (root / "CONTRIBUTING.md").write_text("run tests\n", encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_demo.py").write_text("def test_demo():\n    assert True\n", encoding="utf-8")
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text("on: [pull_request]\n", encoding="utf-8")

