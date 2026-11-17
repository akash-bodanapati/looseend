"""Shared test fixtures."""
from pathlib import Path
import pytest


@pytest.fixture
def tmp_project(tmp_path):
    """Clean project fixture — should produce zero high/medium/critical findings."""
    (tmp_path / "README.md").write_text("# Clean Project\n\nA clean project.\n")
    (tmp_path / "LICENSE").write_text("MIT License\n\nCopyright (c) 2026\n")
    (tmp_path / ".gitignore").write_text("__pycache__/\n*.pyc\n.venv/\n")
    src = tmp_path / "src" / "clean"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text('"""Clean package."""\n')
    (src / "utils.py").write_text(
        '"""Utility functions."""\n\n\ndef add(a: int, b: int) -> int:\n'
        '    """Add two numbers."""\n    return a + b\n'
    )
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "__init__.py").write_text("")
    (tests_dir / "test_utils.py").write_text(
        "from clean.utils import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"
    )
    (tmp_path / "requirements.txt").write_text("pytest==7.4.0\n")
    gh = tmp_path / ".github" / "workflows"
    gh.mkdir(parents=True)
    (gh / "ci.yml").write_text(
        "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps: []\n"
    )
    return tmp_path
