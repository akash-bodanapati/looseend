from pathlib import Path

import pytest

from looseend.analyzers import _toml


@pytest.fixture(params=[True, False], ids=["tomllib-missing", "tomllib-present"])
def mode(request, monkeypatch):
    if request.param:
        monkeypatch.setattr(_toml, "tomllib", None)
    elif _toml.tomllib is None:
        pytest.skip("tomllib not available on this Python")


def test_deps_declared(tmp_path: Path, mode):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = [\n  "requests>=2",\n  "click",\n]\n'
    )
    assert _toml.get_project_deps(tmp_path) == ["requests>=2", "click"]


def test_no_deps(tmp_path: Path, mode):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    assert _toml.get_project_deps(tmp_path) == []


def test_missing_file(tmp_path: Path, mode):
    assert _toml.get_project_deps(tmp_path) == []


def test_ignores_other_sections(tmp_path: Path, mode):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.x]\ndependencies = ["nope"]\n[project]\nname = "x"\n'
    )
    assert _toml.get_project_deps(tmp_path) == []