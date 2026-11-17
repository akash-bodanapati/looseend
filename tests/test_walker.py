"""Tests for file walker, ignore matching, and inline ignore parsing."""
from pathlib import Path
from looseend.engine.analyzer import parse_inline_ignores, should_ignore
from looseend.engine.walker import _matches_gitignore, walk_files


def test_walk_basic(tmp_path):
    (tmp_path / "foo.py").write_text("x = 1")
    (tmp_path / "bar.js").write_text("var x = 1;")
    names = {f.name for f, _ in walk_files(tmp_path)}
    assert "foo.py" in names and "bar.js" in names


def test_respects_gitignore(tmp_path):
    (tmp_path / ".gitignore").write_text("secret.py\n")
    (tmp_path / "secret.py").write_text("SECRET = 'abc'")
    (tmp_path / "normal.py").write_text("x = 1")
    names = {f.name for f, _ in walk_files(tmp_path)}
    assert "secret.py" not in names and "normal.py" in names


def test_skips_node_modules(tmp_path):
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("module.exports = {}")
    (tmp_path / "app.js").write_text("const x = 1")
    names = {f.name for f, _ in walk_files(tmp_path)}
    assert "index.js" not in names and "app.js" in names


def test_skips_large_files(tmp_path):
    (tmp_path / "big.py").write_bytes(b"x = 1\n" * 200000)
    names = {f.name for f, _ in walk_files(tmp_path)}
    assert "big.py" not in names


def test_gitignore_patterns():
    assert _matches_gitignore("secret.py", ["secret.py"])
    assert _matches_gitignore("dist/bundle.js", ["dist/"])
    assert not _matches_gitignore("normal.py", ["secret.py"])


def test_inline_ignore():
    source = "x = eval(code) # looseend: ignore[SEC003]\ny = 2\n"
    ignores = parse_inline_ignores(source)
    assert should_ignore(1, "SEC003", ignores)
    assert not should_ignore(1, "SEC001", ignores)
    assert not should_ignore(2, "SEC003", ignores)


def test_inline_ignore_wildcard():
    source = "x = eval(code) # looseend: ignore\n"
    ignores = parse_inline_ignores(source)
    assert should_ignore(1, "SEC003", ignores)
    assert should_ignore(1, "SEC001", ignores)
