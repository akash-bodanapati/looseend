"""Gap analyzer tests — positive and negative cases per rule."""
from pathlib import Path
from looseend.analyzers.gap import GapAnalyzer


def _run(tmp_path, name, content, root=None):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    r = root or tmp_path
    a = GapAnalyzer(root=r)
    ext = Path(name).suffix.lower()
    langs = {".py": "python", ".js": "javascript", ".ts": "typescript", ".java": "java", ".go": "go"}
    lang = langs.get(ext, "text")
    findings = list(a.analyze(p, content, lang, name))
    return findings


# GAP001: TODO/FIXME/HACK
def test_gap001_todo_positive(tmp_path):
    f = _run(tmp_path, "app.py", "# TODO: finish this implementation\nx = 1\n")
    assert any(x.rule_id == "GAP001" for x in f)


def test_gap001_clean_negative(tmp_path):
    f = _run(tmp_path, "app.py", "x = 1\n# Clean comment describing logic\n")
    assert not any(x.rule_id == "GAP001" for x in f)


# GAP002: Bare except
def test_gap002_bare_except_positive(tmp_path):
    content = "try:\n    val = 1 / 0\nexcept:\n    val = 0\n"
    f = _run(tmp_path, "app.py", content)
    assert any(x.rule_id == "GAP002" for x in f)


def test_gap002_typed_except_negative(tmp_path):
    content = "try:\n    val = 1 / 0\nexcept ZeroDivisionError:\n    val = 0\n"
    f = _run(tmp_path, "app.py", content)
    assert not any(x.rule_id == "GAP002" for x in f)


# GAP003: Swallowed errors / empty catch
def test_gap003_python_swallowed_positive(tmp_path):
    content = "try:\n    risky_operation()\nexcept Exception:\n    pass\n"
    f = _run(tmp_path, "app.py", content)
    assert any(x.rule_id == "GAP003" for x in f)


def test_gap003_python_handled_negative(tmp_path):
    content = "try:\n    risky_operation()\nexcept Exception as err:\n    logger.error(err)\n    raise\n"
    f = _run(tmp_path, "app.py", content)
    assert not any(x.rule_id == "GAP003" for x in f)


def test_gap003_js_empty_catch_positive(tmp_path):
    content = "try { risky(); } catch (err) {}\n"
    f = _run(tmp_path, "app.js", content)
    assert any(x.rule_id == "GAP003" for x in f)


def test_gap003_js_handled_negative(tmp_path):
    content = "try { risky(); } catch (err) { console.error(err); throw err; }\n"
    f = _run(tmp_path, "app.js", content)
    assert not any(x.rule_id == "GAP003" for x in f)


# GAP004: Very long functions (>100 lines)
def test_gap004_long_function_positive(tmp_path):
    body = "\n".join(f"    v{i} = {i}" for i in range(110))
    content = f"def giant_monolith():\n{body}\n"
    f = _run(tmp_path, "app.py", content)
    assert any(x.rule_id == "GAP004" for x in f)


def test_gap004_short_function_negative(tmp_path):
    content = "def short_func():\n    return 42\n"
    f = _run(tmp_path, "app.py", content)
    assert not any(x.rule_id == "GAP004" for x in f)


# GAP005: Missing tests
def test_gap005_missing_test_positive(tmp_path):
    src_file = tmp_path / "src" / "my_feature.py"
    src_file.parent.mkdir(parents=True, exist_ok=True)
    src_file.write_text("def run(): return True\n", encoding="utf-8")
    a = GapAnalyzer(root=tmp_path)
    f = list(a.analyze(src_file, "def run(): return True\n", "python", "src/my_feature.py"))
    assert any(x.rule_id == "GAP005" for x in f)


def test_gap005_has_test_negative(tmp_path):
    src_file = tmp_path / "src" / "my_feature.py"
    src_file.parent.mkdir(parents=True, exist_ok=True)
    src_file.write_text("def run(): return True\n", encoding="utf-8")
    test_file = tmp_path / "tests" / "test_my_feature.py"
    test_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.write_text("def test_run(): pass\n", encoding="utf-8")
    a = GapAnalyzer(root=tmp_path)
    f = list(a.analyze(src_file, "def run(): return True\n", "python", "src/my_feature.py"))
    assert not any(x.rule_id == "GAP005" for x in f)


# GAP006: Missing repo hygiene files
def test_gap006_missing_hygiene_positive(tmp_path):
    empty_root = tmp_path / "empty_repo"
    empty_root.mkdir()
    f = _run(empty_root, "dummy.py", "x = 1\n", root=empty_root)
    assert any(x.rule_id == "GAP006" and "README" in x.message for x in f)
    assert any(x.rule_id == "GAP006" and "LICENSE" in x.message for x in f)
    assert any(x.rule_id == "GAP006" and ".gitignore" in x.message for x in f)


def test_gap006_all_hygiene_present_negative(tmp_path):
    repo = tmp_path / "complete_repo"
    repo.mkdir()
    (repo / "README.md").write_text("# Title\n")
    (repo / "LICENSE").write_text("MIT\n")
    (repo / ".gitignore").write_text("*.pyc\n")
    ci = repo / ".github" / "workflows"
    ci.mkdir(parents=True)
    (ci / "ci.yml").write_text("name: CI\n")
    f = _run(repo, "dummy.py", "x = 1\n", root=repo)
    assert not any(x.rule_id == "GAP006" for x in f)


def test_gap006_missing_lockfile_with_deps_positive(tmp_path):
    repo = tmp_path / "app_with_deps"
    repo.mkdir()
    (repo / "README.md").write_text("# App\n")
    (repo / "LICENSE").write_text("MIT\n")
    (repo / ".gitignore").write_text("*.pyc\n")
    ci = repo / ".github" / "workflows"
    ci.mkdir(parents=True)
    (ci / "ci.yml").write_text("name: CI\n")
    # Declares runtime dependencies in pyproject.toml, but has only plain requirements.txt
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1"\ndependencies = ["requests>=2.28"]\n'
    )
    (repo / "requirements.txt").write_text("requests==2.28.0\n")
    f = _run(repo, "dummy.py", "x = 1\n", root=repo)
    assert any(x.rule_id == "GAP006" and "lockfile" in x.message.lower() for x in f)


def test_gap006_lockfile_present_negative(tmp_path):
    repo = tmp_path / "app_with_lockfile"
    repo.mkdir()
    (repo / "README.md").write_text("# App\n")
    (repo / "LICENSE").write_text("MIT\n")
    (repo / ".gitignore").write_text("*.pyc\n")
    ci = repo / ".github" / "workflows"
    ci.mkdir(parents=True)
    (ci / "ci.yml").write_text("name: CI\n")
    (repo / "package.json").write_text('{"dependencies": {"express": "4.18.2"}}\n')
    (repo / "package-lock.json").write_text('{"name": "app", "lockfileVersion": 3}\n')
    f = _run(repo, "dummy.js", "const x = 1;\n", root=repo)
    assert not any(x.rule_id == "GAP006" and "lockfile" in x.message.lower() for x in f)


def _gap001_findings(tmp_path, name, language, content):
    from pathlib import Path
    from looseend.analyzers.gap import GapAnalyzer
    p = Path(tmp_path) / name
    p.write_text(content, encoding="utf-8")
    a = GapAnalyzer(Path(tmp_path))
    return [f for f in a.analyze(p, content, language, name) if f.rule_id == "GAP001"]


def test_gap001_python_comment_flagged(tmp_path):
    assert _gap001_findings(tmp_path, "a.py", "python", "x = 1  # TODO: fix\n")


def test_gap001_python_string_not_flagged(tmp_path):
    assert not _gap001_findings(tmp_path, "a.py", "python", 'msg = "TODO: not a comment"\n')


def test_gap001_js_line_comment_flagged(tmp_path):
    assert _gap001_findings(tmp_path, "a.js", "javascript", "// FIXME: later\nlet x = 1;\n")


def test_gap001_js_block_comment_flagged(tmp_path):
    assert _gap001_findings(tmp_path, "a.js", "javascript", "/*\n HACK: temporary\n*/\nlet x = 1;\n")


def test_gap001_js_string_not_flagged(tmp_path):
    assert not _gap001_findings(tmp_path, "a.js", "javascript", 'const s = "TODO later";\n')


def test_gap001_markdown_not_flagged(tmp_path):
    assert not _gap001_findings(tmp_path, "README.md", "markdown", "- TODO: write docs\n")


def test_gap001_json_not_flagged(tmp_path):
    assert not _gap001_findings(tmp_path, "a.json", "json", '{"note": "TODO: set later"}\n')


def test_gap001_txt_not_flagged(tmp_path):
    assert not _gap001_findings(tmp_path, "a.txt", "text", "TODO: something\n")
