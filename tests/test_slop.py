"""Slop analyzer tests — positive and negative cases per rule."""
from pathlib import Path
from looseend.analyzers.slop import SlopAnalyzer


def _run(tmp_path, name, content):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    a = SlopAnalyzer()
    ext = Path(name).suffix.lower()
    langs = {".py": "python", ".js": "javascript", ".ts": "typescript", ".java": "java", ".go": "go"}
    lang = langs.get(ext, "text")
    findings = list(a.analyze(p, content, lang, name))
    findings.extend(a.finalize())
    return findings


# SLOP001: Placeholder stubs
def test_slop001_pass_positive(tmp_path):
    f = _run(tmp_path, "stub.py", "def my_func():\n    pass\n")
    assert any(x.rule_id == "SLOP001" for x in f)


def test_slop001_not_implemented_positive(tmp_path):
    f = _run(tmp_path, "stub.py", "def my_func():\n    raise NotImplementedError\n")
    assert any(x.rule_id == "SLOP001" for x in f)


def test_slop001_lorem_positive(tmp_path):
    f = _run(tmp_path, "content.py", 'text = "Lorem ipsum dolor sit amet"\n')
    assert any(x.rule_id == "SLOP001" for x in f)


def test_slop001_real_code_negative(tmp_path):
    f = _run(tmp_path, "real.py", "def my_func(a: int) -> int:\n    return a * 2\n")
    assert not any(x.rule_id == "SLOP001" for x in f)


# SLOP002: Hallucinated imports
def test_slop002_python_hallucinated_positive(tmp_path):
    # Imaginary third-party library
    f = _run(tmp_path, "app.py", "import imaginary_ai_superpack_xyz\n")
    assert any(x.rule_id == "SLOP002" for x in f)


def test_slop002_python_stdlib_negative(tmp_path):
    f = _run(tmp_path, "app.py", "import os\nimport sys\nimport math\n")
    assert not any(x.rule_id == "SLOP002" for x in f)


def test_slop002_js_hallucinated_positive(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.18.0"}}\n')
    f = _run(tmp_path, "index.js", "import fakePack from 'fake-imaginary-package';\n")
    assert any(x.rule_id == "SLOP002" for x in f)


def test_slop002_js_declared_negative(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.18.0"}}\n')
    f = _run(tmp_path, "index.js", "import express from 'express';\nimport fs from 'fs';\n")
    assert not any(x.rule_id == "SLOP002" for x in f)


# SLOP003: Duplicate blocks
def test_slop003_duplicate_blocks_positive(tmp_path):
    block = (
        "subtotal = price * quantity\n"
        "discount = subtotal * discount_rate\n"
        "taxable = subtotal - discount\n"
        "tax_amount = taxable * tax_rate\n"
        "total = taxable + tax_amount\n"
        "receipt_lines.append(total)\n"
    )
    p1 = tmp_path / "file1.py"
    p2 = tmp_path / "file2.py"
    p1.write_text(block, encoding="utf-8")
    p2.write_text(block, encoding="utf-8")
    a = SlopAnalyzer()
    list(a.analyze(p1, block, "python", "file1.py"))
    list(a.analyze(p2, block, "python", "file2.py"))
    findings = list(a.finalize())
    assert any(x.rule_id == "SLOP003" for x in findings)


def test_slop003_distinct_blocks_negative(tmp_path):
    b1 = "a1 = 1\na2 = 2\na3 = 3\na4 = 4\na5 = 5\na6 = 6\n"
    b2 = "b1 = 10\nb2 = 20\nb3 = 30\nb4 = 40\nb5 = 50\nb6 = 60\n"
    p1 = tmp_path / "f1.py"
    p2 = tmp_path / "f2.py"
    p1.write_text(b1, encoding="utf-8")
    p2.write_text(b2, encoding="utf-8")
    a = SlopAnalyzer()
    list(a.analyze(p1, b1, "python", "f1.py"))
    list(a.analyze(p2, b2, "python", "f2.py"))
    findings = list(a.finalize())
    assert not any(x.rule_id == "SLOP003" for x in findings)


# SLOP004: Commented-out code
def test_slop004_commented_code_positive(tmp_path):
    content = "x = 1\n# val = compute(x)\n# result = val * 2\n# return result\ny = 2\n"
    f = _run(tmp_path, "calc.py", content)
    assert any(x.rule_id == "SLOP004" for x in f)


def test_slop004_prose_comment_negative(tmp_path):
    content = "# This module implements the core logic\n# for scanning codebase files accurately.\n# Designed for stdlib execution.\nx = 1\n"
    f = _run(tmp_path, "calc.py", content)
    assert not any(x.rule_id == "SLOP004" for x in f)


# SLOP005: Debug prints outside tests/CLIs
def test_slop005_print_positive(tmp_path):
    content = "def calculate(x):\n    print('debugging:', x)\n    return x + 1\n"
    f = _run(tmp_path, "service.py", content)
    assert any(x.rule_id == "SLOP005" for x in f)


def test_slop005_print_in_test_negative(tmp_path):
    content = "def test_calculate():\n    print('in test')\n    assert True\n"
    f = _run(tmp_path, "tests/test_service.py", content)
    assert not any(x.rule_id == "SLOP005" for x in f)


def test_slop005_breakpoint_positive(tmp_path):
    content = "def run():\n    breakpoint()\n"
    f = _run(tmp_path, "service.py", content)
    assert any(x.rule_id == "SLOP005" for x in f)


def test_slop005_js_console_positive(tmp_path):
    content = "function run() {\n    console.log('debug');\n}\n"
    f = _run(tmp_path, "app.js", content)
    assert any(x.rule_id == "SLOP005" for x in f)


def test_slop005_js_console_in_test_negative(tmp_path):
    content = "describe('app', () => {\n    console.log('running test');\n});\n"
    f = _run(tmp_path, "test/app.spec.js", content)
    assert not any(x.rule_id == "SLOP005" for x in f)
def test_slop003_short_boilerplate_not_reported(tmp_path):
    block = "a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 6\n"
    p1 = tmp_path / "file1.py"
    p2 = tmp_path / "file2.py"
    p1.write_text(block, encoding="utf-8")
    p2.write_text(block, encoding="utf-8")
    a = SlopAnalyzer()
    list(a.analyze(p1, block, "python", "file1.py"))
    list(a.analyze(p2, block, "python", "file2.py"))
    assert not [x for x in a.finalize() if x.rule_id == "SLOP003"]