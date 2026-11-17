"""Tests for scan runner orchestrator."""
from looseend.analyzers.security import SecurityAnalyzer
from looseend.analyzers.slop import SlopAnalyzer
from looseend.engine.runner import run_scan
from looseend.models import Category, Severity


def test_runner_filter_category(tmp_path):
    (tmp_path / "app.py").write_text("x = eval(user_input)\nprint('debug')\n", encoding="utf-8")
    result = run_scan(tmp_path, [SecurityAnalyzer(), SlopAnalyzer()], categories=[Category.SECURITY])
    assert all(f.category == Category.SECURITY for f in result.findings)
    assert any(f.rule_id == "SEC003" for f in result.findings)
    assert not any(f.rule_id == "SLOP005" for f in result.findings)


def test_runner_filter_severity(tmp_path):
    (tmp_path / "app.py").write_text("x = eval(user_input)\nprint('debug')\n", encoding="utf-8")
    result = run_scan(tmp_path, [SecurityAnalyzer(), SlopAnalyzer()], min_severity=Severity.HIGH)
    # SEC003 (CRITICAL) included, SLOP005 (INFO) excluded
    assert all(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in result.findings)
    assert any(f.rule_id == "SEC003" for f in result.findings)
    assert not any(f.rule_id == "SLOP005" for f in result.findings)


def test_runner_file_counts(tmp_path):
    (tmp_path / "one.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "two.py").write_text("y = 2\n", encoding="utf-8")
    result = run_scan(tmp_path, [SecurityAnalyzer()])
    assert result.files_scanned == 2
    assert result.files_skipped == 0
