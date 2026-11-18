import json

import pytest

from looseend.baseline import apply_baseline, load_baseline
from looseend.models import Category, Confidence, Finding, ScanResult, Severity


def make_finding(line):
    return Finding(
        rule_id="GAP001",
        category=Category.GAP,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        file="a.py",
        line=line,
        message="TODO",
        evidence=f"line {line}",
        fix_hint="fix",
    )


def test_load_from_report(tmp_path):
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"findings": [{"id": "abc"}, {"id": "def"}, {"no_id": 1}]}))
    assert load_baseline(path) == {"abc", "def"}


def test_load_from_plain_list(tmp_path):
    path = tmp_path / "b.json"
    path.write_text(json.dumps(["abc", "def"]))
    assert load_baseline(path) == {"abc", "def"}


def test_invalid_json_raises_value_error(tmp_path):
    path = tmp_path / "b.json"
    path.write_text("{not json")
    with pytest.raises(ValueError):
        load_baseline(path)


def test_wrong_shape_raises_value_error(tmp_path):
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"findings": "nope"}))
    with pytest.raises(ValueError):
        load_baseline(path)


def test_missing_file_raises_os_error(tmp_path):
    with pytest.raises(OSError):
        load_baseline(tmp_path / "missing.json")


def test_apply_baseline_hides_known_findings():
    first, second = make_finding(1), make_finding(2)
    result = ScanResult(root=".", findings=[first, second], files_scanned=2)
    filtered, hidden = apply_baseline(result, {first.id})
    assert hidden == 1
    assert filtered.findings == [second]
    assert filtered.files_scanned == 2
    assert len(result.findings) == 2
