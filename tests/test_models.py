"""Tests for models.py."""
from looseend.models import Category, Confidence, Finding, ScanResult, Severity


def _f(**kw):
    defaults = dict(
        rule_id="TEST001",
        category=Category.SECURITY,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file="foo.py",
        line=1,
        message="test",
        evidence="evidence",
        fix_hint="fix",
    )
    defaults.update(kw)
    return Finding(**defaults)


def test_id_stable():
    assert _f().id == _f().id
    assert len(_f().id) == 12


def test_id_differs_on_line():
    assert _f(line=1).id != _f(line=2).id


def test_to_dict():
    d = _f().to_dict()
    assert d["severity"] == "high"
    assert d["category"] == "security"
    assert d["rule_id"] == "TEST001"


def test_sorted_findings():
    r = ScanResult(root="/tmp")
    r.findings = [_f(file="b.py", line=5), _f(file="a.py", line=10), _f(file="a.py", line=1)]
    s = r.sorted_findings()
    assert s[0].file == "a.py" and s[0].line == 1
    assert s[1].file == "a.py" and s[1].line == 10
    assert s[2].file == "b.py" and s[2].line == 5
