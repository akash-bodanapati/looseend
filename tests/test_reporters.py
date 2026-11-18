import json

import pytest

from looseend.models import Category, Confidence, Finding, ScanResult, Severity
from looseend.reporters import (
    render,
    render_json,
    render_markdown,
    render_sarif,
    render_text,
    summarize,
)


def make_finding(
    rule_id="SEC003",
    severity=Severity.HIGH,
    category=Category.SECURITY,
    file="app.py",
    line=3,
    message="eval used",
    fix_hint="Avoid eval",
):
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        file=file,
        line=line,
        message=message,
        evidence="eval(x)",
        fix_hint=fix_hint,
    )


@pytest.fixture
def result():
    return ScanResult(
        root="/tmp/x",
        files_scanned=4,
        findings=[
            make_finding(),
            make_finding("GAP001", Severity.INFO, Category.GAP, "b.py", 7, "TODO found"),
        ],
    )


def test_summarize_counts_and_risk_score(result):
    summary = summarize(result)
    assert summary["total"] == 2
    assert summary["by_severity"]["high"] == 1
    assert summary["by_severity"]["info"] == 1
    assert summary["by_category"] == {"security": 1, "gap": 1}
    assert summary["risk_score"] == 5


def test_text_without_color_has_no_ansi(result):
    assert "\033[" not in render_text(result, color=False)


def test_text_with_color_has_ansi(result):
    assert "\033[" in render_text(result, color=True)


def test_text_reports_clean_result():
    assert "No findings" in render_text(ScanResult(root="."))


def test_text_lists_errors():
    out = render_text(ScanResult(root=".", errors=["boom"]))
    assert "warning: boom" in out


def test_json_includes_summary(result):
    data = json.loads(render_json(result))
    assert data["summary"]["total"] == 2
    assert [f["file"] for f in data["findings"]] == ["app.py", "b.py"]


def test_markdown_has_table_and_escapes_pipes():
    finding = make_finding(message="a | b", file="dir\\app.py")
    out = render_markdown(ScanResult(root=".", findings=[finding]))
    assert out.startswith("# LooseEnd report")
    assert "| Severity | Rule | Location | Message | Fix |" in out
    assert "a \\| b" in out
    assert "dir/app.py:3" in out


def test_markdown_clean_result():
    assert "No findings" in render_markdown(ScanResult(root="."))


def test_sarif_structure(result):
    doc = json.loads(render_sarif(result))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "LooseEnd"
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert rule_ids == sorted(rule_ids)
    for item in run["results"]:
        assert rule_ids[item["ruleIndex"]] == item["ruleId"]
        region = item["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert item["partialFingerprints"]["looseendFindingId/v1"]


def test_sarif_levels_and_paths():
    findings = [
        make_finding(severity=Severity.CRITICAL, file="a\\b.py"),
        make_finding("GAP006", Severity.MEDIUM, Category.GAP, "c.py", 0),
        make_finding("GAP001", Severity.INFO, Category.GAP, "d.py", 2),
    ]
    results = json.loads(render_sarif(ScanResult(root=".", findings=findings)))["runs"][0]["results"]
    by_rule = {r["ruleId"]: r for r in results}
    assert by_rule["SEC003"]["level"] == "error"
    assert by_rule["GAP006"]["level"] == "warning"
    assert by_rule["GAP001"]["level"] == "note"
    assert by_rule["SEC003"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "a/b.py"
    assert by_rule["GAP006"]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_sarif_clean_result_is_valid():
    doc = json.loads(render_sarif(ScanResult(root=".")))
    assert doc["runs"][0]["results"] == []


def test_render_dispatch_and_unknown_format(result):
    for fmt in ("text", "json", "markdown", "sarif"):
        assert render(fmt, result)
    with pytest.raises(ValueError):
        render("pdf", result)
