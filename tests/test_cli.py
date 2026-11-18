import json
from pathlib import Path

import pytest

from looseend.cli import main

CLEAN_APP = Path(__file__).resolve().parent.parent / "examples" / "clean-app"


@pytest.fixture
def dirty(tmp_path):
    (tmp_path / "bad.py").write_text(
        "def read(path):\n"
        "    try:\n"
        "        return open(path).read()\n"
        "    except:\n"
        "        pass\n"
    )
    return tmp_path


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_no_command_prints_help(capsys):
    code, out, _ = run(capsys)
    assert code == 0
    assert "usage" in out.lower()


def test_text_format_reports_findings(capsys, dirty):
    code, out, _ = run(capsys, "scan", str(dirty))
    assert code == 1
    assert "GAP002" in out


def test_json_format(capsys, dirty):
    code, out, _ = run(capsys, "scan", str(dirty), "--format", "json")
    data = json.loads(out)
    assert code == 1
    assert data["summary"]["total"] == len(data["findings"]) > 0


def test_markdown_format(capsys, dirty):
    _, out, _ = run(capsys, "scan", str(dirty), "--format", "markdown")
    assert out.startswith("# LooseEnd report")


def test_sarif_format(capsys, dirty):
    _, out, _ = run(capsys, "scan", str(dirty), "--format", "sarif")
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]


def test_clean_app_exits_zero(capsys):
    code, out, _ = run(capsys, "scan", str(CLEAN_APP))
    assert code == 0
    assert "No findings" in out


def test_fail_on_threshold(capsys, dirty):
    assert run(capsys, "scan", str(dirty), "--fail-on", "none")[0] == 0
    assert run(capsys, "scan", str(dirty), "--fail-on", "critical")[0] == 0
    assert run(capsys, "scan", str(dirty), "--fail-on", "medium")[0] == 1


def test_min_severity_filters_findings(capsys, dirty):
    _, out, _ = run(capsys, "scan", str(dirty), "--format", "json", "--min-severity", "critical")
    assert json.loads(out)["findings"] == []


def test_category_filter(capsys, dirty):
    _, out, _ = run(capsys, "scan", str(dirty), "--format", "json", "--category", "gap")
    categories = {f["category"] for f in json.loads(out)["findings"]}
    assert categories == {"gap"}


def test_output_file(capsys, dirty, tmp_path):
    target = tmp_path / "out" / "report.json"
    target.parent.mkdir()
    code, out, err = run(capsys, "scan", str(dirty), "--format", "json", "--output", str(target))
    assert code == 1
    assert out == ""
    assert "report written" in err
    assert json.loads(target.read_text(encoding="utf-8"))["summary"]["total"] > 0


def test_output_to_missing_directory_is_usage_error(capsys, dirty, tmp_path):
    bad = tmp_path / "nope" / "report.json"
    code, _, err = run(capsys, "scan", str(dirty), "--output", str(bad))
    assert code == 2
    assert "cannot write report" in err


def test_no_color_flag_keeps_output_plain(capsys, dirty):
    _, out, _ = run(capsys, "scan", str(dirty), "--no-color")
    assert "\033[" not in out


def test_baseline_hides_known_findings(capsys, dirty, tmp_path):
    baseline = tmp_path / "baseline.json"
    run(capsys, "scan", str(dirty), "--format", "json", "--output", str(baseline))
    code, out, err = run(capsys, "scan", str(dirty), "--baseline", str(baseline))
    assert code == 0
    assert "No findings" in out
    assert "baseline findings hidden" in err


def test_bad_baseline_is_usage_error(capsys, dirty, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{oops")
    code, _, err = run(capsys, "scan", str(dirty), "--baseline", str(bad))
    assert code == 2
    assert "cannot read baseline" in err


def test_missing_path_is_usage_error(capsys, tmp_path):
    code, _, err = run(capsys, "scan", str(tmp_path / "does-not-exist"))
    assert code == 2
    assert "does not exist" in err


def test_invalid_format_is_usage_error(capsys, dirty):
    code, _, _ = run(capsys, "scan", str(dirty), "--format", "pdf")
    assert code == 2
