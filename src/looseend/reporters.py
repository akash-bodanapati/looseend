"""Report renderers: text, JSON, Markdown and SARIF 2.1.0."""
from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError, version

from looseend.models import Finding, ScanResult

FORMATS = ("text", "json", "markdown", "sarif")
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

_RISK_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/akash-bodanapati/looseend"

_ANSI = {
    "critical": "\033[91m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"

RULE_TITLES = {
    "SEC001": "Hardcoded secret or credential",
    "SEC002": "High-entropy string that looks like a secret",
    "SEC003": "Dangerous or insecure code pattern",
    "SEC004": "Secret or key file committed to the repository",
    "SEC005": "Unpinned or wildcard dependency version",
    "SLOP001": "Placeholder stub or fake content",
    "SLOP002": "Import not found in stdlib or declared dependencies",
    "SLOP003": "Duplicated code block",
    "SLOP004": "Commented-out code",
    "SLOP005": "Leftover debug output or breakpoint",
    "GAP001": "TODO/FIXME marker: unfinished work",
    "GAP002": "Bare except clause",
    "GAP003": "Swallowed exception",
    "GAP004": "Overly long function",
    "GAP005": "Missing test file",
    "GAP006": "Missing repository hygiene file",
}


def summarize(result: ScanResult) -> dict:
    """Counts by severity and category, plus a weighted risk score."""
    by_severity = {name: 0 for name in SEVERITY_ORDER}
    by_category: dict[str, int] = {}
    for finding in result.findings:
        by_severity[finding.severity.value] += 1
        key = finding.category.value
        by_category[key] = by_category.get(key, 0) + 1
    score = sum(_RISK_WEIGHT[name] * count for name, count in by_severity.items())
    return {
        "total": len(result.findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "risk_score": score,
    }


def _posix(path: str) -> str:
    return path.replace("\\", "/")


def render_text(result: ScanResult, color: bool = False) -> str:
    def paint(text: str, severity: str) -> str:
        return f"{_ANSI[severity]}{text}{_RESET}" if color else text

    bold, reset = (_BOLD, _RESET) if color else ("", "")
    lines: list[str] = []
    findings = result.sorted_findings()
    if not findings:
        lines.append("✓ No findings. Clean codebase!")
    for f in findings:
        sev = paint(f.severity.value.upper(), f.severity.value)
        lines.append(f"\n{bold}[{f.rule_id}]{reset} {sev} — {f.file}:{f.line}")
        lines.append(f"  {f.message}")
        if f.evidence:
            lines.append(f"  evidence: {f.evidence[:120]}")
        if f.fix_hint:
            lines.append(f"  fix: {f.fix_hint}")
    summary = summarize(result)
    lines.append(
        f"\n── {result.files_scanned} files scanned · "
        f"{summary['total']} findings · {result.files_skipped} skipped ──"
    )
    counts = ", ".join(
        f"{count} {name}" for name, count in summary["by_severity"].items() if count
    )
    if counts:
        lines.append(f"Severity: {counts} · risk score {summary['risk_score']}")
    lines.extend(f"warning: {error}" for error in result.errors)
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    data = result.to_dict()
    data["summary"] = summarize(result)
    return json.dumps(data, indent=2)


def _cell(text: object) -> str:
    """Escape text for a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(result: ScanResult) -> str:
    summary = summarize(result)
    lines = [
        "# LooseEnd report",
        "",
        f"- **Files scanned:** {result.files_scanned} ({result.files_skipped} skipped)",
        f"- **Findings:** {summary['total']}",
        f"- **Risk score:** {summary['risk_score']}",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    lines.extend(f"| {name} | {count} |" for name, count in summary["by_severity"].items())
    lines.append("")
    findings = result.sorted_findings()
    if not findings:
        lines.append("No findings. Clean codebase!")
        return "\n".join(lines)
    lines.extend(
        [
            "## Findings",
            "",
            "| Severity | Rule | Location | Message | Fix |",
            "|---|---|---|---|---|",
        ]
    )
    for f in findings:
        location = f"`{_cell(_posix(f.file))}:{f.line}`"
        lines.append(
            f"| {f.severity.value} | {f.rule_id} | {location} "
            f"| {_cell(f.message)} | {_cell(f.fix_hint)} |"
        )
    return "\n".join(lines)


def _tool_version() -> str:
    try:
        return version("looseend")
    except PackageNotFoundError:
        return "0.0.0"


def _sarif_result(finding: Finding, rule_index: int) -> dict:
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _SARIF_LEVEL[finding.severity.value],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _posix(finding.file)},
                    "region": {"startLine": max(1, finding.line)},
                }
            }
        ],
        "partialFingerprints": {"looseendFindingId/v1": finding.id},
        "properties": {
            "category": finding.category.value,
            "confidence": finding.confidence.value,
            "fixHint": finding.fix_hint,
        },
    }


def render_sarif(result: ScanResult) -> str:
    findings = result.sorted_findings()
    rule_ids = sorted({f.rule_id for f in findings})
    index = {rule_id: i for i, rule_id in enumerate(rule_ids)}
    rules = [
        {"id": rule_id, "shortDescription": {"text": RULE_TITLES.get(rule_id, rule_id)}}
        for rule_id in rule_ids
    ]
    document = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LooseEnd",
                        "version": _tool_version(),
                        "informationUri": _INFO_URI,
                        "rules": rules,
                    }
                },
                "results": [_sarif_result(f, index[f.rule_id]) for f in findings],
            }
        ],
    }
    return json.dumps(document, indent=2)


def render(fmt: str, result: ScanResult, color: bool = False) -> str:
    if fmt == "text":
        return render_text(result, color)
    if fmt == "json":
        return render_json(result)
    if fmt == "markdown":
        return render_markdown(result)
    if fmt == "sarif":
        return render_sarif(result)
    raise ValueError(f"unknown format: {fmt}")
