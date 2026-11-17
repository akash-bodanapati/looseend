"""LooseEnd CLI entry point."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from looseend.analyzers.gap import GapAnalyzer
from looseend.analyzers.security import SecurityAnalyzer
from looseend.analyzers.slop import SlopAnalyzer
from looseend.engine.runner import run_scan
from looseend.models import Category, Severity

_COLORS = {
    "critical": "\033[91m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _c(text: str, severity: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{_COLORS.get(severity, '')}{text}{_RESET}"


def _format_text(result) -> str:
    out: list[str] = []
    findings = result.sorted_findings()
    if not findings:
        out.append("✓ No findings. Clean codebase!")
    for f in findings:
        sev = _c(f.severity.value.upper(), f.severity.value)
        out.append(f"\n{_BOLD}[{f.rule_id}]{_RESET} {sev} — {f.file}:{f.line}")
        out.append(f"  {f.message}")
        if f.evidence:
            out.append(f"  evidence: {f.evidence[:120]}")
        if f.fix_hint:
            out.append(f"  fix: {f.fix_hint}")
    out.append(
        f"\n── {result.files_scanned} files scanned · "
        f"{len(result.findings)} findings · "
        f"{result.files_skipped} skipped ──"
    )
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="looseend",
        description="Scan a codebase for security issues, AI slop, and coding gaps.",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan a directory or file")
    scan_p.add_argument("path", nargs="?", default=".", help="Path to scan")
    scan_p.add_argument("--format", choices=["text", "json"], default="text")
    scan_p.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
    )
    scan_p.add_argument(
        "--category",
        choices=["security", "slop", "gap"],
        action="append",
        dest="categories",
    )

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(0)

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"error: path does not exist: {root}", file=sys.stderr)
        sys.exit(1)

    min_severity = Severity(args.severity)
    categories = [Category(c) for c in args.categories] if args.categories else None

    analyzers: list = [SecurityAnalyzer(), SlopAnalyzer(), GapAnalyzer(root=root)]
    result = run_scan(root, analyzers, min_severity=min_severity, categories=categories)

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(_format_text(result))

    sys.exit(0 if not result.findings else 1)


if __name__ == "__main__":
    main()
