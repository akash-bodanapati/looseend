"""LooseEnd command-line interface."""
from __future__ import annotations

import argparse
import contextlib
import os
import sys
from pathlib import Path
from typing import Sequence

from looseend.analyzers.gap import GapAnalyzer
from looseend.analyzers.security import SecurityAnalyzer
from looseend.analyzers.slop import SlopAnalyzer
from looseend.baseline import apply_baseline, load_baseline
from looseend.engine.analyzer import Analyzer
from looseend.engine.runner import run_scan
from looseend.models import Category, ScanResult, Severity
from looseend.reporters import FORMATS, SEVERITY_ORDER, render

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_analyzers(root: Path) -> list[Analyzer]:
    """The default analyzer set, shared by the CLI and the benchmark."""
    return [SecurityAnalyzer(), SlopAnalyzer(), GapAnalyzer(root=root)]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="looseend",
        description="Scan a codebase for security issues, AI slop, and coding gaps.",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a directory or file")
    scan.add_argument("path", nargs="?", default=".", help="Path to scan (default: .)")
    scan.add_argument("--format", choices=FORMATS, default="text", help="Report format")
    scan.add_argument(
        "--min-severity",
        "--severity",
        dest="min_severity",
        choices=SEVERITY_ORDER,
        default="info",
        help="Hide findings below this severity",
    )
    scan.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER + ("none",),
        default="info",
        help="Exit 1 if any finding is at or above this severity (default: info)",
    )
    scan.add_argument(
        "--category",
        choices=[c.value for c in Category],
        action="append",
        dest="categories",
        help="Only run this category (repeatable)",
    )
    scan.add_argument("--baseline", help="JSON report or ID list; its findings are hidden")
    scan.add_argument("--output", help="Write the report to this file instead of stdout")
    scan.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    return parser


def _fails(result: ScanResult, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = SEVERITY_ORDER.index(fail_on)
    return any(SEVERITY_ORDER.index(f.severity.value) <= threshold for f in result.findings)


def _use_color(args: argparse.Namespace) -> bool:
    if args.no_color or args.output or "NO_COLOR" in os.environ:
        return False
    return sys.stdout.isatty()


def _force_utf8() -> None:
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None and (sys.stdout.encoding or "").lower() != "utf-8":
        with contextlib.suppress(ValueError, OSError):
            reconfigure(encoding="utf-8")


def _error(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return EXIT_USAGE


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_CLEAN
    if args.command is None:
        parser.print_help()
        return EXIT_CLEAN

    _force_utf8()
    root = Path(args.path).resolve()
    if not root.exists():
        return _error(f"path does not exist: {root}")

    known: set[str] = set()
    if args.baseline:
        try:
            known = load_baseline(Path(args.baseline))
        except (OSError, ValueError) as exc:
            return _error(f"cannot read baseline: {exc}")

    categories = [Category(c) for c in args.categories] if args.categories else None
    result = run_scan(
        root,
        build_analyzers(root),
        min_severity=Severity(args.min_severity),
        categories=categories,
    )
    if known:
        result, suppressed = apply_baseline(result, known)
        print(f"{suppressed} baseline findings hidden", file=sys.stderr)

    report = render(args.format, result, color=_use_color(args))
    if args.output:
        try:
            Path(args.output).write_text(report + "\n", encoding="utf-8")
        except OSError as exc:
            return _error(f"cannot write report: {exc}")
        print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(report)

    return EXIT_FINDINGS if _fails(result, args.fail_on) else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
