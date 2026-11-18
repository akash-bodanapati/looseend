"""Scan runner."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from looseend.engine.analyzer import Analyzer, parse_inline_ignores, should_ignore
from looseend.engine.walker import walk_files
from looseend.models import Category, ScanResult, Severity

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def run_scan(
    root: Path,
    analyzers: list[Analyzer],
    min_severity: Optional[Severity] = None,
    categories: Optional[list[Category]] = None,
) -> ScanResult:
    root = root.resolve()
    result = ScanResult(root=str(root))
    min_idx = _SEV_ORDER.get(min_severity.value, 4) if min_severity else 4

    rel_base = root if root.is_dir() else root.parent
    file_ignores: dict[str, dict[int, set[str]]] = {}
    for file_path, language in walk_files(root):
        rel_path = str(file_path.relative_to(rel_base))
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            result.errors.append(f"{rel_path}: {e}")
            result.files_skipped += 1
            continue

        ignores = parse_inline_ignores(source)
        file_ignores[rel_path] = ignores
        result.files_scanned += 1

        for analyzer in analyzers:
            if categories and analyzer.category not in categories:
                continue
            try:
                for finding in analyzer.analyze(file_path, source, language, rel_path):
                    if should_ignore(finding.line, finding.rule_id, ignores):
                        continue
                    if _SEV_ORDER.get(finding.severity.value, 4) > min_idx:
                        continue
                    result.findings.append(finding)
            except Exception as e:
                result.errors.append(
                    f"{rel_path} [{analyzer.__class__.__name__}]: {e}"
                )

    for analyzer in analyzers:
        if categories and analyzer.category not in categories:
            continue
        if hasattr(analyzer, "finalize"):
            try:
                for finding in analyzer.finalize():
                    if should_ignore(
                        finding.line,
                        finding.rule_id,
                        file_ignores.get(finding.file, {}),
                    ):
                        continue
                    if _SEV_ORDER.get(finding.severity.value, 4) > min_idx:
                        continue
                    result.findings.append(finding)
            except Exception as e:
                result.errors.append(
                    f"[{analyzer.__class__.__name__} finalize]: {e}"
                )

    return result