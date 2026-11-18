"""Analyzer plugin interface."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from looseend.models import Category, Confidence, Finding, Severity

_INLINE_IGNORE_RE = re.compile(r"looseend:\s*ignore(?:\[([^\]]*)\])?")


def parse_inline_ignores(source: str) -> dict[int, set[str]]:
    """Return {line_no: {rule_ids}} from inline looseend: ignore[...] comments."""
    result: dict[int, set[str]] = {}
    for i, line in enumerate(source.splitlines(), 1):
        m = _INLINE_IGNORE_RE.search(line)
        if m:
            if m.group(1):
                rules = {r.strip() for r in m.group(1).split(",") if r.strip()}
            else:
                rules = {"*"}
            result[i] = rules
    return result


def should_ignore(line: int, rule_id: str, ignores: dict[int, set[str]]) -> bool:
    s = ignores.get(line, set())
    return "*" in s or rule_id in s


class Analyzer(ABC):
    category: Category
    def _make(
        self,
        rule_id: str,
        severity: Severity,
        confidence: Confidence,
        rel_path: str,
        line: int,
        message: str,
        evidence: str,
        fix_hint: str,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            category=self.category,
            severity=severity,
            confidence=confidence,
            file=rel_path,
            line=line,
            message=message,
            evidence=evidence,
            fix_hint=fix_hint,
        )

    @abstractmethod
    def analyze(
        self,
        path: Path,
        source: str,
        language: str,
        rel_path: str,
    ) -> Iterator[Finding]:
        ...
