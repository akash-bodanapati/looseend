"""Analyzer plugin interface."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from looseend.models import Category, Finding

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

    @abstractmethod
    def analyze(
        self,
        path: Path,
        source: str,
        language: str,
        rel_path: str,
    ) -> Iterator[Finding]:
        ...
