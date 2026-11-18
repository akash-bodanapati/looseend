"""Benchmark: scan the seeded apps and compare against their inline expectations."""
from __future__ import annotations

import re
from pathlib import Path

from looseend.cli import build_analyzers
from looseend.engine.runner import run_scan

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
VULNERABLE = EXAMPLES / "vulnerable-app"
CLEAN = EXAMPLES / "clean-app"

MIN_RECALL = 0.80
MIN_EXPECTATIONS = 25

_MARKER_RE = re.compile(r"expect(-next)?:\s*([A-Z]+\d{3}(?:\s*,\s*[A-Z]+\d{3})*)")

Key = tuple[str, int, str]


def load_expected(root: Path) -> set[Key]:
    """Read `expect:` / `expect-next:` markers into (file, line, rule_id) triples."""
    expected: set[Key] = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        name = path.relative_to(root).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            match = _MARKER_RE.search(line)
            if not match:
                continue
            target = lineno + 1 if match.group(1) else lineno
            for rule_id in re.split(r"\s*,\s*", match.group(2)):
                expected.add((name, target, rule_id))
    return expected


def scan_keys(root: Path) -> set[Key]:
    result = run_scan(root, build_analyzers(root))
    return {(f.file.replace("\\", "/"), f.line, f.rule_id) for f in result.findings}


def score(expected: set[Key], found: set[Key]) -> tuple[float, float]:
    hits = expected & found
    recall = len(hits) / len(expected) if expected else 0.0
    precision = len(hits) / len(found) if found else 0.0
    return precision, recall


def test_seeded_app_has_enough_expectations():
    assert len(load_expected(VULNERABLE)) >= MIN_EXPECTATIONS


def test_benchmark_precision_and_recall():
    expected = load_expected(VULNERABLE)
    found = scan_keys(VULNERABLE)
    precision, recall = score(expected, found)
    print(f"\nexpected={len(expected)} found={len(found)} "
          f"precision={precision:.2f} recall={recall:.2f}")
    for key in sorted(expected - found):
        print("  MISSED    ", key)
    for key in sorted(found - expected):
        print("  UNEXPECTED", key)
    assert recall >= MIN_RECALL, f"recall {recall:.2f} is below {MIN_RECALL}"


def test_clean_app_yields_zero_findings():
    result = run_scan(CLEAN, build_analyzers(CLEAN))
    assert [f.to_dict() for f in result.findings] == []


def test_score_handles_empty_sets():
    assert score(set(), set()) == (0.0, 0.0)
    assert score({("a", 1, "X1")}, {("a", 1, "X1")}) == (1.0, 1.0)
