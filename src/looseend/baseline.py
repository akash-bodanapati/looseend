"""Baseline support: hide findings that are already known."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from looseend.models import ScanResult


def load_baseline(path: Path) -> set[str]:
    """Read finding IDs from a LooseEnd JSON report or a plain JSON list of IDs."""
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("findings", []) if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise ValueError("baseline must be a LooseEnd JSON report or a list of finding IDs")
    ids: set[str] = set()
    for entry in entries:
        if isinstance(entry, str):
            ids.add(entry)
        elif isinstance(entry, dict) and isinstance(entry.get("id"), str):
            ids.add(entry["id"])
    return ids


def apply_baseline(result: ScanResult, known: set[str]) -> tuple[ScanResult, int]:
    """Return the result without known findings, and how many were suppressed."""
    kept = [f for f in result.findings if f.id not in known]
    return replace(result, findings=kept), len(result.findings) - len(kept)
