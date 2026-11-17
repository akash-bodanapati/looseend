"""Data models for LooseEnd findings."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Category(str, Enum):
    SECURITY = "security"
    SLOP = "slop"
    GAP = "gap"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: Category
    severity: Severity
    confidence: Confidence
    file: str
    line: int
    message: str
    evidence: str
    fix_hint: str
    id: str = field(init=False)

    def __post_init__(self) -> None:
        raw = f"{self.rule_id}:{self.file}:{self.line}:{self.evidence[:100]}"
        digest = hashlib.sha256(raw.encode()).hexdigest()[:12]
        object.__setattr__(self, "id", digest)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "file": self.file,
            "line": self.line,
            "message": self.message,
            "evidence": self.evidence,
            "fix_hint": self.fix_hint,
        }


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors: list[str] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (f.file, f.line, f.rule_id),
        )

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
