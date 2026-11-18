"""Gap analyzer: TODO/FIXME, bare except, swallowed errors, long functions, missing tests/files."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterator

from looseend.analyzers._toml import load_pyproject
from looseend.engine.analyzer import Analyzer
from looseend.models import Category, Confidence, Finding, Severity


_TODO_RE = re.compile(r"(?i)\b(TODO|FIXME|HACK|XXX|BUG|WORKAROUND)\b")
_BARE_EXCEPT_RE = re.compile(r"^\s*except\s*:")
_EXCEPT_RE = re.compile(r"^\s*except\b")

# Function/method start patterns per language
_FUNC_START: dict[str, re.Pattern] = {
    "python": re.compile(r"^\s*(async\s+)?def\s+\w+"),
    "javascript": re.compile(r"(?:function\s+\w+|=>\s*\{|\w+\s*\(.*\)\s*\{)"),
    "typescript": re.compile(r"(?:function\s+\w+|=>\s*\{|\w+\s*\(.*\)\s*\{)"),
    "java": re.compile(r"^\s+(?:public|private|protected|static|final|\w+)\s+\w+\s+\w+\s*\("),
    "go": re.compile(r"^func\s+"),
}


def _has_runtime_deps(root: Path) -> bool:
    """Check if project explicitly declares runtime production dependencies."""
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        data = load_pyproject(root)
        if data is not None:
            if data.get("project", {}).get("dependencies"):
                return True
            poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            if any(k.lower() != "python" for k in poetry_deps):
                return True
        else:  # Python 3.10 (no tomllib) or unparseable file
            try:
                content = pyproject.read_text(encoding="utf-8", errors="replace")
            except OSError:
                content = ""
            if re.search(r"^\s*dependencies\s*=\s*\[[^\]]+\]", content, re.MULTILINE):
                return True

    pkg_json = root / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
            if data.get("dependencies"):
                return True
        except Exception:
            pass

    go_mod = root / "go.mod"
    if go_mod.exists():
        try:
            for line in go_mod.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if stripped.startswith("require ") and not stripped.endswith("("):
                    return True
                if stripped and not stripped.startswith(("//", "module ", "go ", "require (", ")")) and " " in stripped:
                    return True
        except OSError:
            pass

    pom_xml = root / "pom.xml"
    if pom_xml.exists():
        try:
            content = pom_xml.read_text(encoding="utf-8", errors="replace")
            if "<dependency>" in content:
                return True
        except OSError:
            pass

    cargo_toml = root / "Cargo.toml"
    if cargo_toml.exists():
        try:
            content = cargo_toml.read_text(encoding="utf-8", errors="replace")
            if "[dependencies]" in content:
                return True
        except OSError:
            pass

    gemfile = root / "Gemfile"
    if gemfile.exists():
        try:
            for line in gemfile.read_text(encoding="utf-8", errors="replace").splitlines():
                if re.match(r'^\s*gem\s+["\']', line):
                    return True
        except OSError:
            pass

    return False


class GapAnalyzer(Analyzer):
    category = Category.GAP

    def __init__(self, root: Path | None = None) -> None:
        self._is_single_file = root is not None and root.is_file()
        self._root = root.parent if (root is not None and root.is_file()) else root
        self._hygiene_done = False

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
            category=Category.GAP,
            severity=severity,
            confidence=confidence,
            file=rel_path,
            line=line,
            message=message,
            evidence=evidence,
            fix_hint=fix_hint,
        )

    def analyze(
        self,
        path: Path,
        source: str,
        language: str,
        rel_path: str,
    ) -> Iterator[Finding]:
        if self._root is None:
            self._root = path.parent
        elif self._root.is_file():
            self._root = self._root.parent

        yield from self._gap001(source, rel_path)
        if language == "python":
            yield from self._gap002(source, rel_path)
            yield from self._gap003_python(source, rel_path)
        elif language in ("javascript", "typescript"):
            yield from self._gap003_js(source, rel_path)
        yield from self._gap004(source, language, rel_path)
        if language == "python":
            yield from self._gap005(path, rel_path)
        if not self._hygiene_done and not self._is_single_file:
            yield from self._gap006(rel_path)
            self._hygiene_done = True

    def _gap001(self, source: str, rel_path: str) -> Iterator[Finding]:
        for lineno, line in enumerate(source.splitlines(), 1):
            m = _TODO_RE.search(line)
            if m:
                yield self._make(
                    "GAP001", Severity.INFO, Confidence.HIGH,
                    rel_path, lineno,
                    f"{m.group(1)} comment — unfinished work",
                    line.strip()[:100],
                    "Resolve or create a tracked issue",
                )

    def _gap002(self, source: str, rel_path: str) -> Iterator[Finding]:
        for lineno, line in enumerate(source.splitlines(), 1):
            if _BARE_EXCEPT_RE.match(line):
                yield self._make(
                    "GAP002", Severity.MEDIUM, Confidence.HIGH,
                    rel_path, lineno,
                    "Bare except: catches all exceptions including KeyboardInterrupt",
                    line.strip(),
                    "Catch specific exceptions: except ValueError: or except Exception:",
                )

    def _gap003_python(self, source: str, rel_path: str) -> Iterator[Finding]:
        """Flag except blocks whose only body is pass."""
        lines = source.splitlines()
        i = 0
        while i < len(lines):
            if _EXCEPT_RE.match(lines[i]):
                # Gather body lines
                j = i + 1
                body_lines = []
                while j < len(lines):
                    stripped = lines[j].strip()
                    if stripped == "":
                        j += 1
                        continue
                    # Check indentation — if less or equal to except, body is done
                    if stripped and len(lines[j]) - len(lines[j].lstrip()) <= len(lines[i]) - len(lines[i].lstrip()):
                        break
                    body_lines.append(stripped)
                    j += 1
                if body_lines and all(b == "pass" for b in body_lines):
                    yield self._make(
                        "GAP003", Severity.MEDIUM, Confidence.HIGH,
                        rel_path, i + 1,
                        "Swallowed exception: except block only contains pass",
                        lines[i].strip(),
                        "Log the error, re-raise, or handle it explicitly",
                    )
            i += 1

    def _gap003_js(self, source: str, rel_path: str) -> Iterator[Finding]:
        """Flag empty catch blocks in JS/TS."""
        catch_re = re.compile(r"\bcatch\s*\([^)]*\)\s*\{\s*\}", re.DOTALL)
        for m in catch_re.finditer(source):
            lineno = source[:m.start()].count("\n") + 1
            yield self._make(
                "GAP003", Severity.MEDIUM, Confidence.HIGH,
                rel_path, lineno,
                "Empty catch block swallows exceptions silently",
                m.group(0)[:60],
                "Log or handle the error; don't silently swallow it",
            )

    def _gap004(self, source: str, language: str, rel_path: str) -> Iterator[Finding]:
        """Flag functions longer than 100 lines."""
        pat = _FUNC_START.get(language)
        if not pat:
            return
        lines = source.splitlines()
        func_start: int | None = None
        func_name = ""

        for lineno, line in enumerate(lines, 1):
            m = pat.match(line)
            if m:
                if func_start is not None:
                    length = lineno - func_start
                    if length > 100:
                        yield self._make(
                            "GAP004", Severity.LOW, Confidence.HIGH,
                            rel_path, func_start,
                            f"Function '{func_name}' is {length} lines long (threshold: 100)",
                            func_name,
                            "Break into smaller functions",
                        )
                func_start = lineno
                func_name = m.group(0).strip()[:40]

        # Check last function
        if func_start is not None:
            length = len(lines) - func_start + 1
            if length > 100:
                yield self._make(
                    "GAP004", Severity.LOW, Confidence.HIGH,
                    rel_path, func_start,
                    f"Function '{func_name}' is {length} lines long (threshold: 100)",
                    func_name,
                    "Break into smaller functions",
                )

    def _gap005(self, path: Path, rel_path: str) -> Iterator[Finding]:
        """Flag Python src files without corresponding test files."""
        # Only check files in src/
        if "src" not in rel_path.replace("\\", "/").split("/"):
            return
        # Skip __init__, conftest, test_ files
        name = path.stem
        if name.startswith(("test_", "__", "conftest")):
            return
        # Look for test file
        root = self._root
        if root is None:
            return
        test_patterns = [
            root / "tests" / f"test_{name}.py",
            root / "test" / f"test_{name}.py",
            root / f"test_{name}.py",
        ]
        if not any(p.exists() for p in test_patterns):
            yield self._make(
                "GAP005", Severity.LOW, Confidence.LOW,
                rel_path, 1,
                f"No test file found for '{name}.py'",
                rel_path,
                f"Create tests/test_{name}.py",
            )

    def _gap006(self, rel_path: str) -> Iterator[Finding]:
        """Check root for required repo hygiene files."""
        root = self._root
        if root is None:
            return

        # README
        readme_names = ["README.md", "README.rst", "README.txt", "README"]
        if not any((root / n).exists() for n in readme_names):
            yield self._make(
                "GAP006", Severity.MEDIUM, Confidence.HIGH,
                rel_path, 1,
                "Missing README file",
                "README.md",
                "Create a README.md describing the project",
            )

        # LICENSE
        license_names = ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"]
        if not any((root / n).exists() for n in license_names):
            yield self._make(
                "GAP006", Severity.MEDIUM, Confidence.HIGH,
                rel_path, 1,
                "Missing LICENSE file",
                "LICENSE",
                "Add a LICENSE file (MIT, Apache 2.0, etc.)",
            )

        # .gitignore
        if not (root / ".gitignore").exists():
            yield self._make(
                "GAP006", Severity.LOW, Confidence.HIGH,
                rel_path, 1,
                "Missing .gitignore file",
                ".gitignore",
                "Create a .gitignore to exclude build artifacts and secrets",
            )

        # CI config
        ci_paths = [
            root / ".github" / "workflows",
            root / ".travis.yml",
            root / ".circleci" / "config.yml",
            root / "Jenkinsfile",
            root / "Makefile",
            root / ".gitlab-ci.yml",
        ]
        has_ci = False
        for ci in ci_paths:
            if ci.exists():
                if ci.is_dir():
                    try:
                        if any(ci.iterdir()):
                            has_ci = True
                            break
                    except OSError:
                        pass
                else:
                    has_ci = True
                    break
        if not has_ci:
            yield self._make(
                "GAP006", Severity.LOW, Confidence.HIGH,
                rel_path, 1,
                "Missing CI configuration",
                ".github/workflows/",
                "Add a CI workflow (GitHub Actions, Travis CI, CircleCI, etc.)",
            )

        # Lockfile: only flag if the project declares runtime dependencies
        if _has_runtime_deps(root):
            lockfiles = [
                "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                "poetry.lock", "Pipfile.lock", "go.sum",
                "Cargo.lock", "Gemfile.lock",
            ]
            if not any((root / lf).exists() for lf in lockfiles):
                yield self._make(
                    "GAP006", Severity.LOW, Confidence.MEDIUM,
                    rel_path, 1,
                    "No dependency lockfile found for project with declared runtime dependencies",
                    "lockfile",
                    "Add a lockfile (poetry.lock, package-lock.json, Cargo.lock, etc.)",
                )