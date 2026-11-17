"""Slop analyzer: placeholder stubs, hallucinated imports, duplicate blocks, debug prints."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Iterator

from looseend.engine.analyzer import Analyzer
from looseend.models import Category, Confidence, Finding, Severity


_PLACEHOLDER_RE = re.compile(
    r"(?i)(lorem\s+ipsum|placeholder\s+text|dummy\s+(?:data|content|value)|"
    r"TODO:\s*implement|FIXME:\s*implement|stub\s+method|not\s+implemented)",
    re.IGNORECASE,
)

_COMMENT_MARKERS = {
    "python": "#",
    "ruby": "#",
    "shell": "#",
    "javascript": "//",
    "typescript": "//",
    "java": "//",
    "go": "//",
    "cpp": "//",
    "csharp": "//",
    "rust": "//",
    "php": "//",
    "c": "//",
}

_CODE_SIGNALS = re.compile(
    r"[=({;]|def\s+|function\s+|var\s+|let\s+|const\s+|import\s+|return\s+|class\s+"
)

_DEBUG_TEST_PATHS = re.compile(r"test|spec|__tests__", re.IGNORECASE)
_DEBUG_CLI_PATHS = re.compile(r"cli|cmd|command|__main__", re.IGNORECASE)


def _is_test_or_cli(rel_path: str) -> bool:
    return bool(_DEBUG_TEST_PATHS.search(rel_path) or _DEBUG_CLI_PATHS.search(rel_path))


def _get_declared_deps(root: Path) -> set[str]:
    """Read declared deps from requirements.txt and pyproject.toml."""
    deps: set[str] = set()
    req = root / "requirements.txt"
    if req.exists():
        try:
            for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith(("#", "-")):
                    pkg = re.split(r"[>=<!@;#\s\[]", line)[0].lower().replace("-", "_")
                    deps.add(pkg)
        except OSError:
            pass

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            try:
                import tomllib  # type: ignore
            except ImportError:
                tomllib = None  # type: ignore
            if tomllib is not None:
                with open(pyproject, "rb") as f:
                    data = tomllib.load(f)
                project_deps = data.get("project", {}).get("dependencies", [])
                for dep in project_deps:
                    pkg = re.split(r"[>=<!@;#\s\[]", dep)[0].lower().replace("-", "_")
                    deps.add(pkg)
        except Exception:
            pass

    return deps


class SlopAnalyzer(Analyzer):
    category = Category.SLOP

    def __init__(self) -> None:
        # For SLOP003 duplicate detection: hash -> list of (file, line)
        self._block_hashes: dict[str, list[tuple[str, int]]] = {}
        self._root: Path | None = None

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
            category=Category.SLOP,
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
        yield from self._slop001(source, language, rel_path)
        if language == "python":
            yield from self._slop002(path, source, rel_path)
        elif language in ("javascript", "typescript"):
            yield from self._slop002_js(path, source, rel_path)
        self._slop003_collect(source, rel_path)
        yield from self._slop004(source, language, rel_path)
        yield from self._slop005(source, language, rel_path)

    def finalize(self) -> Iterator[Finding]:
        """Yield SLOP003 duplicate block findings."""
        for block_hash, locations in self._block_hashes.items():
            if len(locations) >= 2:
                for file_path, lineno in locations:
                    yield self._make(
                        "SLOP003", Severity.LOW, Confidence.MEDIUM,
                        file_path, lineno,
                        f"Duplicate code block (appears in {len(locations)} locations)",
                        f"Hash {block_hash[:8]}",
                        "Extract duplicate block into a shared function or module",
                    )

    def _slop001(self, source: str, language: str, rel_path: str) -> Iterator[Finding]:
        lines = source.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped in ("pass", "..."):
                # Check if preceded by def/class within 3 lines
                for j in range(max(0, i - 3), i):
                    if re.match(r"\s*(def |class |async def )", lines[j]):
                        yield self._make(
                            "SLOP001", Severity.MEDIUM, Confidence.HIGH,
                            rel_path, i + 1,
                            "Placeholder stub: function/class body is only pass or ...",
                            stripped,
                            "Implement the function body or remove the stub",
                        )
                        break

            if re.search(r"\braise\s+NotImplementedError\b", line):
                yield self._make(
                    "SLOP001", Severity.LOW, Confidence.MEDIUM,
                    rel_path, i + 1,
                    "Unimplemented method raises NotImplementedError",
                    stripped[:80],
                    "Implement the method",
                )

            if _PLACEHOLDER_RE.search(line):
                yield self._make(
                    "SLOP001", Severity.MEDIUM, Confidence.HIGH,
                    rel_path, i + 1,
                    "Placeholder/fake content detected",
                    stripped[:80],
                    "Replace with real content",
                )

    def _slop002(self, path: Path, source: str, rel_path: str) -> Iterator[Finding]:
        """Detect imports that aren't in stdlib or declared deps."""
        stdlib = getattr(sys, "stdlib_module_names", set())
        # Find project root by walking up from file
        root = path.parent
        while root.parent != root:
            if (root / "pyproject.toml").exists() or (root / "setup.py").exists() or (root / "requirements.txt").exists():
                break
            root = root.parent
        declared = _get_declared_deps(root)

        # Collect local package names (sibling dirs/files with __init__.py or .py)
        local_mods: set[str] = set()
        try:
            for entry in root.iterdir():
                if entry.is_dir() and (entry / "__init__.py").exists():
                    local_mods.add(entry.name.lower())
                elif entry.is_file() and entry.suffix == ".py":
                    local_mods.add(entry.stem.lower())
            # Also add src/ subdirs
            src = root / "src"
            if src.is_dir():
                for entry in src.iterdir():
                    if entry.is_dir() and (entry / "__init__.py").exists():
                        local_mods.add(entry.name.lower())
        except OSError:
            pass

        import_re = re.compile(r"^(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)")
        for lineno, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = import_re.match(stripped)
            if not m:
                continue
            top_module = m.group(1).lower()
            if top_module.startswith("_"):
                continue
            if top_module in stdlib:
                continue
            normalized = top_module.replace("-", "_")
            if normalized in declared or top_module in declared:
                continue
            if normalized in local_mods or top_module in local_mods:
                continue
            yield self._make(
                "SLOP002", Severity.LOW, Confidence.LOW,
                rel_path, lineno,
                f"Import '{m.group(1)}' not found in stdlib or declared dependencies",
                line.strip()[:80],
                "Add to requirements.txt/pyproject.toml or verify the import",
            )

    def _slop002_js(self, path: Path, source: str, rel_path: str) -> Iterator[Finding]:
        """Detect JS/TS imports not found in package.json or node builtins."""
        root = path.parent
        while root.parent != root:
            if (root / "package.json").exists():
                break
            root = root.parent
        pkg_json = root / "package.json"
        if not pkg_json.exists():
            return
        declared: set[str] = set()
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
            for sec in ("dependencies", "devDependencies", "peerDependencies"):
                deps = data.get(sec, {})
                if isinstance(deps, dict):
                    declared.update(deps.keys())
        except Exception:
            return

        node_builtins = {
            "assert", "async_hooks", "buffer", "child_process", "cluster",
            "console", "constants", "crypto", "dgram", "diagnostics_channel",
            "dns", "domain", "events", "fs", "fs/promises", "http", "http2",
            "https", "inspector", "module", "net", "os", "path", "perf_hooks",
            "process", "punycode", "querystring", "readline", "repl", "stream",
            "string_decoder", "timers", "tls", "trace_events", "tty", "url",
            "util", "v8", "vm", "wasi", "worker_threads", "zlib",
        }

        import_re = re.compile(
            r"""(?:import\s+.*?\s+from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\))"""
        )
        for lineno, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue
            for m in import_re.finditer(line):
                spec = m.group(1) or m.group(2)
                if not spec or spec.startswith(".") or spec.startswith("/"):
                    continue
                if spec.startswith("node:"):
                    continue
                parts = spec.split("/")
                pkg_name = f"{parts[0]}/{parts[1]}" if spec.startswith("@") and len(parts) >= 2 else parts[0]
                if pkg_name in node_builtins:
                    continue
                if pkg_name not in declared:
                    yield self._make(
                        "SLOP002", Severity.LOW, Confidence.LOW,
                        rel_path, lineno,
                        f"Import '{pkg_name}' not found in package.json",
                        stripped[:80],
                        "Add to package.json dependencies or verify the import",
                    )

    def _slop003_collect(self, source: str, rel_path: str) -> None:
        """Collect 6-line block hashes for duplicate detection."""
        lines = [re.sub(r"\s+", " ", l).strip().lower() for l in source.splitlines()]
        lines = [l for l in lines if l]  # remove blank
        window = 6
        if len(lines) < window:
            return
        for i in range(len(lines) - window + 1):
            block = "\n".join(lines[i:i + window])
            h = hashlib.md5(block.encode()).hexdigest()
            if h not in self._block_hashes:
                self._block_hashes[h] = []
            # Only add if not already from this file at this line
            existing_files = {loc[0] for loc in self._block_hashes[h]}
            if rel_path not in existing_files:
                self._block_hashes[h].append((rel_path, i + 1))

    def _slop004(self, source: str, language: str, rel_path: str) -> Iterator[Finding]:
        """Flag runs of 3+ consecutive commented-out code lines."""
        marker = _COMMENT_MARKERS.get(language)
        if not marker:
            return
        lines = source.splitlines()
        run_lines: list[int] = []

        def _flush() -> Iterator[Finding]:
            if len(run_lines) >= 3:
                yield self._make(
                    "SLOP004", Severity.INFO, Confidence.LOW,
                    rel_path, run_lines[0],
                    f"Commented-out code block ({len(run_lines)} lines)",
                    lines[run_lines[0] - 1].strip()[:80],
                    "Remove commented-out code; use version control to track old code",
                )
            run_lines.clear()

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(marker):
                content = stripped[len(marker):].strip()
                if content and _CODE_SIGNALS.search(content):
                    run_lines.append(lineno)
                    continue
            # Not a commented code line — flush and reset
            if run_lines:
                yield from _flush()

        if run_lines:
            yield from _flush()

    def _slop005(self, source: str, language: str, rel_path: str) -> Iterator[Finding]:
        """Flag debug prints outside test/CLI files."""
        is_exempt = _is_test_or_cli(rel_path)
        lines = source.splitlines()

        if language == "python":
            print_re = re.compile(r"\bprint\s*\(")
            pdb_re = re.compile(r"\b(?:pdb\.set_trace|breakpoint)\s*\(\s*\)")
            for lineno, line in enumerate(lines, 1):
                if pdb_re.search(line):
                    yield self._make(
                        "SLOP005", Severity.MEDIUM, Confidence.HIGH,
                        rel_path, lineno,
                        "Debugger breakpoint left in code",
                        line.strip()[:80],
                        "Remove breakpoint before committing",
                    )
                elif not is_exempt and print_re.search(line):
                    yield self._make(
                        "SLOP005", Severity.INFO, Confidence.MEDIUM,
                        rel_path, lineno,
                        "Debug print() outside test/CLI",
                        line.strip()[:80],
                        "Replace with logger.debug() or remove",
                    )

        elif language in ("javascript", "typescript"):
            console_re = re.compile(r"\bconsole\.(log|debug|warn|error)\s*\(")
            if not is_exempt:
                for lineno, line in enumerate(lines, 1):
                    if console_re.search(line):
                        yield self._make(
                            "SLOP005", Severity.INFO, Confidence.MEDIUM,
                            rel_path, lineno,
                            "console.log/debug/warn/error outside test file",
                            line.strip()[:80],
                            "Remove or replace with a proper logger",
                        )

        elif language == "java":
            if not is_exempt:
                sysout_re = re.compile(r"\bSystem\.out\.print")
                for lineno, line in enumerate(lines, 1):
                    if sysout_re.search(line):
                        yield self._make(
                            "SLOP005", Severity.INFO, Confidence.MEDIUM,
                            rel_path, lineno,
                            "System.out.print outside test file",
                            line.strip()[:80],
                            "Use a logger (SLF4J, Log4j, etc.)",
                        )

        elif language == "go":
            if not is_exempt and "main" not in rel_path:
                fmt_re = re.compile(r"\bfmt\.Print")
                for lineno, line in enumerate(lines, 1):
                    if fmt_re.search(line):
                        yield self._make(
                            "SLOP005", Severity.INFO, Confidence.LOW,
                            rel_path, lineno,
                            "fmt.Print outside test/main",
                            line.strip()[:80],
                            "Use log package instead",
                        )
