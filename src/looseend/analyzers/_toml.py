"""Read declared runtime dependencies from pyproject.toml (Python 3.10+)."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    import tomllib  # novermin  (guarded: absent on Python 3.10)
except ModuleNotFoundError:
    tomllib = None  # type: ignore[assignment]

_ASSIGN_RE = re.compile(r"dependencies\s*=")
_QUOTED_RE = re.compile(r"""["']([^"']+)["']""")


def _fallback_deps(text: str) -> list[str]:
    """Line-based extraction of [project] dependencies when tomllib is missing."""
    in_project = False
    collecting = False
    chunks: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not collecting and line.startswith("["):
            in_project = line == "[project]"
            continue
        if in_project and not collecting and _ASSIGN_RE.match(line):
            collecting = True
            line = line.split("=", 1)[1].strip()
        if collecting:
            chunks.append(line)
            if "]" in line:
                break
    return _QUOTED_RE.findall(" ".join(chunks))


def load_pyproject(root: Path) -> dict[str, Any] | None:
    """Parsed pyproject.toml, or None if unreadable, invalid, or tomllib is missing."""
    if tomllib is None:
        return None
    try:
        text = (root / "pyproject.toml").read_text(encoding="utf-8", errors="replace")
        return tomllib.loads(text)  # novermin
    except (OSError, ValueError):  # TOMLDecodeError is a ValueError
        return None


def get_project_deps(root: Path) -> list[str]:
    """Return declared [project] dependencies, or [] if none or unreadable."""
    try:
        text = (root / "pyproject.toml").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if tomllib is None:
        return _fallback_deps(text)
    data = load_pyproject(root)
    if data is None:
        return []
    deps = data.get("project", {}).get("dependencies", [])
    return [d for d in deps if isinstance(d, str)]