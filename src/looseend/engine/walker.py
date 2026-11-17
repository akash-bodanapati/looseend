"""File system walker with .gitignore and .looseendignore support."""
from __future__ import annotations

import fnmatch
import os
import stat
from pathlib import Path
from typing import Generator, Optional


MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB

BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".flac",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".obj", ".o", ".a", ".lib",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".db", ".sqlite", ".sqlite3",
    ".wasm", ".class", ".pyc", ".pyo",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
})

LANGUAGE_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".java": "java",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".fish": "shell",
    ".ps1": "powershell",
    ".cs": "csharp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".c": "c",
    ".h": "c",
    ".hpp": "cpp",
    ".rs": "rust",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".xml": "xml",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "css",
    ".sql": "sql",
    ".md": "markdown",
    ".txt": "text",
    ".env": "env",
    ".conf": "conf",
    ".cfg": "conf",
    ".ini": "conf",
    ".tf": "terraform",
}

ALWAYS_IGNORE_DIRS = frozenset({
    ".git", ".hg", ".svn", "__pycache__", "node_modules",
    ".venv", "venv", "env", ".tox", "dist", "build", ".eggs",
})


def _load_ignore_patterns(path: Path) -> list[str]:
    patterns: list[str] = []
    if path.exists():
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
        except OSError:
            pass
    return patterns


def _matches_gitignore(rel_path: str, patterns: list[str]) -> bool:
    rel_posix = rel_path.replace("\\", "/")
    parts = rel_posix.split("/")
    name = parts[-1]
    for pattern in patterns:
        p = pattern.lstrip("/")
        if p.endswith("/"):
            p = p.rstrip("/")
            for part in parts[:-1]:
                if fnmatch.fnmatch(part, p):
                    return True
            if fnmatch.fnmatch(name, p):
                return True
        elif "/" in p:
            if fnmatch.fnmatch(rel_posix, p):
                return True
        else:
            if fnmatch.fnmatch(name, p):
                return True
            for part in parts:
                if fnmatch.fnmatch(part, p):
                    return True
    return False


def _is_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        chunk = path.read_bytes()[:8192]
        return b"\x00" in chunk
    except OSError:
        return True


def walk_files(
    root: Path,
    extra_patterns: Optional[list[str]] = None,
) -> Generator[tuple[Path, str], None, None]:
    """Yield (path, language) for each scannable text file under root."""
    root = root.resolve()
    if root.is_file():
        try:
            if root.stat().st_size > MAX_FILE_SIZE or _is_binary(root):
                return
        except OSError:
            return
        lang = LANGUAGE_MAP.get(root.suffix.lower(), "text")
        if root.name.startswith("Dockerfile"):
            lang = "dockerfile"
        elif root.name == ".env" or root.name.startswith(".env."):
            lang = "env"
        yield (root, lang)
        return

    patterns: list[str] = []
    patterns += _load_ignore_patterns(root / ".gitignore")
    patterns += _load_ignore_patterns(root / ".looseendignore")
    if extra_patterns:
        patterns += extra_patterns

    seen_inodes: set[tuple[int, int]] = set()

    def _walk(directory: Path) -> Generator[tuple[Path, str], None, None]:
        try:
            entries = sorted(directory.iterdir())
        except (PermissionError, OSError):
            return

        for entry in entries:
            try:
                lst = os.lstat(entry)
            except OSError:
                continue

            if stat.S_ISLNK(lst.st_mode):
                try:
                    real = entry.resolve()
                    rst = os.stat(real)
                    inode = (rst.st_dev, rst.st_ino)
                    if inode in seen_inodes:
                        continue
                    seen_inodes.add(inode)
                except OSError:
                    continue

            rel = str(entry.relative_to(root))

            if entry.is_dir():
                if entry.name in ALWAYS_IGNORE_DIRS:
                    continue
                if _matches_gitignore(rel, patterns):
                    continue
                yield from _walk(entry)
            elif entry.is_file():
                if _matches_gitignore(rel, patterns):
                    continue
                try:
                    if entry.stat().st_size > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                if _is_binary(entry):
                    continue
                lang = LANGUAGE_MAP.get(entry.suffix.lower(), "text")
                if entry.name.startswith("Dockerfile"):
                    lang = "dockerfile"
                elif entry.name == ".env" or entry.name.startswith(".env."):
                    lang = "env"
                yield (entry, lang)

    yield from _walk(root)
