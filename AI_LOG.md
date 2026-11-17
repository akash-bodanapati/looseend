# AI_LOG.md — LooseEnd Build Log

This file is graded. Each entry records what was done, why, and what was rejected.

---

## Entry 1 — 2026-11-17T14:57 — Initial Implementation

**Prompt summary:** Build LooseEnd from scratch: scaffold, models, engine (file walker + analyzer interface), security/slop/gap analyzers covering 16 rules across Python/JS/Java/Go/PHP/Ruby/shell, tests with positive+negative cases per rule, clean fixture with zero findings. MIT license, git commits, public-repo-ready.

**What was done:**
- `git init` with minimal config
- `pyproject.toml` with `looseend` console script entry point
- `MIT LICENSE`, `.gitignore`, `README.md` stub, `AI_LOG.md`, `arena.json`
- `src/looseend/models.py`: `Finding` (frozen dataclass, stable 12-hex SHA-256 ID), `ScanResult`, `Category`/`Severity`/`Confidence` enums
- `src/looseend/engine/walker.py`: recursive walker honoring `.gitignore` and `.looseendignore`, binary detection by extension+null-byte scan, 1 MB size limit, symlink loop protection via inode tracking, `always_ignore` dirs
- `src/looseend/engine/analyzer.py`: abstract `Analyzer` base class, `parse_inline_ignores()`, `should_ignore()`
- `src/looseend/engine/runner.py`: `run_scan()` orchestrator with severity/category filtering, error collection, `finalize()` protocol
- `src/looseend/analyzers/security.py`: SEC001–SEC005
- `src/looseend/analyzers/slop.py`: SLOP001–SLOP005
- `src/looseend/analyzers/gap.py`: GAP001–GAP006
- `src/looseend/cli.py`: argparse CLI with text/JSON output, ANSI colors
- `tests/`: conftest.py, test_models.py, test_walker.py, test_security.py, test_slop.py, test_gap.py
- `examples/bad_python.py`, `examples/clean_python.py`

**Decisions:**
- Stable finding IDs: SHA-256 of `rule_id:file:line:evidence[:100]` → 12 hex chars
- Deterministic ordering: sort by (file, line, rule_id)
- Language detection by file extension only (no shebang — sufficient for MVP)
- Entropy threshold: 4.5 bits/char (Shannon), strings 20–200 chars; 1 finding/file max to reduce noise
- Duplicate block detection: 6-line sliding window, normalized hashing, two-pass via `finalize()`
- Allowlist for SEC001/SEC002: skip if line contains `example`, `test`, `dummy`, `fake`, `placeholder`, `your_`, `<`, `>`, `TODO`, `FIXME`
- SLOP002 (hallucinated imports): uses `sys.stdlib_module_names` (3.10+), reads requirements.txt/pyproject.toml
- GAP005 (missing tests): only checks Python files in `src/` with no corresponding `test_*.py`
- GAP006 (missing hygiene files): runs once per scan via instance state flag

**Rejected/corrected:**
- Rejected AST-based analysis (no deps, regex is sufficient for hackathon)
- Rejected shebang-based language detection (extension lookup is fast and sufficient)
- Rejected per-file entropy findings for all files (too noisy; restricted to config/secret file types)
- Rejected checking network-based dep vulnerabilities (offline requirement)
- `tomllib` is Python 3.11+ stdlib; for 3.10 compatibility, wrapped with try/except ImportError

**TODOs (arena.json fields unknown):**
- `track`: official hackathon track name
- `repo_url`: public repo URL after push
- `demo_url`: demo video URL
- `walkthrough_url`: walkthrough video URL


---

## Entry 2 — 2026-11-17T21:48:00+05:30 — Test Suite, Analyzers Polish, and Verification

**Prompt summary:** Retry from where you stopped; complete all rules, positive/negative tests, clean fixture, examples, and verify pytest passes.

**What was done:**
- Fixed build backend in `pyproject.toml` from legacy non-existent path to `setuptools.build_meta`
- Installed dependencies (`setuptools`, `wheel`, `pytest`) and editable package `looseend`
- Implemented JS/TS import validation vs `package.json` for SLOP002
- Broadened entropy candidate value regex to match complex tokens while maintaining Shannon threshold > 4.5
- Supported single-file scanning in `walker.py` and `runner.py`
- Excluded repo hygiene checks (GAP006) on single-file scans
- Implemented comprehensive unit & integration tests (`test_models.py`, `test_walker.py`, `test_security.py`, `test_slop.py`, `test_gap.py`, `test_clean_fixture.py`) with positive AND negative cases per rule
- Created `examples/bad_python.py` and `examples/clean_python.py`
- Executed `pytest`: 72 tests passed, 0 failed

**Decisions:**
- In `walker.py`, if a single file path is passed as root, directly yield the file and its detected language instead of attempting directory listing
- In `SLOP002` JS analysis, filtered out standard Node.js built-ins (`fs`, `path`, `crypto`, etc.) and `node:*` schemes before comparing against `package.json` dependencies
- In `runner.py`, called `finalize()` on analyzers to collect cross-file or post-processing findings like duplicate blocks (SLOP003)

**Rejected/corrected:**
- Corrected `_ENTROPY_VALUE_RE` in `security.py`: original character class was limited to alphanumeric + base64 symbols, failing to catch tokens containing punctuation like `#`, `$`, `@`. Changed to non-whitespace value boundary
- Corrected `tmp_project` fixture in `conftest.py` by adding `poetry.lock` so that clean project fixture yields strictly 0 findings
- Corrected double invocation of `finalize()` between `runner.py` and `cli.py`
