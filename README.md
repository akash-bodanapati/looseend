# LooseEnd

[![CI](https://github.com/akash-bodanapati/looseend/actions/workflows/ci.yml/badge.svg)](https://github.com/akash-bodanapati/looseend/actions/workflows/ci.yml)
[![LooseEnd](https://github.com/akash-bodanapati/looseend/actions/workflows/looseend.yml/badge.svg)](https://github.com/akash-bodanapati/looseend/actions/workflows/looseend.yml)


**A language-agnostic CLI agent that finds the loose ends in a codebase: security issues, AI slop and coding gaps, whatever the architecture or stack.**

```bash
pip install git+https://github.com/akash-bodanapati/looseend.git
looseend scan .
```

| | |
|---|---|
| **16 rules** | 5 security, 5 slop, 6 gap, each with a severity and a confidence level |
| **4 report formats** | text, JSON, Markdown, SARIF (GitHub code scanning) |
| **CI-ready** | configurable exit codes, baselines, inline ignores, GitHub Action, pre-commit hook |
| **Zero runtime dependencies** | Python 3.10+ standard library only |
| **Dogfooded** | scans its own source with 0 findings |

## What it finds

1. **Security issues**: hardcoded secrets, high-entropy strings, dangerous code patterns (eval/exec, shell injection, unsafe deserialization, SQL built from strings, weak MD5/SHA1 hashes), committed key files, unpinned dependencies
2. **AI slop**: placeholder stubs and fake content, imports that exist nowhere, duplicated blocks, commented-out code, leftover debug output
3. **Coding gaps**: TODO/FIXME markers, bare and swallowed exceptions, overly long functions, missing tests, missing repository hygiene files

## Example output

This is a real finding LooseEnd raised on its own source while it was being built (two analyzers shared the same `analyze()` signature):

```text
[SLOP003] LOW — src\looseend\analyzers\gap.py:158
  Duplicate code block (7 lines, appears in 2 files)
  evidence: Hash 5bdd5ae7
  fix: Extract duplicate block into a shared function or module

── 39 files scanned · 2 findings · 0 skipped ──
Severity: 2 low · risk score 2
```

## Install

Requires Python 3.10+. `pytest` is needed only to run the tests.

```bash
git clone https://github.com/akash-bodanapati/looseend.git
cd looseend
pip install .
```

For development: `pip install -e .`

## Quickstart

```bash
# Scan the current directory
looseend scan .

# Only security findings, medium severity and above
looseend scan . --category security --min-severity medium

# Write a SARIF report for GitHub code scanning
looseend scan . --format sarif --output looseend.sarif

# Fail CI only on high or critical findings
looseend scan . --fail-on high
```

## Options

| Flag | Description |
|---|---|
| `path` | File or directory to scan (default: `.`) |
| `--format {text,json,markdown,sarif}` | Report format |
| `--min-severity {critical,high,medium,low,info}` | Hide findings below this severity (alias: `--severity`) |
| `--fail-on {critical,high,medium,low,info,none}` | Exit 1 if any finding is at or above this severity (default: `info`) |
| `--category {security,slop,gap}` | Only run this category (repeatable) |
| `--baseline BASELINE` | JSON report or ID list; its findings are hidden |
| `--output OUTPUT` | Write the report to a file instead of stdout |
| `--no-color` | Disable ANSI colors |

## Rules

### Security

| ID | What it finds | Severity |
|---|---|---|
| SEC001 | Hardcoded secret or credential | varies by pattern |
| SEC002 | High-entropy string that looks like a secret | Medium |
| SEC003 | Dangerous or insecure code pattern, across Python, JS/TS, Java, Go, PHP, Ruby and shell | Critical / High / Medium |
| SEC004 | Secret or key file committed to the repository | Critical |
| SEC005 | Unpinned or wildcard dependency version | Low |

### Slop

| ID | What it finds | Severity |
|---|---|---|
| SLOP001 | Placeholder stub or fake content | Medium / Low |
| SLOP002 | Import not found in stdlib or declared dependencies (Python, JS/TS) | Low |
| SLOP003 | Duplicated code block across files | Low |
| SLOP004 | Commented-out code | Info |
| SLOP005 | Leftover debug output or breakpoint | Medium / Info |

### Gaps

| ID | What it finds | Severity |
|---|---|---|
| GAP001 | TODO, FIXME, HACK, XXX, BUG or WORKAROUND in a real comment | Info |
| GAP002 | Bare `except` clause | Medium |
| GAP003 | Swallowed exception | Medium |
| GAP004 | Function longer than 100 lines | Low |
| GAP005 | Missing test file | Low |
| GAP006 | Missing repository hygiene file | Medium / Low |

## Suppressing findings

**Inline ignore.** Put a comment on the line the finding is reported on:

```python
value = risky_call()  # looseend: ignore[SEC003]
other = thing()       # looseend: ignore            (all rules on this line)
```

Several rules can be listed: `# looseend: ignore[SLOP005,GAP001]`.

Cross-file rules such as SLOP003 are reported after all files are scanned. Inline ignores apply to them too: put the same comment on the first line of the duplicated block in each file.

**Ignore file.** `.looseendignore` excludes paths from the scan, alongside `.gitignore`.

**Baseline.** Hide findings that already exist and fail only on new ones:

```bash
looseend scan . --format json --output baseline.json
looseend scan . --baseline baseline.json
```

## CI

### GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: akash-bodanapati/looseend@main
  with:
    fail-on: high
```

Inputs: `path`, `fail-on`, `min-severity`, `category`, `format`, `output`, `baseline`. In the Action, `fail-on` defaults to `high`, so Info-level findings such as TODO markers do not fail the build.

### GitHub code scanning (SARIF)

```yaml
- uses: actions/checkout@v4
- uses: akash-bodanapati/looseend@main
  with:
    format: sarif
    output: looseend.sarif
    fail-on: none
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: looseend.sarif
```

### pre-commit

```yaml
repos:
  - repo: https://github.com/akash-bodanapati/looseend
    rev: main
    hooks:
      - id: looseend
        args: ["--fail-on", "high"]
```

## Evidence

| Check | Result |
|---|---|
| Test suite | 152 passed |
| Benchmark corpus | 34 expected, 34 found, precision 1.00, recall 1.00 |
| Self-scan | 0 findings |
| Python compatibility | vermin reports a minimum of 3.8, within the declared 3.10+ target |

Run them yourself:

```bash
python -m pytest -q
python -m pytest tests/test_benchmark.py -s -q
looseend scan . --no-color
```

## Design

```text
walker ──► runner ──► analyzers (security · slop · gap)
 │           │              │
 │           │              └─ analyze(): per-file findings
 │           └─ inline ignores ──► filter
 └─ .gitignore + .looseendignore    finalize(): cross-file findings (SLOP003) ──► filter
                                                │
                                   baseline ──► reporters (text · json · markdown · sarif)
```

- **Analyzer plugins.** Each category implements one `analyze()` interface. A second `finalize()` pass handles cross-file checks such as duplicate detection.
- **Architecture-agnostic.** The walker respects `.gitignore` and `.looseendignore` and detects the language per file. Language-specific checks (import verification, dangerous patterns) cover the languages listed above; the rest work on any text file.
- **Findings carry confidence.** Each finding reports High, Medium or Low confidence, so noisy heuristics such as entropy checks rank below certain ones.

## Built with an AI pair, verified by its own tool

LooseEnd was built with Antigravity. Every AI-assisted step is recorded in [`AI_LOG.md`](AI_LOG.md), including mistakes and corrections.

One example: running LooseEnd on itself flagged duplicate `analyze()` signatures (SLOP003). The inline ignore did not suppress it. Tracing that showed that cross-file findings from `finalize()` bypassed the ignore filter in the runner. The fix and two regression tests (a control without the ignore, and one with it) are in the history.

## Limitations

- Heuristic analysis, not a full static analyzer. Low-confidence rules can give false positives, which baselines and inline ignores are for.
- Import verification (SLOP002) covers Python and JS/TS only.
- Duplicate detection (SLOP003) works on line windows, not syntax trees.

## License

MIT