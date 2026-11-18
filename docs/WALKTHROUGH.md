# LooseEnd walkthrough

A guided tour of LooseEnd on real output. Every number below comes from running the commands shown, on the demo apps in `examples/`.

## 1. Setup

```bash
git clone https://github.com/akash-bodanapati/looseend.git
cd looseend
pip install .
looseend scan --help
```

Python 3.10+ and nothing else. LooseEnd has no runtime dependencies.

## 2. The demo apps

| App | Purpose | Languages and files |
|---|---|---|
| `examples/vulnerable-app` | Seeded with known problems | Python, JavaScript, Java, Go, shell, `requirements.txt` |
| `examples/clean-app` | Same shape, no problems | Python, JavaScript, Makefile, README, LICENSE |

Each seeded line carries an `# expect: RULE` marker, so what is planted is explicit. The benchmark test counts 34 expected findings.

## 3. Scan the vulnerable app

```bash
looseend scan examples/vulnerable-app --no-color --fail-on none
```

```text
── 15 files scanned · 34 findings · 0 skipped ──
Severity: 4 critical, 6 high, 10 medium, 7 low, 7 info · risk score 97
```

34 findings across five languages in one scan, with no per-language setup. Some of what it reports:

```text
[SEC001] CRITICAL — app.py:9
  AWS access key ID detected
  fix: Remove credential from source code; use environment variables or a secrets manager

[SEC003] HIGH — app.py:31
  Unsafe deserialization via pickle
  fix: Use json or a safe serialization format

[SEC003] HIGH — transport.go:10
  TLS certificate verification disabled
  fix: Remove InsecureSkipVerify:true

[SLOP002] LOW — app.py:6
  Import 'fastjsonx' not found in stdlib or declared dependencies
  fix: Add to requirements.txt/pyproject.toml or verify the import

[GAP002] MEDIUM — app.py:55
  Bare except: catches all exceptions including KeyboardInterrupt
  fix: Catch specific exceptions: except ValueError: or except Exception:
```

Every finding has a rule ID, severity, file and line, the offending code as evidence, and a concrete fix.

### What the 34 findings are

| Category | Findings | Rules that fired |
|---|---|---|
| Security | 14 | SEC001 (2), SEC003 (11), SEC005 (1) |
| Slop | 13 | SLOP001 (3), SLOP002 (2), SLOP003 (2), SLOP004 (2), SLOP005 (4) |
| Gaps | 7 | GAP001 (2), GAP002 (1), GAP003 (3), GAP004 (1) |

SEC002, SEC004, GAP005 and GAP006 are covered by the test suite instead. They need conditions the demo app does not create, such as a committed key file or a missing hygiene file.

### Things worth noticing

- **Cross-file detection.** `shared_a.py:1` and `shared_b.py:1` are each reported as a duplicate 6-line block with the same hash (`2a84e8f4`). Neither file looks wrong alone. The duplicate only shows up when the whole tree is compared.
- **Hallucinated imports.** `fastjsonx` (Python) and `left-pad-pro` (JavaScript) are checked against the standard library and the declared dependencies. Neither exists in either place.
- **Related findings stay separate.** `app.py:55` reports both GAP002 (bare `except`) and GAP003 (swallowed exception), because they are two different problems.
- **Threshold in the message.** `long_function.py` reports `process_all` at 106 lines against a threshold of 100.

## 4. Use it as a CI gate

```bash
looseend scan examples/vulnerable-app --fail-on high
echo $?          # PowerShell: $LASTEXITCODE
```

The same report prints and the exit code is `1`, because the app has critical and high findings. `--fail-on` sets the lowest severity that fails the build. The scan above used `--fail-on none`, which always exits 0.

## 5. A clean codebase

```bash
looseend scan examples/clean-app
```

```text
✓ No findings. Clean codebase!

── 6 files scanned · 0 findings · 0 skipped ──
```

Exit code `0`. The clean app is the false-positive check: a tool that flags everything is useless.

## 6. Focus the report

```bash
looseend scan examples/vulnerable-app --category security --min-severity high --no-color --fail-on none
```

```text
── 15 files scanned · 10 findings · 0 skipped ──
Severity: 4 critical, 6 high · risk score 70
```

34 findings become the 10 that matter first: 4 critical and 6 high. `--category` is repeatable and `--min-severity` hides everything below the chosen level.

## 7. Output formats

```bash
looseend scan examples/vulnerable-app --format json --output report.json --fail-on none
looseend scan examples/vulnerable-app --format sarif --output report.sarif --fail-on none
looseend scan examples/vulnerable-app --format markdown --output report.md --fail-on none
```

JSON for scripts, Markdown for pull request comments, and SARIF for GitHub code scanning. The repository's own workflow (`.github/workflows/looseend.yml`) uploads SARIF on every push.

## 8. Adopt it on an existing codebase

```bash
looseend scan . --format json --output baseline.json --fail-on none
looseend scan . --baseline baseline.json
```

A baseline hides findings that already exist, so CI fails only on new ones.

## 9. It scans itself

```bash
looseend scan . --no-color
```

```text
── 0 findings ──
```

LooseEnd is held to its own standard, and CI runs this scan on every push.

Getting to 0 turned up a real bug. The first self-scan reported two SLOP003 findings, one each in `gap.py` and `slop.py`. Both were the shared `analyze()` signature that every analyzer must have, so they were not real duplicates. Adding `# looseend: ignore[SLOP003]` did nothing. The cause was in the runner: inline ignores were applied to per-file findings but not to the cross-file findings from `finalize()`. The fix and two regression tests are in the history. See Entry 7 in [`AI_LOG.md`](../AI_LOG.md).

## 10. Evidence

| Check | Result |
|---|---|
| Test suite | 152 passed |
| Benchmark corpus | 34 expected, 34 found, precision 1.00, recall 1.00 |
| Self-scan | 0 findings |
| Python compatibility | CI runs on 3.10, 3.11, 3.12, 3.13 and checks with vermin |

```bash
python -m pytest -q
python -m pytest tests/test_benchmark.py -s -q
```

## 11. Limitations

- Heuristic analysis, not a full static analyzer. Rules with low confidence can give false positives, which is what baselines and inline ignores are for.
- Import verification covers Python and JavaScript/TypeScript.
- Duplicate detection compares normalized line windows, not syntax trees.