# LooseEnd

A language-agnostic CLI agent that scans any codebase for:

1. **Security issues** — secrets, dangerous patterns, weak crypto, misconfigured deps
2. **AI slop** — placeholder stubs, hallucinated imports, duplicate blocks, debug prints
3. **Coding gaps** — TODO/FIXME/HACK, bare excepts, missing tests, missing repo hygiene files

## Install

```bash
pip install -e .
```

## Usage

```bash
looseend scan .                    # scan current directory
looseend scan /path/to/project     # scan a specific path
looseend scan . --format json      # JSON output
looseend scan . --severity high    # only high+ severity
looseend scan . --category security  # only security findings
```

## Zero dependencies

Requires only Python 3.10+. No third-party libraries.

## Rules

| Rule | Category | Description |
|------|----------|-------------|
| SEC001 | security | Hardcoded secrets and credentials |
| SEC002 | security | High entropy strings (potential secrets) |
| SEC003 | security | Dangerous code patterns |
| SEC004 | security | Committed .env or private key files |
| SEC005 | security | Unpinned dependencies |
| SLOP001 | slop | Placeholder stubs and fake content |
| SLOP002 | slop | Hallucinated imports |
| SLOP003 | slop | Duplicate code blocks |
| SLOP004 | slop | Commented-out code |
| SLOP005 | slop | Debug prints outside tests |
| GAP001 | gap | TODO/FIXME/HACK comments |
| GAP002 | gap | Bare except clauses |
| GAP003 | gap | Swallowed/empty error handlers |
| GAP004 | gap | Very long functions (>100 lines) |
| GAP005 | gap | Missing test files |
| GAP006 | gap | Missing repo hygiene files |
