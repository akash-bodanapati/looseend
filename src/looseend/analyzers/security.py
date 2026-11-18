"""Security analyzer: secrets, dangerous patterns, committed files, unpinned deps."""
from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Iterator

from looseend.engine.analyzer import Analyzer
from looseend.models import Category, Confidence, Finding, Severity


_ALLOWLIST_RE = re.compile(
    r"(?i)(example|test|dummy|fake|placeholder|your_|<[^>]+>|TODO|FIXME)"
)

# SEC001 patterns: (regex, severity, message)
_SECRET_PATTERNS: list[tuple[re.Pattern, Severity, str]] = [
    (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "Private key material detected",
    ),
    (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        Severity.CRITICAL,
        "AWS access key ID detected",
    ),
    (
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        Severity.CRITICAL,
        "GitHub personal access token detected",
    ),
    (
        re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
        Severity.HIGH,
        "Slack token detected",
    ),
    (
        re.compile(r"(?i)(?:mysql|postgres|mongodb|redis|amqp)://[^:\s]+:[^@\s]{3,}@"),
        Severity.HIGH,
        "Database connection string with credentials",
    ),
    (
        re.compile(r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9\-_]{20,})["\']?'),
        Severity.HIGH,
        "Hardcoded API key",
    ),
    (
        re.compile(r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']'),
        Severity.HIGH,
        "Hardcoded password",
    ),
    (
        re.compile(r'(?i)(?:secret[_-]?key|secret)\s*[:=]\s*["\']([^"\']{8,})["\']'),
        Severity.HIGH,
        "Hardcoded secret",
    ),
    (
        re.compile(r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]{20,}"),
        Severity.MEDIUM,
        "Hardcoded Bearer token",
    ),
]

# SEC003: (languages, regex, severity, message, fix_hint)
_DANGEROUS: list[tuple[set[str], re.Pattern, Severity, str, str]] = [
    # Python
    ({"python"}, re.compile(r"\beval\s*\("), Severity.CRITICAL,
     "Use of eval() executes arbitrary code", "Use ast.literal_eval() for data, or redesign to avoid eval"),
    ({"python"}, re.compile(r"\bexec\s*\("), Severity.CRITICAL,
     "Use of exec() executes arbitrary code", "Redesign to avoid exec(); use importlib for dynamic imports"),
    ({"python"}, re.compile(r"\bsubprocess\b.*\bshell\s*=\s*True"), Severity.HIGH,
     "shell=True enables shell injection", "Pass a list of args instead; remove shell=True"),
    ({"python"}, re.compile(r"\bos\.system\s*\("), Severity.HIGH,
     "os.system() enables shell injection", "Use subprocess.run() with a list of args"),
    ({"python"}, re.compile(r"\bpickle\.loads?\s*\("), Severity.HIGH,
     "Unsafe deserialization via pickle", "Use json or a safe serialization format"),
    ({"python"}, re.compile(r"\bmarshal\.loads?\s*\("), Severity.HIGH,
     "Unsafe deserialization via marshal", "Use json or a safe serialization format"),
    ({"python"}, re.compile(r"\byaml\.load\s*\((?![^)]*Loader)"), Severity.HIGH,
     "yaml.load() without Loader is unsafe", "Use yaml.safe_load() instead"),
    ({"python"}, re.compile(r"\bhashlib\.(md5|sha1)\s*\("), Severity.MEDIUM,
     "Weak hash algorithm", "Use hashlib.sha256() or stronger"),
    ({"python"}, re.compile(r"\bverify\s*=\s*False"), Severity.HIGH,
     "TLS certificate verification disabled", "Remove verify=False or use a proper CA bundle"),
    ({"python"}, re.compile(r"\bDEBUG\s*=\s*True"), Severity.MEDIUM,
     "Debug mode enabled — do not deploy", "Set DEBUG=False in production"),
    ({"python"}, re.compile(r'(?i)CORS.*allow_origins.*["\'\[]?\*'), Severity.MEDIUM,
     "Permissive CORS allows all origins", "Restrict to specific trusted origins"),
    ({"python"}, re.compile(r'\bcursor\.execute\s*\(\s*(?:f["\']|["\'].*%|["\'].*\{)'), Severity.HIGH,
     "Potential SQL injection via string formatting", "Use parameterized queries"),
    # JavaScript / TypeScript
    ({"javascript", "typescript"}, re.compile(r"\beval\s*\("), Severity.CRITICAL,
     "Use of eval() executes arbitrary code", "Avoid eval(); use JSON.parse() for data"),
    ({"javascript", "typescript"}, re.compile(r"\bnew\s+Function\s*\("), Severity.HIGH,
     "new Function() is equivalent to eval", "Avoid dynamic code construction"),
    ({"javascript", "typescript"}, re.compile(r"\binnerHTML\s*="), Severity.MEDIUM,
     "innerHTML assignment may cause XSS", "Use textContent or sanitize input with DOMPurify"),
    ({"javascript", "typescript"}, re.compile(r"\bdocument\.write\s*\("), Severity.MEDIUM,
     "document.write() is unsafe", "Use DOM manipulation methods instead"),
    ({"javascript", "typescript"}, re.compile(r"\bchild_process\b.*\bshell\s*:\s*true"), Severity.HIGH,
     "shell:true enables shell injection", "Remove shell:true and pass args as array"),
    ({"javascript", "typescript"}, re.compile(r'\bcrypto\.createHash\s*\(\s*["\']md5["\']\s*\)'), Severity.MEDIUM,
     "Weak MD5 hash", "Use crypto.createHash('sha256')"),
    ({"javascript", "typescript"}, re.compile(r'\bcrypto\.createHash\s*\(\s*["\']sha1["\']\s*\)'), Severity.MEDIUM,
     "Weak SHA1 hash", "Use crypto.createHash('sha256')"),
    ({"javascript", "typescript"}, re.compile(r"\brejectUnauthorized\s*:\s*false"), Severity.HIGH,
     "TLS certificate verification disabled", "Remove rejectUnauthorized:false"),
    ({"javascript", "typescript"}, re.compile(r"\bdangerouslySetInnerHTML"), Severity.MEDIUM,
     "React dangerouslySetInnerHTML is an XSS risk", "Sanitize content before rendering"),
    # Java
    ({"java"}, re.compile(r"\bRuntime\.getRuntime\(\)\.exec\s*\("), Severity.HIGH,
     "Shell execution via Runtime.exec()", "Use ProcessBuilder with a list of args"),
    ({"java"}, re.compile(r'\bMessageDigest\.getInstance\s*\(\s*"MD5"\s*\)'), Severity.MEDIUM,
     "Weak MD5 hash", "Use SHA-256 or stronger"),
    ({"java"}, re.compile(r'\bMessageDigest\.getInstance\s*\(\s*"SHA-1"\s*\)'), Severity.MEDIUM,
     "Weak SHA1 hash", "Use SHA-256 or stronger"),
    ({"java"}, re.compile(r"\.setHostnameVerifier\s*\(.*ALLOW_ALL"), Severity.HIGH,
     "Hostname verification disabled", "Use default hostname verifier"),
    # Go
    ({"go"}, re.compile(r"\bexec\.Command\s*\("), Severity.MEDIUM,
     "Command execution — verify input is sanitized", "Validate and whitelist command arguments"),
    ({"go"}, re.compile(r"\bmd5\.New\s*\(\s*\)"), Severity.MEDIUM,
     "Weak MD5 hash", "Use crypto/sha256"),
    ({"go"}, re.compile(r"\bsha1\.New\s*\(\s*\)"), Severity.MEDIUM,
     "Weak SHA1 hash", "Use crypto/sha256"),
    ({"go"}, re.compile(r"\bInsecureSkipVerify\s*:\s*true"), Severity.HIGH,
     "TLS certificate verification disabled", "Remove InsecureSkipVerify:true"),
    # PHP
    ({"php"}, re.compile(r"\beval\s*\("), Severity.CRITICAL,
     "Use of eval() executes arbitrary code", "Remove eval(); redesign the logic"),
    ({"php"}, re.compile(r"\bsystem\s*\("), Severity.HIGH,
     "Shell execution via system()", "Avoid shell execution; use PHP libraries"),
    ({"php"}, re.compile(r"\bexec\s*\("), Severity.HIGH,
     "Shell execution via exec()", "Avoid shell execution"),
    ({"php"}, re.compile(r"\bshell_exec\s*\("), Severity.HIGH,
     "Shell execution via shell_exec()", "Avoid shell execution"),
    ({"php"}, re.compile(r"\bpassthru\s*\("), Severity.HIGH,
     "Shell execution via passthru()", "Avoid shell execution"),
    ({"php"}, re.compile(r"\bmd5\s*\("), Severity.MEDIUM,
     "Weak MD5 hash", "Use password_hash() for passwords, hash('sha256', ...) for data"),
    ({"php"}, re.compile(r"\bsha1\s*\("), Severity.MEDIUM,
     "Weak SHA1 hash", "Use hash('sha256', ...)"),
    # Ruby
    ({"ruby"}, re.compile(r"`[^`]+`"), Severity.HIGH,
     "Backtick shell execution", "Use Open3 or system() with an array; sanitize inputs"),
    ({"ruby"}, re.compile(r"\bsystem\s*\("), Severity.HIGH,
     "Shell execution via system()", "Pass an array to avoid shell injection"),
    ({"ruby"}, re.compile(r"\beval\s*\("), Severity.CRITICAL,
     "Use of eval() executes arbitrary code", "Avoid eval()"),
    ({"ruby"}, re.compile(r"\bDigest::MD5\b"), Severity.MEDIUM,
     "Weak MD5 hash", "Use Digest::SHA256"),
    ({"ruby"}, re.compile(r"\bDigest::SHA1\b"), Severity.MEDIUM,
     "Weak SHA1 hash", "Use Digest::SHA256"),
    ({"ruby"}, re.compile(r"\bOpenSSL::SSL::VERIFY_NONE\b"), Severity.HIGH,
     "TLS certificate verification disabled", "Use VERIFY_PEER"),
    # Shell
    ({"shell"}, re.compile(r'\beval\s+"?\$'), Severity.HIGH,
     "eval of variable is dangerous", "Avoid eval with user-controlled input"),
    ({"shell"}, re.compile(r"\bcurl\b.*\|\s*(?:ba)?sh\b"), Severity.CRITICAL,
     "Piping curl output to shell", "Download first, verify checksum, then execute"),
    ({"shell"}, re.compile(r"\bwget\b.*\|\s*(?:ba)?sh\b"), Severity.CRITICAL,
     "Piping wget output to shell", "Download first, verify checksum, then execute"),
    ({"shell"}, re.compile(
        r"\bcurl\b[^\n]*?\s(?:-[A-Za-z]*k[A-Za-z]*|--insecure)(?=\s|$)"
        r"|\bwget\b[^\n]*?\s--no-check-certificate\b"),
     Severity.HIGH, "TLS certificate verification disabled",
     "Remove -k/--insecure/--no-check-certificate; trust the right CA bundle instead"),
]

_ENV_FILE_NAMES = frozenset({
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.test",
})
_KEY_EXTENSIONS = frozenset({".pem", ".p12", ".pfx", ".key"})

_ENTROPY_LANGS = frozenset({
    "env", "conf", "yaml", "json", "toml", "python", "javascript", "typescript",
})
_ENTROPY_VALUE_RE = re.compile(
    r'(?:[:=]\s*["\']?|["\'])([A-Za-z0-9+/=_\-.~!@#$%^&*]{20,200})["\']?'
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _is_allowlisted(line: str) -> bool:
    return bool(_ALLOWLIST_RE.search(line))


def _is_url_or_path(s: str) -> bool:
    return s.startswith(("http://", "https://", "/", "./", "../")) or "\\" in s


class SecurityAnalyzer(Analyzer):
    category = Category.SECURITY

    def analyze(
        self,
        path: Path,
        source: str,
        language: str,
        rel_path: str,
    ) -> Iterator[Finding]:
        yield from self._sec001(path, source, rel_path)
        yield from self._sec002(path, source, language, rel_path)
        yield from self._sec003(path, source, language, rel_path)
        yield from self._sec004(path, rel_path)
        yield from self._sec005(path, source, language, rel_path)

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
            category=Category.SECURITY,
            severity=severity,
            confidence=confidence,
            file=rel_path,
            line=line,
            message=message,
            evidence=evidence,
            fix_hint=fix_hint,
        )

    def _sec001(self, path: Path, source: str, rel_path: str) -> Iterator[Finding]:
        for lineno, line in enumerate(source.splitlines(), 1):
            if _is_allowlisted(line):
                continue
            for pat, severity, message in _SECRET_PATTERNS:
                m = pat.search(line)
                if m:
                    yield self._make(
                        "SEC001", severity, Confidence.HIGH,
                        rel_path, lineno, message,
                        line.strip()[:120],
                        "Remove credential from source code; use environment variables or a secrets manager",
                    )
                    break  # one finding per line

    def _sec002(self, path: Path, source: str, language: str, rel_path: str) -> Iterator[Finding]:
        if language not in _ENTROPY_LANGS:
            return
        for lineno, line in enumerate(source.splitlines(), 1):
            if _is_allowlisted(line):
                continue
            for m in _ENTROPY_VALUE_RE.finditer(line):
                candidate = m.group(1)
                if _is_url_or_path(candidate):
                    continue
                entropy = _shannon_entropy(candidate)
                if entropy > 4.5:
                    yield self._make(
                        "SEC002", Severity.MEDIUM, Confidence.LOW,
                        rel_path, lineno,
                        f"High-entropy string detected ({entropy:.2f} bits/char)",
                        candidate[:60],
                        "If this is a secret, move it to an environment variable or secrets manager",
                    )
                    return  # one finding per file

    def _sec003(self, path: Path, source: str, language: str, rel_path: str) -> Iterator[Finding]:
        lines = source.splitlines()
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if language == "python" and stripped.startswith("#"):
                continue
            for langs, pat, severity, message, fix_hint in _DANGEROUS:
                if language not in langs:
                    continue
                if pat.search(line):
                    yield self._make(
                        "SEC003", severity, Confidence.HIGH,
                        rel_path, lineno, message,
                        line.strip()[:120], fix_hint,
                    )
                    break  # one finding per line

    def _sec004(self, path: Path, rel_path: str) -> Iterator[Finding]:
        name = path.name
        if name in _ENV_FILE_NAMES or path.suffix.lower() in _KEY_EXTENSIONS:
            yield self._make(
                "SEC004", Severity.CRITICAL, Confidence.HIGH,
                rel_path, 1,
                f"Sensitive file '{name}' is not gitignored and may be committed",
                rel_path,
                "Add this file to .gitignore and remove from git history if committed",
            )

    def _sec005(self, path: Path, source: str, language: str, rel_path: str) -> Iterator[Finding]:
        name = path.name.lower()
        if name == "requirements.txt":
            yield from self._sec005_requirements(source, rel_path)
        elif name == "package.json":
            yield from self._sec005_package_json(source, rel_path)
        elif name == "go.mod":
            yield from self._sec005_go_mod(source, rel_path)
        elif name == "pom.xml":
            yield from self._sec005_pom_xml(source, rel_path)

    def _sec005_requirements(self, source: str, rel_path: str) -> Iterator[Finding]:
        for lineno, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-r", "-c", "-e", "-f", "--")):
                continue
            # Unpinned if uses >=, ~=, > or has no version specifier at all
            if re.search(r"[>~]=|^[A-Za-z0-9]", stripped) and not re.search(r"==", stripped):
                # Check it's a package line (not a URL)
                if not stripped.startswith(("http://", "https://", "git+")):
                    pkg = re.split(r"[>=<!@;#\s]", stripped)[0]
                    yield self._make(
                        "SEC005", Severity.LOW, Confidence.HIGH,
                        rel_path, lineno,
                        f"Unpinned dependency: {pkg}",
                        stripped,
                        "Pin to an exact version: pkg==X.Y.Z",
                    )

    def _sec005_package_json(self, source: str, rel_path: str) -> Iterator[Finding]:
        try:
            data = json.loads(source)
        except (json.JSONDecodeError, ValueError):
            return
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for pkg, ver in deps.items():
                if isinstance(ver, str) and ver[:1] in ("^", "~", "*") or ver == "latest":
                    lineno = 1
                    for i, line in enumerate(source.splitlines(), 1):
                        if f'"{pkg}"' in line:
                            lineno = i
                            break
                    yield self._make(
                        "SEC005", Severity.LOW, Confidence.HIGH,
                        rel_path, lineno,
                        f"Unpinned npm dependency: {pkg}@{ver}",
                        f'"{pkg}": "{ver}"',
                        "Use an exact version without ^ or ~",
                    )

    def _sec005_go_mod(self, source: str, rel_path: str) -> Iterator[Finding]:
        for lineno, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("require") or (stripped and stripped[0] not in ("/", ")")):
                if "-SNAPSHOT" in stripped:
                    pkg = stripped.split()[0] if stripped.split() else stripped
                    yield self._make(
                        "SEC005", Severity.LOW, Confidence.HIGH,
                        rel_path, lineno,
                        f"SNAPSHOT dependency in go.mod: {pkg}",
                        stripped, "Use a released version",
                    )

    def _sec005_pom_xml(self, source: str, rel_path: str) -> Iterator[Finding]:
        for lineno, line in enumerate(source.splitlines(), 1):
            if "<version>" in line and "SNAPSHOT" in line:
                yield self._make(
                    "SEC005", Severity.LOW, Confidence.HIGH,
                    rel_path, lineno,
                    "SNAPSHOT version in pom.xml",
                    line.strip(),
                    "Use a release version instead of SNAPSHOT",
                )