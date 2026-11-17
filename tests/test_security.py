"""Security analyzer tests — positive and negative cases per rule."""
from pathlib import Path
from looseend.analyzers.security import SecurityAnalyzer


def _run(tmp_path, name, content):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    a = SecurityAnalyzer()
    ext = Path(name).suffix.lower()
    langs = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".java": "java", ".go": "go", ".php": "php", ".rb": "ruby",
        ".sh": "shell", ".env": "env", ".txt": "text", ".json": "json",
        ".xml": "xml", ".mod": "go",
    }
    lang = langs.get(ext, "text")
    if name.startswith(".env"):
        lang = "env"
    elif name == "go.mod":
        lang = "go"
    return list(a.analyze(p, content, lang, name))


# SEC001: Secret regex packs
def test_sec001_api_key_positive(tmp_path):
    f = _run(tmp_path, "cfg.py", 'API_KEY = "abcdefghijklmnopqrstuvwxyz123456"\n')
    assert any(x.rule_id == "SEC001" for x in f)


def test_sec001_allowlist_negative(tmp_path):
    f = _run(tmp_path, "cfg.py", 'API_KEY = "your_api_key_here"\n')
    assert not any(x.rule_id == "SEC001" for x in f)


def test_sec001_aws_positive(tmp_path):
    f = _run(tmp_path, "aws.py", 'key = "AKIAIOSFODNN7ABCDE12"\n')
    assert any(x.rule_id == "SEC001" and x.severity.value == "critical" for x in f)


def test_sec001_private_key_positive(tmp_path):
    f = _run(tmp_path, "mykey.txt", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n")
    assert any(x.rule_id == "SEC001" for x in f)


def test_sec001_github_token_positive(tmp_path):
    f = _run(tmp_path, "cfg.txt", "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234\n")
    assert any(x.rule_id == "SEC001" for x in f)


def test_sec001_clean_negative(tmp_path):
    f = _run(tmp_path, "clean.py", "x = 1\ny = 'normal string'\n")
    assert not any(x.rule_id == "SEC001" for x in f)


# SEC002: Entropy
def test_sec002_entropy_positive(tmp_path):
    # High entropy string in .env
    f = _run(tmp_path, ".env.app", 'TOKEN="9zK#mP2$vL8@qR4&wX1*yN7!jB5^"\n')
    assert any(x.rule_id == "SEC002" for x in f)


def test_sec002_entropy_negative(tmp_path):
    # Low entropy regular words in .env
    f = _run(tmp_path, ".env.app", 'APP_NAME="LooseEndCodebaseScanner"\n')
    assert not any(x.rule_id == "SEC002" for x in f)


# SEC003: Dangerous patterns
def test_sec003_python_eval_positive(tmp_path):
    f = _run(tmp_path, "app.py", "res = eval(user_input)\n")
    assert any(x.rule_id == "SEC003" for x in f)


def test_sec003_python_clean_negative(tmp_path):
    f = _run(tmp_path, "safe.py", "import ast\nres = ast.literal_eval(user_input)\n")
    assert not any(x.rule_id == "SEC003" for x in f)


def test_sec003_python_shell_true_positive(tmp_path):
    f = _run(tmp_path, "sub.py", "subprocess.run(cmd, shell=True)\n")
    assert any(x.rule_id == "SEC003" for x in f)


def test_sec003_python_pickle_positive(tmp_path):
    f = _run(tmp_path, "data.py", "obj = pickle.loads(raw_data)\n")
    assert any(x.rule_id == "SEC003" for x in f)


def test_sec003_python_tls_verify_positive(tmp_path):
    f = _run(tmp_path, "req.py", "requests.get(url, verify=False)\n")
    assert any(x.rule_id == "SEC003" for x in f)


def test_sec003_js_eval_positive(tmp_path):
    f = _run(tmp_path, "app.js", "const r = eval(code);\n")
    assert any(x.rule_id == "SEC003" for x in f)


def test_sec003_js_clean_negative(tmp_path):
    f = _run(tmp_path, "app.js", "const r = JSON.parse(code);\n")
    assert not any(x.rule_id == "SEC003" for x in f)


def test_sec003_java_runtime_exec_positive(tmp_path):
    f = _run(tmp_path, "Main.java", 'Runtime.getRuntime().exec("sh");\n')
    assert any(x.rule_id == "SEC003" for x in f)


def test_sec003_go_exec_positive(tmp_path):
    f = _run(tmp_path, "main.go", 'exec.Command("sh")\n')
    assert any(x.rule_id == "SEC003" for x in f)


def test_sec003_php_eval_positive(tmp_path):
    f = _run(tmp_path, "index.php", "eval($code);\n")
    assert any(x.rule_id == "SEC003" for x in f)


def test_sec003_ruby_backtick_positive(tmp_path):
    f = _run(tmp_path, "app.rb", "`ls #{params[:dir]}`\n")
    assert any(x.rule_id == "SEC003" for x in f)


def test_sec003_shell_curl_pipe_sh_positive(tmp_path):
    f = _run(tmp_path, "setup.sh", "curl https://example.com/install.sh | sh\n")
    assert any(x.rule_id == "SEC003" for x in f)


# SEC004: Committed .env / private keys
def test_sec004_env_file_positive(tmp_path):
    f = _run(tmp_path, ".env", "PORT=3000\n")
    assert any(x.rule_id == "SEC004" for x in f)


def test_sec004_pem_file_positive(tmp_path):
    f = _run(tmp_path, "cert.pem", "test\n")
    assert any(x.rule_id == "SEC004" for x in f)


def test_sec004_regular_file_negative(tmp_path):
    f = _run(tmp_path, "regular.py", "x = 1\n")
    assert not any(x.rule_id == "SEC004" for x in f)


# SEC005: Unpinned dependencies
def test_sec005_requirements_unpinned_positive(tmp_path):
    f = _run(tmp_path, "requirements.txt", "requests>=2.0.0\nflask\n")
    assert any(x.rule_id == "SEC005" for x in f)


def test_sec005_requirements_pinned_negative(tmp_path):
    f = _run(tmp_path, "requirements.txt", "requests==2.31.0\nflask==3.0.0\n")
    assert not any(x.rule_id == "SEC005" for x in f)


def test_sec005_package_json_unpinned_positive(tmp_path):
    f = _run(tmp_path, "package.json", '{"dependencies": {"express": "^4.18.0"}}\n')
    assert any(x.rule_id == "SEC005" for x in f)


def test_sec005_package_json_pinned_negative(tmp_path):
    f = _run(tmp_path, "package.json", '{"dependencies": {"express": "4.18.0"}}\n')
    assert not any(x.rule_id == "SEC005" for x in f)


def test_sec005_go_mod_positive(tmp_path):
    f = _run(tmp_path, "go.mod", "require github.com/foo/bar v0.0.0-SNAPSHOT\n")
    assert any(x.rule_id == "SEC005" for x in f)


def test_sec005_pom_xml_positive(tmp_path):
    f = _run(tmp_path, "pom.xml", "<dependency><version>1.0.0-SNAPSHOT</version></dependency>\n")
    assert any(x.rule_id == "SEC005" for x in f)
