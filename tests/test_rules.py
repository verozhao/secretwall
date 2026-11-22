import pytest

from secretwall import hook as H


def protected(rules_text, path, is_dir=False):
    return H.Rules.parse(rules_text).match(path, is_dir) is not None


@pytest.mark.parametrize("path, expected", [
    (".env", True),
    ("backend/.env", True),
    (".env.local", True),
    ("apps/web/.env.production", True),
    ("prod.env", True),
    (".env.example", False),
    ("config/.env.sample", False),
    ("server.pem", True),
    ("certs/tls.key", True),
    ("id_rsa", True),
    ("id_rsa.pub", False),
    ("credentials.json", True),
    ("gcp/service-account-prod.json", True),
    ("terraform.tfstate", True),
    ("src/app.py", False),
    ("README.md", False),
    ("environment.ts", False),
    (".ENV", True),  # case does not matter
])
def test_default_rules(path, expected):
    assert protected(H.DEFAULT_RULES, path) is expected


def test_gitignore_syntax():
    rules = "secrets/\n/top-only.txt\ndocs/**/private.md\n*.log\n!keep.log\n"
    assert protected(rules, "secrets/db.json")
    assert protected(rules, "a/secrets/x/y.json")
    assert not protected(rules, "secrets")          # a file named "secrets", not a folder
    assert protected(rules, "secrets", is_dir=True)
    assert protected(rules, "top-only.txt")
    assert not protected(rules, "sub/top-only.txt")
    assert protected(rules, "docs/private.md")
    assert protected(rules, "docs/a/b/private.md")
    assert protected(rules, "x/debug.log")
    assert not protected(rules, "keep.log")


def test_char_class_and_question_mark():
    rules = "key[0-9].txt\nfile?.cfg\n"
    assert protected(rules, "key7.txt")
    assert not protected(rules, "keyA.txt")
    assert protected(rules, "file1.cfg")
    assert not protected(rules, "file10.cfg")


def test_comments_and_escapes():
    rules = "# comment\n\n\\#hash\n\\!bang\n"
    assert protected(rules, "#hash")
    assert protected(rules, "!bang")
    assert not protected(rules, "comment")


def test_venv_named_env_is_not_secret(tmp_path):
    (tmp_path / ".env").mkdir()
    (tmp_path / ".env" / "pyvenv.cfg").write_text("home = /usr\n")
    (tmp_path / ".env" / "lib.py").write_text("x = 1\n")
    guard = H.Guard(str(tmp_path), H.Rules.parse(H.DEFAULT_RULES), {}, home=str(tmp_path / "h"))
    assert guard.check(str(tmp_path / ".env" / "lib.py")) is None


def test_home_secrets(guard, home):
    assert guard.check(str(home / ".ssh" / "id_rsa"))
    assert guard.check(str(home / ".aws" / "credentials"))
    assert guard.check(str(home / ".ssh" / "id_rsa.pub")) is None
    assert guard.check(str(home / "notes.txt")) is None


def test_home_protection_can_be_turned_off(project, home):
    g = H.Guard(str(project), H.Rules.parse(H.DEFAULT_RULES), {"protect_home": False}, home=str(home))
    assert g.check(str(home / ".aws" / "credentials")) is None


def test_symlink_to_secret(project, guard):
    link = project / "src" / "notes.txt"
    link.symlink_to(project / ".env")
    assert guard.check(str(link))


@pytest.mark.parametrize("name, expected", [
    ("OPENAI_API_KEY", True), ("STRIPE_SECRET", True), ("DB_PASSWORD", True), ("GITHUB_TOKEN", True),
    ("DATABASE_URL", True), ("SENTRY_DSN", True), ("ApiKey", True), ("DB_PWD", True),
    ("PWD", False), ("PATH", False), ("NODE_ENV", False), ("HOME", False), ("SSH_AUTH_SOCK", False),
    ("GIT_AUTHOR_NAME", False), ("NEXT_PUBLIC_STRIPE_KEY", False), ("KEYBOARD", False),
])
def test_secret_names(name, expected):
    assert H.is_secret_name(name) is expected
