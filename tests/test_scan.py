from secretwall import hook as H
from secretwall import scan

from conftest import git


def kinds(tmp_path, text, name="config.py"):
    folder = tmp_path / str(len(list(tmp_path.iterdir())))
    folder.mkdir()
    (folder / name).write_text(text)
    return [r["kind"] for r in scan.secrets_in_files(str(folder))]


def test_finds_real_looking_secrets(tmp_path):
    assert kinds(tmp_path, 'KEY = "AKIAQWERTYUIOPASDFGH"\n') == ["AWS access key"]
    assert kinds(tmp_path, "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n", "k.txt") == ["private key"]
    assert kinds(tmp_path, "token: ghp_" + "a" * 36 + "\n", "ci.yml") == ["GitHub token"]
    assert kinds(tmp_path, "url = postgres://app:Xk29dkW1q@prod.db.internal:5432/app\n") == ["database password"]


def test_ignores_examples_and_local_defaults(tmp_path):
    assert kinds(tmp_path, 'KEY = "AKIAIOSFODNN7EXAMPLE"\n') == []
    assert kinds(tmp_path, "url = postgres://postgres:postgres@localhost:5432/app\n") == []
    assert kinds(tmp_path, "url = postgres://app:${DB_PASSWORD}@db.example.com/app\n") == []


def test_skips_lockfiles_and_binaries(tmp_path):
    (tmp_path / "package-lock.json").write_text('"AKIAQWERTYUIOPASDFGH"')
    (tmp_path / "blob.bin").write_bytes(b"\0\0AKIAQWERTYUIOPASDFGH")
    assert scan.secrets_in_files(str(tmp_path)) == []


def test_secret_files_skip_node_modules(project):
    (project / "node_modules" / "pkg").mkdir(parents=True)
    (project / "node_modules" / "pkg" / ".env").write_text("A=1\n")
    guard = H.Guard(str(project), H.Rules.parse(H.DEFAULT_RULES), {})
    found = [p.replace(str(project) + "/", "") for p in scan.secret_files(guard)]
    assert found == [".env", "config/credentials.json"]


def test_git_status(project):
    git(project, "add", "config/credentials.json")
    tracked, not_ignored = scan.git_status(str(project), [str(project / ".env"),
                                                          str(project / "config" / "credentials.json"),
                                                          str(project / "src" / "app.py")])
    assert tracked == {str(project / "config" / "credentials.json")}
    assert not_ignored == {str(project / "src" / "app.py")}


def test_git_status_outside_git(tmp_path):
    assert scan.git_status(str(tmp_path), []) == (None, None)
