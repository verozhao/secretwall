import json
import os

import pytest

from secretwall import cli, leaks

from conftest import SECRET

PEM = ("-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(
    ("MIIEpAIBAAKCAQEA%02dqVJxHk2bF7TQyWmZpN9sLcD4rE8uV1aG6hJ3kX0wY5zB" % i)[:64] for i in range(9))
    + "\n-----END RSA PRIVATE KEY-----\n")


def test_collect(project):
    (project / "certs").mkdir()
    (project / "certs" / "server.key").write_text(PEM)
    files = [str(project / ".env"), str(project / "secrets" / "db.json"), str(project / "certs" / "server.key")]
    found = {s.label: s.value for s in leaks.collect(files, str(project))}
    assert found[".env: OPENAI_API_KEY"] == SECRET
    assert ".env: NODE_ENV" not in found
    assert found["secrets/db.json: password"] == "hunter2hunter2"
    assert found["certs/server.key: private key"] in PEM


def test_collect_urls_and_quotes(tmp_path):
    env = tmp_path / ".env"
    env.write_text('DATABASE_URL="postgres://app:Sup3rS3cretPw@db.example.com:5432/app"\n'
                   "export STRIPE_KEY='sk_test_51Habcdefghijk'  # test key\n"
                   "PORT=3000\nDEBUG=true\nEMPTY=\nREF=${OTHER}\n")
    found = {s.label: s.value for s in leaks.collect([str(env)], str(tmp_path))}
    assert found[".env: DATABASE_URL (password)"] == "Sup3rS3cretPw"
    assert found[".env: STRIPE_KEY"] == "sk_test_51Habcdefghijk"
    assert not any(k.endswith(("PORT", "DEBUG", "EMPTY", "REF")) for k in found)


def test_search_finds_raw_and_json_escaped(tmp_path):
    secret = leaks.Secret("x", 'pa"ss/word\\123456')
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "a.jsonl").write_text(json.dumps({"content": "value is %s" % secret.value}) + "\n")
    (logs / "b.txt").write_text("nothing here\n")
    result = leaks.search([secret], [("Test", str(logs))])
    assert [os.path.basename(p) for _, p, _ in result.hits[0]] == ["a.jsonl"]
    assert result.files == 2


def test_search_skips_big_files(tmp_path):
    big = tmp_path / "big.jsonl"
    big.write_text("x" * 2000)
    result = leaks.search([leaks.Secret("x", "abcdefgh12345")], [("Test", str(big))], max_bytes=1000)
    assert result.skipped and not result.hits


def test_mask():
    assert leaks.mask("sk-proj-abcdefghijklmnop") == "sk-p…mnop"
    assert leaks.mask("short123") == "sh…"


def test_locations(home, project):
    (home / ".claude" / "projects").mkdir(parents=True)
    (home / ".codex" / "sessions").mkdir(parents=True)
    (project / ".aider.chat.history.md").write_text("hi\n")
    names = [a for a, _ in leaks.locations(str(home), str(project))]
    assert names == ["Claude Code", "Codex CLI", "Aider"]


@pytest.fixture
def chat_logs(home):
    folder = home / ".claude" / "projects" / "-tmp-proj"
    folder.mkdir(parents=True)
    return folder


def test_leaks_command_finds_a_leak(project, home, chat_logs, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("NO_COLOR", "1")
    line = {"type": "tool_result", "content": "OPENAI_API_KEY=%s\nNODE_ENV=development" % SECRET}
    (chat_logs / "session.jsonl").write_text(json.dumps(line) + "\n")
    assert cli.main(["leaks", "--root", str(project)]) == 1
    out = capsys.readouterr().out
    assert ".env: OPENAI_API_KEY" in out and "Claude Code" in out
    assert SECRET not in out
    assert leaks.mask(SECRET) in out


def test_leaks_command_all_clear(project, home, chat_logs, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("NO_COLOR", "1")
    (chat_logs / "session.jsonl").write_text('{"content": "nothing secret"}\n')
    assert cli.main(["leaks", "--root", str(project)]) == 0
    assert "None of your" in capsys.readouterr().out


def test_parse_size():
    assert cli.parse_size("1G") == 1 << 30
    assert cli.parse_size("500m") == 500 << 20
    assert cli.parse_size("0") > 1 << 60
