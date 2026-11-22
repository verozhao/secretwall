import json
import os
import sys

import pytest

from secretwall import agents, cli
from secretwall import hook as H

ALL_HOOKS = "claude,codex,copilot,cursor,gemini,windsurf"


@pytest.fixture(autouse=True)
def fake_home(home, monkeypatch):
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("NO_COLOR", "1")


def init(project, *extra):
    return cli.main(["init", "--root", str(project), "--python", sys.executable] + list(extra))


def load(path):
    return json.loads(path.read_text())


def test_init_sets_up_agents(project, capsys):
    assert init(project, "--agents", ALL_HOOKS + ",aider") == 0
    out = capsys.readouterr().out
    assert ".env" in out and "Claude Code" in out
    assert (project / ".secretwall" / "hook.py").read_text() == open(cli.hook_source()).read()
    assert "!.env.example" in (project / ".secretwall" / "rules").read_text()
    assert load(project / ".secretwall" / "config.json")["block_env_dump"] is True
    assert (project / ".secretwall" / ".gitignore").read_text().strip() == "blocked.log"
    claude = load(project / ".claude" / "settings.json")
    assert claude["hooks"]["PreToolUse"][0]["matcher"] == agents.CLAUDE_MATCHER
    assert "Read(**/.env)" in claude["permissions"]["deny"]
    assert "Read(/config/credentials.json)" not in claude["permissions"]["deny"]  # covered by a pattern
    assert agents.HOOK_MARK in (project / ".codex" / "hooks.json").read_text()
    assert load(project / ".github" / "hooks" / "secretwall.json")["version"] == 1
    cursor = load(project / ".cursor" / "hooks.json")
    assert set(cursor["hooks"]) == {"beforeShellExecution", "beforeReadFile"}
    assert agents.HOOK_MARK in (project / ".gemini" / "settings.json").read_text()
    assert set(load(project / ".windsurf" / "hooks.json")["hooks"]) == {
        "pre_read_code", "pre_write_code", "pre_run_command"}
    for name in (".cursorignore", ".geminiignore", ".codeiumignore", ".aiderignore"):
        text = (project / name).read_text()
        assert agents.BLOCK_START in text and "\n.env\n" in text and "!.env.example" in text


def test_init_keeps_existing_settings_and_is_idempotent(project):
    (project / ".claude").mkdir()
    user_hook = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo mine"}]}
    (project / ".claude" / "settings.json").write_text(json.dumps({
        "permissions": {"allow": ["Bash(npm test)"], "deny": ["Read(./private.txt)"]},
        "hooks": {"PreToolUse": [user_hook]}, "model": "opus"}))
    (project / ".cursorignore").write_text("node_modules/\n")
    assert init(project, "--agents", "claude,cursor") == 0
    first = (project / ".claude" / "settings.json").read_text()
    assert init(project, "--agents", "claude,cursor") == 0
    assert (project / ".claude" / "settings.json").read_text() == first
    data = json.loads(first)
    assert data["model"] == "opus"
    assert data["permissions"]["allow"] == ["Bash(npm test)"]
    assert data["permissions"]["deny"][0] == "Read(./private.txt)"
    assert data["hooks"]["PreToolUse"][0] == user_hook
    assert sum(agents.HOOK_MARK in json.dumps(g) for g in data["hooks"]["PreToolUse"]) == 1
    ignore = (project / ".cursorignore").read_text()
    assert ignore.startswith("node_modules/\n") and ignore.count(agents.BLOCK_START) == 1


def test_broken_json_is_left_alone(project, capsys):
    (project / ".gemini").mkdir()
    (project / ".gemini" / "settings.json").write_text("{ // comments are not JSON\n}")
    assert init(project, "--agents", "claude,gemini") == 1
    assert "can't parse" in capsys.readouterr().out
    assert (project / ".gemini" / "settings.json").read_text().startswith("{ //")
    assert (project / ".claude" / "settings.json").exists()


def test_dry_run_writes_nothing(project):
    before = sorted(os.listdir(str(project)))
    assert init(project, "--agents", ALL_HOOKS, "--dry-run") == 0
    assert sorted(os.listdir(str(project))) == before


def test_init_finds_secrets_inside_files(project, capsys):
    (project / "settings.yml").write_text("stripe:\n  key: sk_live_%s\n" % ("a1B2c3D4e5F6g7H8i9J0k1L2"))
    (project / "src" / "keys.py").write_text('AWS = "AKIAQWERTYUIOPASDFGH"\n')
    assert init(project, "--agents", "claude") == 0
    out = capsys.readouterr().out
    assert "settings.yml" in out and "Stripe live key" in out
    assert "src/keys.py line 1" in out
    assert "/settings.yml" in (project / ".secretwall" / "rules").read_text()
    assert "config/credentials.json is not in .gitignore" in out


def test_sandbox_rules(project):
    assert init(project, "--agents", "claude", "--sandbox") == 0
    deny_read = load(project / ".claude" / "settings.json")["sandbox"]["filesystem"]["denyRead"]
    assert "./.env" in deny_read
    assert "enabled" not in load(project / ".claude" / "settings.json")["sandbox"]


def test_remove(project, capsys):
    (project / ".gemini").mkdir()
    (project / ".gemini" / "settings.json").write_text('{"theme": "dark"}')
    (project / ".cursorignore").write_text("node_modules/\n")
    assert init(project, "--agents", ALL_HOOKS + ",aider") == 0
    assert cli.main(["remove", "--root", str(project)]) == 0
    assert load(project / ".gemini" / "settings.json") == {"theme": "dark"}
    assert (project / ".cursorignore").read_text() == "node_modules/\n"
    for gone in (".claude/settings.json", ".codex/hooks.json", ".github/hooks/secretwall.json",
                 ".cursor/hooks.json", ".windsurf/hooks.json", ".aiderignore", ".geminiignore"):
        assert not (project / gone).exists(), gone
    assert (project / ".secretwall").exists()
    assert cli.main(["remove", "--root", str(project), "--purge"]) == 0
    assert not (project / ".secretwall").exists()


def test_doctor(project, capsys):
    assert cli.main(["doctor", "--root", str(project)]) == 1  # not set up yet
    assert init(project, "--agents", ALL_HOOKS + ",aider") == 0
    capsys.readouterr()
    assert cli.main(["doctor", "--root", str(project), "--python", sys.executable]) == 0
    out = capsys.readouterr().out
    assert out.count("blocks secret reads and shell commands") == 6
    assert "All good" in out


def test_doctor_spots_stale_ignore_file(project, capsys):
    init(project, "--agents", "aider")
    with open(str(project / ".secretwall" / "rules"), "a") as fh:
        fh.write("extra-secret.txt\n")
    capsys.readouterr()
    cli.main(["doctor", "--root", str(project), "--python", sys.executable])
    assert "out of date" in capsys.readouterr().out


def test_check(project, monkeypatch, capsys):
    monkeypatch.chdir(str(project))
    assert cli.main(["check", "--root", str(project), ".env"]) == 1
    assert cli.main(["check", "--root", str(project), ".env.example"]) == 0
    assert cli.main(["check", "--root", str(project), "cat .env | head -1"]) == 1
    assert cli.main(["check", "--root", str(project), "-c", "ls"]) == 0
    out = capsys.readouterr().out
    assert "Blocked" in out and "Allowed" in out


def test_unknown_agent(project, capsys):
    assert init(project, "--agents", "notepad") == 2
    assert "Unknown agent" in capsys.readouterr().out


def test_version(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert H.VERSION in capsys.readouterr().out
