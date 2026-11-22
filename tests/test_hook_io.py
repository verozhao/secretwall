"""Run hook.py as the agents do: JSON on stdin, answer on stdout, exit code."""
import json
import os
import shutil
import subprocess
import sys

import pytest

from secretwall import cli

HOOK = cli.hook_source()


@pytest.fixture
def installed(project):
    folder = project / ".secretwall"
    folder.mkdir()
    shutil.copyfile(HOOK, str(folder / "hook.py"))
    return project


def call(project, agent, payload, raw=None):
    proc = subprocess.run([sys.executable, "-I", str(project / ".secretwall" / "hook.py"), agent],
                          input=raw if raw is not None else json.dumps(payload),
                          capture_output=True, text=True, cwd=str(project), timeout=30)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def test_claude(installed):
    env = str(installed / ".env")
    code, out, err = call(installed, "claude", {"hook_event_name": "PreToolUse", "tool_name": "Read",
                                                "tool_input": {"file_path": env}, "cwd": str(installed)})
    assert code == 2
    body = json.loads(out)["hookSpecificOutput"]
    assert body["hookEventName"] == "PreToolUse"
    assert body["permissionDecision"] == "deny"
    assert "secretwall blocked this" in body["permissionDecisionReason"]
    assert "secretwall blocked this" in err
    code, out, _ = call(installed, "claude", {"tool_name": "Bash", "tool_input": {"command": "ls"},
                                              "cwd": str(installed)})
    assert (code, out) == (0, "")


def test_codex(installed):
    code, out, _ = call(installed, "codex", {"tool_name": "Bash", "tool_input": {"command": "cat .env"},
                                             "cwd": str(installed)})
    assert code == 2
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_copilot(installed):
    code, out, _ = call(installed, "copilot", {"toolName": "view", "toolArgs": json.dumps(
        {"path": str(installed / ".env")}), "cwd": str(installed), "timestamp": 1})
    assert code == 2
    body = json.loads(out)
    assert body["permissionDecision"] == "deny" and body["permissionDecisionReason"]
    code, out, _ = call(installed, "copilot", {"toolName": "bash", "toolArgs": json.dumps({"command": "ls"}),
                                               "cwd": str(installed)})
    assert (code, out) == (0, "")


def test_cursor(installed):
    code, out, _ = call(installed, "cursor", {"hook_event_name": "beforeShellExecution", "command": "cat .env",
                                              "cwd": str(installed)})
    assert code == 2
    body = json.loads(out)
    assert body["permission"] == "deny" and body["user_message"] and body["agent_message"]
    code, out, _ = call(installed, "cursor", {"hook_event_name": "beforeShellExecution", "command": "ls",
                                              "cwd": str(installed)})
    assert code == 0 and json.loads(out) == {"permission": "allow"}


def test_gemini(installed):
    code, out, _ = call(installed, "gemini", {"hook_event_name": "BeforeTool", "tool_name": "read_file",
                                              "tool_input": {"file_path": ".env"}, "cwd": str(installed)})
    assert code == 2
    body = json.loads(out)
    assert body["decision"] == "deny" and body["reason"]
    code, out, _ = call(installed, "gemini", {"hook_event_name": "BeforeTool", "tool_name": "read_file",
                                              "tool_input": {"file_path": "src/app.py"}, "cwd": str(installed)})
    assert code == 0 and json.loads(out) == {"decision": "allow"}


def test_windsurf(installed):
    code, out, err = call(installed, "windsurf", {"agent_action_name": "pre_read_code",
                                                  "tool_info": {"file_path": str(installed / ".env")}})
    assert code == 2 and out == "" and "secretwall" in err


def test_auto_detects_agent(installed):
    code, out, _ = call(installed, "auto", {"hook_event_name": "beforeReadFile",
                                            "file_path": str(installed / ".env")})
    assert code == 2 and json.loads(out)["permission"] == "deny"


@pytest.mark.parametrize("raw", ["", "not json", "[1, 2]", '{"tool_name": 5}'])
def test_bad_input_is_allowed(installed, raw):
    code, out, _ = call(installed, "claude", None, raw=raw)
    assert (code, out) == (0, "")
    code, out, _ = call(installed, "cursor", None, raw=raw)
    assert code == 0 and json.loads(out) == {"permission": "allow"}


def test_log_has_reason_not_secret(installed):
    call(installed, "claude", {"tool_name": "Bash", "tool_input": {"command": "cat .env"}, "cwd": str(installed)})
    log = (installed / ".secretwall" / "blocked.log").read_text()
    assert "claude" in log and ".env" in log
    assert "sk-proj" not in log


def test_rules_file_and_config_are_read(installed):
    (installed / ".secretwall" / "rules").write_text("src/app.py\n")
    (installed / ".secretwall" / "config.json").write_text('{"log": false}')
    code, _, _ = call(installed, "claude", {"tool_name": "Read", "tool_input": {
        "file_path": str(installed / "src" / "app.py")}, "cwd": str(installed)})
    assert code == 2
    code, _, _ = call(installed, "claude", {"tool_name": "Read", "tool_input": {
        "file_path": str(installed / ".env")}, "cwd": str(installed)})
    assert code == 0  # .env is not in this custom rules file
    assert not os.path.exists(str(installed / ".secretwall" / "blocked.log"))
