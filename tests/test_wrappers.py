"""The shell commands we put in each agent's config must never break the agent."""
import json
import os
import shutil
import subprocess
import sys

import pytest

from secretwall import agents, cli

pytestmark = pytest.mark.skipif(not shutil.which("sh"), reason="needs sh")
HOOK_AGENTS = ["claude", "codex", "copilot", "cursor", "gemini", "windsurf"]
ALLOW_JSON = {"cursor": {"permission": "allow"}, "gemini": {"decision": "allow"}}


def payload(agent, project, command):
    p = str(project)
    if agent == "copilot":
        return {"toolName": "bash", "toolArgs": json.dumps({"command": command}), "cwd": p}
    if agent == "cursor":
        return {"hook_event_name": "beforeShellExecution", "command": command, "cwd": p}
    if agent == "windsurf":
        return {"agent_action_name": "pre_run_command", "tool_info": {"command_line": command, "cwd": p}}
    if agent == "gemini":
        return {"hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
                "tool_input": {"command": command}, "cwd": p}
    return {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": p}


def run(agent, project, command, python=sys.executable, cwd=None, env_extra=None):
    env = dict(os.environ)
    env.pop("CLAUDE_PROJECT_DIR", None)
    env.pop("GEMINI_PROJECT_DIR", None)
    env.update(env_extra or {})
    proc = subprocess.run(["sh", "-c", agents.posix_command(agent, python)],
                          input=json.dumps(payload(agent, cwd or project, command)), capture_output=True,
                          text=True, cwd=str(cwd or project), env=env, timeout=30)
    return proc.returncode, proc.stdout.strip()


def install(project):
    (project / ".secretwall").mkdir(exist_ok=True)
    shutil.copyfile(cli.hook_source(), str(project / ".secretwall" / "hook.py"))


@pytest.mark.parametrize("agent", HOOK_AGENTS)
def test_blocks_and_allows(project, agent):
    install(project)
    assert run(agent, project, "cat .env")[0] == 2
    code, out = run(agent, project, "ls")
    assert code == 0
    if agent in ALLOW_JSON:
        assert json.loads(out) == ALLOW_JSON[agent]


@pytest.mark.parametrize("agent", HOOK_AGENTS)
def test_works_from_a_subfolder(project, agent):
    install(project)
    assert run(agent, project, "cat ../.env", cwd=project / "src")[0] == 2


@pytest.mark.parametrize("agent", HOOK_AGENTS)
def test_missing_hook_allows(project, agent):
    code, out = run(agent, project, "cat .env")
    assert code == 0
    if agent in ALLOW_JSON:
        assert json.loads(out) == ALLOW_JSON[agent]


@pytest.mark.parametrize("agent", HOOK_AGENTS)
def test_missing_python_allows(project, agent):
    install(project)
    code, out = run(agent, project, "cat .env", python="no-such-python-here")
    assert code == 0
    if agent in ALLOW_JSON:
        assert json.loads(out) == ALLOW_JSON[agent]


@pytest.mark.parametrize("agent", HOOK_AGENTS)
def test_broken_hook_allows(project, agent):
    install(project)
    (project / ".secretwall" / "hook.py").write_text("this is not python (\n")
    code, out = run(agent, project, "cat .env")
    assert code == 0
    if agent in ALLOW_JSON:
        assert json.loads(out) == ALLOW_JSON[agent]


def test_claude_uses_project_dir(project, tmp_path):
    install(project)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / ".env").write_text("A=1\n")
    code, _ = run("claude", elsewhere, "cat .env", cwd=elsewhere,
                  env_extra={"CLAUDE_PROJECT_DIR": str(project)})
    assert code == 2
