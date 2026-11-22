"""Connect each AI coding agent to the secretwall hook.

Every agent gets its own config file. We merge into existing files, never
overwrite them, and we can take our entries out again (`secretwall remove`).
"""
from __future__ import annotations

import json
import os
import shutil

from .hook import _GLOB_CHARS

HOOK_MARK = ".secretwall/hook.py"
BLOCK_START = "# >>> secretwall >>>"
BLOCK_END = "# <<< secretwall <<<"
BLOCK_NOTE = "# Managed by secretwall. Edit .secretwall/rules, then run `secretwall init`."

CLAUDE_MATCHER = "Bash|PowerShell|Read|Edit|Write|MultiEdit|NotebookEdit|Grep"
CODEX_MATCHER = "^(Bash|apply_patch)$"
GEMINI_MATCHER = ("^(run_shell_command|read_file|read_many_files|write_file|replace|edit"
                  "|grep_search|search_file_content)$")


class Agent:
    def __init__(self, key, name, markers=(), home_markers=(), commands=(), ignore_file=None,
                 hooks=True, note=""):
        self.key = key
        self.name = name
        self.markers = markers
        self.home_markers = home_markers
        self.commands = commands
        self.ignore_file = ignore_file
        self.hooks = hooks
        self.note = note


AGENTS = [
    Agent("claude", "Claude Code", (".claude", "CLAUDE.md"), (".claude",), ("claude",)),
    Agent("codex", "Codex CLI", (".codex",), (".codex",), ("codex",),
          note="Approve the hook once: run /hooks in Codex."),
    Agent("copilot", "GitHub Copilot CLI", (".github/copilot-instructions.md", ".github/hooks",
                                            ".github/copilot"), (".copilot",), ("copilot",)),
    Agent("cursor", "Cursor", (".cursor", ".cursorrules", ".cursorignore"), (".cursor",),
          ("cursor", "cursor-agent"), ".cursorignore"),
    Agent("gemini", "Gemini CLI", (".gemini", "GEMINI.md", ".geminiignore"), (".gemini",), ("gemini",),
          ".geminiignore", note="Gemini CLI asks you to trust project hooks once."),
    Agent("windsurf", "Windsurf", (".windsurf", ".windsurfrules", ".codeiumignore"),
          (".codeium/windsurf",), ("windsurf",), ".codeiumignore"),
    Agent("jetbrains", "JetBrains AI / Junie", (".aiignore", ".junie"), (), (), ".aiignore", hooks=False),
    Agent("aider", "Aider", (".aiderignore", ".aider.conf.yml", ".aider.chat.history.md"), (),
          ("aider",), ".aiderignore", hooks=False),
    Agent("cline", "Cline", (".clineignore", ".clinerules"), (), (), ".clineignore", hooks=False),
    Agent("roo", "Roo Code", (".rooignore", ".roo", ".roomodes"), (), (), ".rooignore", hooks=False),
]
BY_KEY = {a.key: a for a in AGENTS}
HOOK_AGENTS = [a.key for a in AGENTS if a.hooks]


def detect(root, home):
    """Agents in use: {key: "project" | "installed"}."""
    found = {}
    for a in AGENTS:
        if any(os.path.exists(os.path.join(root, m)) for m in a.markers):
            found[a.key] = "project"
        elif any(os.path.exists(os.path.join(home, m)) for m in a.home_markers) or any(
                shutil.which(c) for c in a.commands):
            found[a.key] = "installed"
    return found


# ---------------------------------------------------------------------------
# Hook commands
# ---------------------------------------------------------------------------

_GIT_ROOT = "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
_ROOTS = {
    "claude": "${CLAUDE_PROJECT_DIR:-%s}" % _GIT_ROOT,
    "gemini": "${GEMINI_PROJECT_DIR:-%s}" % _GIT_ROOT,
}
_ALLOW_JSON = {"cursor": '{"permission": "allow"}', "gemini": '{"decision": "allow"}'}


def posix_command(agent, python="python3"):
    """Shell command for macOS/Linux. Exit 2 means blocked.

    If Python or the hook file is missing, it allows the action instead of
    breaking the agent (and prints the "allow" answer the agent expects).
    """
    exe = python.split()[0]
    run = 'f="%s/%s"; if [ -f "$f" ] && command -v %s >/dev/null 2>&1; then %s -I "$f" %s' % (
        _ROOTS.get(agent, _GIT_ROOT), HOOK_MARK, exe, python, agent)
    allow = _ALLOW_JSON.get(agent)
    if allow:
        return run + " && exit 0; [ $? -eq 2 ] && exit 2; fi; echo '%s'" % allow
    return run + "; [ $? -eq 2 ] && exit 2; fi; exit 0"


def powershell_command(agent, python="python"):
    """Command for Windows PowerShell. Untested; it allows the action on any error."""
    exe = python.split()[0]
    return ('$f = ".secretwall/hook.py"; $r = (git rev-parse --show-toplevel 2>$null); '
            'if ($r) { $f = Join-Path $r ".secretwall/hook.py" }; '
            'if ((Test-Path $f) -and (Get-Command %s -ErrorAction SilentlyContinue)) '
            '{ $input | & %s -I $f %s; if ($LASTEXITCODE -eq 2) { exit 2 } }; exit 0') % (exe, python, agent)


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

class SetupError(Exception):
    pass


def read_json(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise SetupError("can't read %s: %s" % (path, exc))
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise SetupError("can't parse %s (%s). Fix it or remove it, then run init again." % (path, exc))
    if not isinstance(data, dict):
        raise SetupError("%s is not a JSON object" % path)
    return data


def write_text(path, text, dry_run):
    try:
        with open(path, encoding="utf-8") as fh:
            if fh.read() == text:
                return False
    except OSError:
        pass
    if not dry_run:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return True


def write_json(path, data, dry_run):
    return write_text(path, json.dumps(data, indent=2) + "\n", dry_run)


def _ours(entry):
    return HOOK_MARK in json.dumps(entry)


def _strip_groups(groups):
    """Remove our hooks from a list of {matcher, hooks: [...]} groups."""
    out = []
    for g in groups if isinstance(groups, list) else []:
        if isinstance(g, dict) and isinstance(g.get("hooks"), list):
            kept = [h for h in g["hooks"] if not _ours(h)]
            if not kept:
                continue
            if len(kept) != len(g["hooks"]):
                g = dict(g, hooks=kept)
        elif _ours(g):
            continue
        out.append(g)
    return out


def _dict_at(data, key, path):
    value = data.get(key)
    if value is None:
        value = {}
        data[key] = value
    if not isinstance(value, dict):
        raise SetupError('"%s" in %s is not an object' % (key, path))
    return value


def _list_at(data, key, path):
    value = data.get(key)
    if value is None:
        value = []
        data[key] = value
    if not isinstance(value, list):
        raise SetupError('"%s" in %s is not a list' % (key, path))
    return value


def write_block(path, lines, dry_run):
    """Put our lines between markers in an ignore file. Keeps everything else."""
    try:
        with open(path, encoding="utf-8") as fh:
            existing = fh.read()
    except OSError:
        existing = ""
    block = "\n".join([BLOCK_START, BLOCK_NOTE] + list(lines) + [BLOCK_END])
    if BLOCK_START in existing and BLOCK_END in existing:
        before, rest = existing.split(BLOCK_START, 1)
        after = rest.split(BLOCK_END, 1)[1]
        new = before + block + after
    else:
        sep = "" if not existing else ("\n" if existing.endswith("\n") else "\n\n")
        new = existing + sep + block + "\n"
    return write_text(path, new, dry_run)


def remove_block(path, dry_run):
    try:
        with open(path, encoding="utf-8") as fh:
            existing = fh.read()
    except OSError:
        return False
    if BLOCK_START not in existing or BLOCK_END not in existing:
        return False
    before, rest = existing.split(BLOCK_START, 1)
    after = rest.split(BLOCK_END, 1)[1]
    new = (before.rstrip("\n") + "\n" + after.lstrip("\n")).strip("\n")
    if not dry_run:
        if new.strip():
            write_text(path, new + "\n", dry_run)
        else:
            os.remove(path)
    return True


def block_lines(path):
    """Our lines in an ignore file, or None if there is no block."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None
    if BLOCK_START not in text or BLOCK_END not in text:
        return None
    inner = text.split(BLOCK_START, 1)[1].split(BLOCK_END, 1)[0]
    return [ln for ln in inner.splitlines() if ln.strip() and ln != BLOCK_NOTE]


# ---------------------------------------------------------------------------
# Claude Code deny rules
# ---------------------------------------------------------------------------

CORE_PATTERNS = {".env", "*.env", "*.pem", "*.key", "id_rsa", "id_ed25519", "credentials.json"}


def claude_deny_rules(rules, secret_files):
    """Turn our rules into Claude Code `Read(...)`/`Edit(...)` deny rules.

    A second layer under the hook: it works even if Python is missing.
    We keep the list short: common patterns plus patterns that match a file
    in this project. Rules that have exceptions (like `.env.*` with
    `!.env.example`) can't be deny rules, so we list the matching files instead.
    """
    negations = [r for r in rules.rules if r.negate]
    generic = []
    out = []
    for r in rules.rules:
        if r.negate:
            continue
        if any(_GLOB_CHARS.search(n.pattern) or r.regex.match(n.pattern) for n in negations):
            continue
        if r.pattern not in CORE_PATTERNS and not any(r.regex.match(f) for f in secret_files):
            continue
        spec = ("/" + r.pattern) if r.anchored else ("**/" + r.pattern)
        if r.dir_only:
            spec += "/**"
        generic.append(r)
        out += ["Read(%s)" % spec, "Edit(%s)" % spec]
    for rel in secret_files:
        if any(r.regex.match(rel) for r in generic):
            continue
        out += ["Read(/%s)" % rel, "Edit(/%s)" % rel]
    seen, unique = set(), []
    for item in out:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


# ---------------------------------------------------------------------------
# Install / remove per agent
# ---------------------------------------------------------------------------

class Context:
    def __init__(self, root, rules, rule_lines, secret_files, python="python3",
                 ps_python="python", sandbox=False, dry_run=False):
        self.root = root
        self.rules = rules
        self.rule_lines = rule_lines
        self.secret_files = secret_files  # paths relative to root
        self.python = python
        self.ps_python = ps_python
        self.sandbox = sandbox
        self.dry_run = dry_run

    def path(self, *parts):
        return os.path.join(self.root, *parts)


def _install_claude(ctx):
    path = ctx.path(".claude", "settings.json")
    data = read_json(path)
    hooks = _dict_at(data, "hooks", path)
    groups = _strip_groups(hooks.get("PreToolUse", []))
    groups.append({"matcher": CLAUDE_MATCHER, "hooks": [
        {"type": "command", "command": posix_command("claude", ctx.python), "timeout": 10}]})
    hooks["PreToolUse"] = groups
    perms = _dict_at(data, "permissions", path)
    deny = _list_at(perms, "deny", path)
    added = 0
    for rule in claude_deny_rules(ctx.rules, ctx.secret_files):
        if rule not in deny:
            deny.append(rule)
            added += 1
    detail = "hook + deny rules"
    if ctx.sandbox:
        sandbox = _dict_at(data, "sandbox", path)
        fs = _dict_at(sandbox, "filesystem", path)
        deny_read = _list_at(fs, "denyRead", path)
        for rel in ctx.secret_files:
            if "./" + rel not in deny_read:
                deny_read.append("./" + rel)
        detail += " + sandbox rules"
    write_json(path, data, ctx.dry_run)
    return [".claude/settings.json"], detail


def _install_codex(ctx):
    path = ctx.path(".codex", "hooks.json")
    data = read_json(path)
    hooks = _dict_at(data, "hooks", path)
    groups = _strip_groups(hooks.get("PreToolUse", []))
    groups.append({"matcher": CODEX_MATCHER, "hooks": [
        {"type": "command", "command": posix_command("codex", ctx.python),
         "commandWindows": powershell_command("codex", ctx.ps_python), "timeout": 10}]})
    hooks["PreToolUse"] = groups
    write_json(path, data, ctx.dry_run)
    return [".codex/hooks.json"], "hook"


def _install_copilot(ctx):
    path = ctx.path(".github", "hooks", "secretwall.json")
    data = {"version": 1, "hooks": {"preToolUse": [
        {"type": "command", "bash": posix_command("copilot", ctx.python),
         "powershell": powershell_command("copilot", ctx.ps_python), "cwd": ".", "timeoutSec": 10}]}}
    write_json(path, data, ctx.dry_run)
    return [".github/hooks/secretwall.json"], "hook"


def _install_cursor(ctx):
    path = ctx.path(".cursor", "hooks.json")
    data = read_json(path)
    data.setdefault("version", 1)
    hooks = _dict_at(data, "hooks", path)
    for event in ("beforeShellExecution", "beforeReadFile"):
        entries = [e for e in hooks.get(event, []) if not _ours(e)] if isinstance(hooks.get(event), list) else []
        entries.append({"command": posix_command("cursor", ctx.python), "timeout": 10})
        hooks[event] = entries
    write_json(path, data, ctx.dry_run)
    return [".cursor/hooks.json"], "hooks"


def _install_gemini(ctx):
    path = ctx.path(".gemini", "settings.json")
    data = read_json(path)
    hooks = _dict_at(data, "hooks", path)
    groups = _strip_groups(hooks.get("BeforeTool", []))
    groups.append({"matcher": GEMINI_MATCHER, "hooks": [
        {"name": "secretwall", "type": "command", "command": posix_command("gemini", ctx.python),
         "timeout": 10000, "description": "Blocks AI access to secret files"}]})
    hooks["BeforeTool"] = groups
    write_json(path, data, ctx.dry_run)
    return [".gemini/settings.json"], "hook"


def _install_windsurf(ctx):
    path = ctx.path(".windsurf", "hooks.json")
    data = read_json(path)
    hooks = _dict_at(data, "hooks", path)
    for event in ("pre_read_code", "pre_write_code", "pre_run_command"):
        entries = [e for e in hooks.get(event, []) if not _ours(e)] if isinstance(hooks.get(event), list) else []
        entries.append({"command": posix_command("windsurf", ctx.python),
                        "powershell": powershell_command("windsurf", ctx.ps_python)})
        hooks[event] = entries
    write_json(path, data, ctx.dry_run)
    return [".windsurf/hooks.json"], "hooks"


_INSTALLERS = {
    "claude": _install_claude,
    "codex": _install_codex,
    "copilot": _install_copilot,
    "cursor": _install_cursor,
    "gemini": _install_gemini,
    "windsurf": _install_windsurf,
}


def install(key, ctx):
    """Set up one agent. Returns (files, detail). Raises SetupError."""
    agent = BY_KEY[key]
    files, details = [], []
    if key in _INSTALLERS:
        f, d = _INSTALLERS[key](ctx)
        files += f
        details.append(d)
    if agent.ignore_file:
        write_block(ctx.path(agent.ignore_file), ctx.rule_lines, ctx.dry_run)
        files.append(agent.ignore_file)
        details.append("ignore file")
    return files, " + ".join(details)


def _remove_from_json(path, edit, dry_run):
    if not os.path.exists(path):
        return False
    data = read_json(path)
    before = json.dumps(data, sort_keys=True)
    edit(data)
    if json.dumps(data, sort_keys=True) == before:
        return False
    if not dry_run:
        if data:
            write_json(path, data, dry_run)
        else:
            os.remove(path)
    return True


def _drop_groups(container, event):
    groups = _strip_groups(container.get(event, []))
    if groups:
        container[event] = groups
    else:
        container.pop(event, None)


def _drop_entries(container, event):
    entries = [e for e in container.get(event, []) if not _ours(e)] if isinstance(container.get(event), list) else []
    if entries:
        container[event] = entries
    else:
        container.pop(event, None)


def remove(key, ctx):
    """Take our entries out of one agent's files. Returns the files changed."""
    changed = []

    def tidy(data, key_name):
        if isinstance(data.get(key_name), dict) and not data[key_name]:
            del data[key_name]

    if key == "claude":
        deny_rules = set(claude_deny_rules(ctx.rules, ctx.secret_files))

        def edit(data):
            hooks = data.get("hooks")
            if isinstance(hooks, dict):
                _drop_groups(hooks, "PreToolUse")
                tidy(data, "hooks")
            perms = data.get("permissions")
            if isinstance(perms, dict) and isinstance(perms.get("deny"), list):
                perms["deny"] = [r for r in perms["deny"] if r not in deny_rules]
                if not perms["deny"]:
                    del perms["deny"]
                tidy(data, "permissions")
            fs = data.get("sandbox", {}).get("filesystem", {}) if isinstance(data.get("sandbox"), dict) else {}
            if isinstance(fs, dict) and isinstance(fs.get("denyRead"), list):
                ours = {"./" + rel for rel in ctx.secret_files}
                fs["denyRead"] = [p for p in fs["denyRead"] if p not in ours]
                if not fs["denyRead"]:
                    del fs["denyRead"]
                tidy(data["sandbox"], "filesystem")
                tidy(data, "sandbox")
        if _remove_from_json(ctx.path(".claude", "settings.json"), edit, ctx.dry_run):
            changed.append(".claude/settings.json")
    elif key in ("codex", "gemini"):
        rel = (".codex", "hooks.json") if key == "codex" else (".gemini", "settings.json")
        event = "PreToolUse" if key == "codex" else "BeforeTool"

        def edit(data):
            hooks = data.get("hooks")
            if isinstance(hooks, dict):
                _drop_groups(hooks, event)
                tidy(data, "hooks")
        if _remove_from_json(ctx.path(*rel), edit, ctx.dry_run):
            changed.append("/".join(rel))
    elif key == "copilot":
        path = ctx.path(".github", "hooks", "secretwall.json")
        if os.path.exists(path):
            if not ctx.dry_run:
                os.remove(path)
            changed.append(".github/hooks/secretwall.json")
    elif key in ("cursor", "windsurf"):
        rel = (".cursor", "hooks.json") if key == "cursor" else (".windsurf", "hooks.json")
        events = (("beforeShellExecution", "beforeReadFile") if key == "cursor"
                  else ("pre_read_code", "pre_write_code", "pre_run_command"))

        def edit(data):
            hooks = data.get("hooks")
            if isinstance(hooks, dict):
                for event in events:
                    _drop_entries(hooks, event)
                tidy(data, "hooks")
            if key == "cursor" and list(data.keys()) == ["version"]:
                data.clear()
        if _remove_from_json(ctx.path(*rel), edit, ctx.dry_run):
            changed.append("/".join(rel))
    agent = BY_KEY[key]
    if agent.ignore_file and remove_block(ctx.path(agent.ignore_file), ctx.dry_run):
        changed.append(agent.ignore_file)
    return changed


def configured(key, root):
    """Is this agent set up in the project? Returns True/False."""
    paths = {
        "claude": (".claude", "settings.json"),
        "codex": (".codex", "hooks.json"),
        "copilot": (".github", "hooks", "secretwall.json"),
        "cursor": (".cursor", "hooks.json"),
        "gemini": (".gemini", "settings.json"),
        "windsurf": (".windsurf", "hooks.json"),
    }
    agent = BY_KEY[key]
    if key in paths:
        path = os.path.join(root, *paths[key])
        try:
            with open(path, encoding="utf-8") as fh:
                return HOOK_MARK in fh.read()
        except OSError:
            return False
    return block_lines(os.path.join(root, agent.ignore_file)) is not None
