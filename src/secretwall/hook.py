#!/usr/bin/env python3
"""secretwall hook: stops AI coding agents from reading your secrets.

`secretwall init` copies this file to .secretwall/hook.py in your project.
Your AI agents run it before each tool call (open a file, run a command).
It reads the tool call as JSON on stdin and blocks the call when it would
show a secret to the agent.

Standard library only. Runs on Python 3.9 and newer.

    python3 -I .secretwall/hook.py <claude|codex|copilot|cursor|gemini|windsurf>

Exit code 2 means "blocked". Every agent above treats exit code 2 as a block.
"""
from __future__ import annotations

import fnmatch
import glob as globmod
import itertools
import json
import os
import re
import shlex
import subprocess
import sys
import time

VERSION = "0.1.0"

DIR_NAME = ".secretwall"
RULES_FILE = "rules"
CONFIG_FILE = "config.json"
LOG_FILE = "blocked.log"

DEFAULT_RULES = """\
# secretwall rules: files that AI agents must not read or change.
# Same syntax as .gitignore. A line that starts with ! allows a file again.
# The hook reads this file on every check. After you edit it, run
# `secretwall init` again so the agents' ignore files match.

# Environment files
*.env
.env
.env.*
.envrc
.dev.vars
.secrets
*.secret
!.env.example
!.env.sample
!.env.template
!.env.dist
!.env.defaults
!.env.schema

# Private keys and certificates
*.pem
*.key
*.p8
*.p12
*.pfx
*.jks
*.keystore
*.ppk
id_rsa
id_dsa
id_ecdsa
id_ed25519

# Credential files
credentials.json
credentials.yml
credentials.yaml
client_secret*.json
service-account*.json
*-service-account.json
secrets.json
secrets.yml
secrets.yaml
secrets.toml
kubeconfig
*.kubeconfig
.netrc
.pypirc
.git-credentials
.htpasswd
.vault-token
*.tfvars
*.tfstate
*.tfstate.backup
"""

# Secret files in your home folder. A leading / means "only at the top of ~".
HOME_RULES = """\
/.ssh/*
!/.ssh/*.pub
!/.ssh/known_hosts
!/.ssh/known_hosts.old
!/.ssh/config
!/.ssh/authorized_keys
/.aws/credentials
/.aws/sso/cache/
/.aws/cli/cache/
/.config/gcloud/
/.azure/
/.kube/config
/.docker/config.json
/.netrc
/.npmrc
/.pypirc
/.git-credentials
/.gnupg/
/.config/gh/hosts.yml
/.terraform.d/credentials.tfrc.json
/.vault-token
/.cargo/credentials
/.cargo/credentials.toml
/.gem/credentials
/.claude/.credentials.json
/.codex/auth.json
/.gemini/oauth_creds.json
"""

DEFAULT_CONFIG = {
    "protect_home": True,           # also guard ~/.ssh, ~/.aws/credentials and similar
    "block_env_dump": True,         # block `env`, `printenv` and code that prints every variable
    "block_secret_vars": True,      # block printing variables with secret-looking names
    "block_secret_commands": True,  # block commands that print credentials (gh auth token, ...)
    "block_git_add": True,          # block staging secret files for a commit
    "log": True,                    # write blocked actions to .secretwall/blocked.log
}

# Folders we never walk into when we look for secret files.
PRUNE = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".nox", "dist",
    "build", "target", ".next", ".nuxt", ".svelte-kit", ".turbo", ".cache",
    ".parcel-cache", ".gradle", ".idea", "vendor", "Pods", "DerivedData",
    ".terraform", "coverage", ".yarn", ".pnpm-store",
}


# ---------------------------------------------------------------------------
# Rules (.gitignore syntax)
# ---------------------------------------------------------------------------

_SPECIAL = re.compile(r"[*?\[\\]")


class Rule:
    """One line of a rules file.

    Most rules are plain names (".env") or "*.ext". Those are matched with
    string operations; the rest use a regex that is compiled on first use.
    This keeps the hook fast, because it starts fresh on every tool call.
    """
    __slots__ = ("text", "pattern", "negate", "dir_only", "anchored", "kind", "a", "b", "_regex")

    def __init__(self, text, pattern, negate, dir_only, anchored):
        self.text = text
        self.pattern = pattern
        self.negate = negate
        self.dir_only = dir_only
        self.anchored = anchored
        self._regex = None
        self.kind, self.a, self.b = "regex", "", ""
        low = pattern.lower()
        if anchored:
            if not _SPECIAL.search(low):
                self.kind, self.a = "path", low
        elif not _SPECIAL.search(low):
            self.kind, self.a = "name", low
        elif low.count("*") == 1 and not _SPECIAL.search(low.replace("*", "")):
            head, tail = low.split("*")
            self.kind, self.a, self.b = "glob", head, tail

    @property
    def regex(self):
        if self._regex is None:
            self._regex = re.compile(_translate(self.pattern, self.anchored), re.I | re.S)
        return self._regex

    def test(self, low, base):
        """Does this rule match? `low` is the lowercased relative path, `base` its last part."""
        kind = self.kind
        if kind == "name":
            return base == self.a
        if kind == "glob":
            return len(base) >= len(self.a) + len(self.b) and base.startswith(self.a) and base.endswith(self.b)
        if kind == "path":
            return low == self.a
        return self.regex.match(low) is not None


def _translate(pat: str, anchored: bool) -> str:
    """Turn one .gitignore pattern into a regex for a /-separated relative path."""
    out = []
    i, n = 0, len(pat)
    while i < n:
        c = pat[i]
        if c == "*":
            if i + 1 < n and pat[i + 1] == "*":
                at_start = i == 0 or pat[i - 1] == "/"
                j = i + 2
                if at_start and j == n:            # "dir/**": everything inside
                    out.append(".*")
                    i = j
                    continue
                if at_start and pat[j:j + 1] == "/":  # "**/": any number of folders
                    out.append("(?:.*/)?")
                    i = j + 1
                    continue
                out.append("[^/]*")
                i = j
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = i + 1
            if j < n and pat[j] in "!^":
                j += 1
            if j < n and pat[j] == "]":
                j += 1
            while j < n and pat[j] != "]":
                j += 1
            if j >= n:
                out.append(re.escape(c))
            else:
                body = pat[i + 1:j]
                if body[:1] in ("!", "^"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j
        elif c == "\\" and i + 1 < n:
            i += 1
            out.append(re.escape(pat[i]))
        else:
            out.append(re.escape(c))
        i += 1
    body = "".join(out)
    return ("^" if anchored else "^(?:.*/)?") + body + "$"


class Rules:
    def __init__(self, rules):
        self.rules = list(rules)
        self._has_positive = any(not r.negate for r in self.rules)

    @classmethod
    def parse(cls, text: str) -> "Rules":
        rules = []
        for raw in text.splitlines():
            line = re.sub(r"(?<!\\)\s+$", "", raw)
            if not line or line.startswith("#"):
                continue
            negate = False
            if line.startswith("!"):
                negate, line = True, line[1:]
            elif line.startswith(("\\!", "\\#")):
                line = line[1:]
            dir_only = line.endswith("/")
            line = line.rstrip("/")
            if not line:
                continue
            anchored = "/" in line
            pattern = line[1:] if line.startswith("/") else line
            if not pattern:
                continue
            rules.append(Rule(raw.strip(), pattern, negate, dir_only, anchored))
        return cls(rules)

    def _last(self, rel, is_dir):
        low = rel.lower()
        base = low.rsplit("/", 1)[-1]
        hit = None
        for r in self.rules:
            if r.dir_only and not is_dir:
                continue
            if r.test(low, base):
                hit = r
        return hit

    def match(self, rel: str, is_dir: bool = False, parents: bool = True, dir_ok=None):
        """Return the rule that protects `rel` (a relative path), or None."""
        if not self._has_positive:
            return None
        rel = rel.replace("\\", "/").strip("/")
        if not rel or rel == ".":
            return None
        if parents and "/" in rel:
            parts = rel.split("/")
            for i in range(1, len(parts)):
                d = "/".join(parts[:i])
                r = self._last(d, True)
                if r is not None and not r.negate and (dir_ok is None or dir_ok(d)):
                    return r
        r = self._last(rel, is_dir)
        if r is None or r.negate:
            return None
        if is_dir and dir_ok is not None and not dir_ok(rel):
            return None
        return r


# ---------------------------------------------------------------------------
# Guard: is this path a secret?
# ---------------------------------------------------------------------------

_PROC_ENVIRON = re.compile(r"^/proc/[^/]+/environ$")


def _relative(path, base):
    """Path of `path` relative to `base` with / separators, or None if outside."""
    try:
        if os.path.normcase(os.path.commonpath([path, base])) != os.path.normcase(base):
            return None
    except ValueError:
        return None
    rel = os.path.relpath(path, base)
    return "" if rel == "." else rel.replace(os.sep, "/")


def _realpath(path):
    try:
        return os.path.realpath(path)
    except OSError:
        return path


def load_rules(root: str) -> Rules:
    try:
        with open(os.path.join(root, DIR_NAME, RULES_FILE), encoding="utf-8") as fh:
            return Rules.parse(fh.read())
    except OSError:
        return Rules.parse(DEFAULT_RULES)


def load_config(root: str) -> dict:
    config = dict(DEFAULT_CONFIG)
    try:
        with open(os.path.join(root, DIR_NAME, CONFIG_FILE), encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            config.update(data)
    except (OSError, ValueError):
        pass
    return config


class Guard:
    def __init__(self, root, rules=None, config=None, home=None):
        self.root = os.path.abspath(root)
        self.rules = rules if rules is not None else load_rules(self.root)
        self.config = dict(DEFAULT_CONFIG)
        self.config.update(config or {})
        self.home = os.path.abspath(home or os.path.expanduser("~"))
        self.outside = Rules([r for r in self.rules.rules if not r.anchored])
        self.home_rules = Rules.parse(HOME_RULES) if self.config.get("protect_home") else None
        self._ignored = {}
        self._tracked = None

    def _dir_ok(self, rel):
        # A Python virtualenv folder named ".env" is not a secret.
        return not os.path.exists(os.path.join(self.root, rel, "pyvenv.cfg"))

    def display(self, path):
        rel = _relative(path, self.root)
        if rel:
            return rel
        hrel = _relative(path, self.home)
        if hrel:
            return "~/" + hrel
        return path

    def expand_home(self, path):
        if path == "~" or path.startswith(("~/", "~\\")):
            return self.home + path[1:]
        return os.path.expanduser(path) if path.startswith("~") else path

    def check(self, path, is_dir=None):
        """Return (shown_path, rule) if `path` is a secret, else None."""
        path = os.path.abspath(self.expand_home(path))
        real = _realpath(path)
        for p in (path, real) if real != path else (path,):
            hit = self._check_one(p, is_dir)
            if hit:
                return hit
        return None

    def _check_one(self, p, is_dir):
        if is_dir is None:
            is_dir = os.path.isdir(p)
        rel = _relative(p, self.root)
        if rel is not None:
            r = self.rules.match(rel, is_dir, dir_ok=self._dir_ok)
            if r is not None:
                return rel or p, r.text
        else:
            r = self.outside.match(p.replace("\\", "/").lstrip("/"), is_dir)
            if r is not None:
                return self.display(p), r.text
        if self.home_rules is not None and (rel is None or self.root == self.home):
            hrel = _relative(p, self.home)
            if hrel:
                r = self.home_rules.match(hrel, is_dir)
                if r is not None:
                    return "~/" + hrel, "~" + r.text
        if _PROC_ENVIRON.match(p.replace("\\", "/")):
            return p, "process environment"
        return None

    def check_rel(self, rel):
        """Check a repo-relative path that may not exist (e.g. `git show HEAD:.env`)."""
        r = self.rules.match(rel[2:] if rel.startswith("./") else rel)
        return (rel, r.text) if r is not None else None

    def _fast(self, full, is_dir):
        rel = _relative(full, self.root)
        if rel is None:
            return self.check(full, is_dir) is not None
        return self.rules.match(rel, is_dir, parents=False, dir_ok=self._dir_ok) is not None

    @staticmethod
    def _files_in(folder, found, deadline, limit):
        for dirpath, _dirs, filenames in os.walk(folder):
            for name in filenames:
                found.append(os.path.join(dirpath, name))
                if len(found) >= limit or time.monotonic() > deadline:
                    return

    def protected_under(self, folders, budget=1.0, limit=200):
        """Secret files inside the given folders (walks the tree, skips heavy folders).

        Files inside a protected folder (like secrets/) are listed one by one.
        """
        found = []
        deadline = time.monotonic() + budget
        for folder in folders:
            folder = os.path.abspath(folder)
            if not os.path.isdir(folder):
                continue
            if self.check(folder, True):
                self._files_in(folder, found, deadline, limit)
                continue
            for dirpath, dirnames, filenames in os.walk(folder):
                if time.monotonic() > deadline or len(found) >= limit:
                    return found
                kept = []
                for name in dirnames:
                    full = os.path.join(dirpath, name)
                    if name in PRUNE or os.path.islink(full):
                        continue
                    if self._fast(full, True):
                        self._files_in(full, found, deadline, limit)
                        continue
                    kept.append(name)
                dirnames[:] = kept
                for name in filenames:
                    full = os.path.join(dirpath, name)
                    if self._fast(full, False):
                        found.append(full)
        return found

    # --- git helpers (used only for a few commands) ---

    def _git(self, args, data=None):
        try:
            res = subprocess.run(
                ["git", "-C", self.root] + args, input=data, capture_output=True, timeout=3
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if res.returncode not in (0, 1):
            return None
        return res.stdout

    def git_ignored(self, paths):
        """The subset of `paths` that git ignores."""
        todo = [p for p in paths if p not in self._ignored]
        if todo:
            out = self._git(["check-ignore", "--stdin", "-z"], "\0".join(todo).encode() + b"\0")
            ignored = set()
            if out:
                for item in out.decode(errors="replace").split("\0"):
                    if item:
                        ignored.add(os.path.abspath(os.path.join(self.root, item)))
            for p in todo:
                self._ignored[p] = os.path.abspath(p) in ignored
        return [p for p in paths if self._ignored.get(p)]

    def git_tracked(self):
        if self._tracked is None:
            out = self._git(["ls-files", "-z"])
            self._tracked = set()
            if out:
                for item in out.decode(errors="replace").split("\0"):
                    if item:
                        self._tracked.add(os.path.abspath(os.path.join(self.root, item)))
        return self._tracked


# ---------------------------------------------------------------------------
# Findings (why something was blocked)
# ---------------------------------------------------------------------------

_DOTENV_NAME = re.compile(r"(^|/)(\.env[^/]*|[^/]*\.env|\.envrc|\.dev\.vars)$")


class Finding:
    def __init__(self, reason, hint="", files=()):
        self.reason = reason
        self.hint = hint
        self.files = list(files)

    def message(self):
        text = "secretwall blocked this: " + self.reason
        return text + (" " + self.hint if self.hint else "")

    @classmethod
    def read(cls, hit):
        path, rule = hit
        hint = "Secret files are off-limits to AI agents here. If you need a value from it, ask the user."
        if _DOTENV_NAME.search(path) and not path.startswith("~"):
            hint += " To load it for a command without printing it, use: set -a; source %s; set +a" % path
        return cls("it would show %s, a secret file (rule `%s`)." % (path, rule), hint, [path])

    @classmethod
    def edit(cls, hit):
        path, rule = hit
        return cls("%s is a secret file (rule `%s`), so AI agents can't change it." % (path, rule),
                   "Ask the user to edit it.", [path])

    @classmethod
    def overwrite(cls, hit):
        return cls("it would overwrite %s, a secret file." % hit[0], "Ask the user to change it.", [hit[0]])

    @classmethod
    def env_dump(cls):
        return cls("it would print all environment variables, which can include secrets.",
                   "Print only the variable you need, if it is not a secret (for example: echo $NODE_ENV).")

    @classmethod
    def secret_var(cls, name):
        return cls("it would print $%s, which looks like a secret." % name,
                   "Use the variable in your command without printing it.")

    @classmethod
    def secret_command(cls, text, why):
        text = text if len(text) <= 60 else text[:57] + "..."
        return cls("`%s` %s." % (text, why), "If it is really needed, ask the user to run it.")

    @classmethod
    def search(cls, shown):
        listed = ", ".join(shown[:3]) + (" and %d more" % (len(shown) - 3) if len(shown) > 3 else "")
        return cls("the search would read secret files (%s)." % listed,
                   "Exclude them (for grep: --exclude='.env*'), or use rg, which skips hidden "
                   "and .gitignored files.", shown)

    @classmethod
    def git_add(cls, shown):
        return cls("it would stage secret files for a commit (%s)." % ", ".join(shown[:3]),
                   "Add them to .gitignore instead.", shown)


# ---------------------------------------------------------------------------
# Tool calls: turn each agent's JSON into paths and commands
# ---------------------------------------------------------------------------

SHELL_TOOLS = {
    "bash", "shell", "sh", "zsh", "powershell", "pwsh", "run_shell_command", "exec",
    "exec_command", "local_shell", "unified_exec", "run_terminal_cmd", "run_command",
    "terminal", "execute", "pre_run_command", "beforeshellexecution",
}
EDIT_TOOLS = {
    "write", "edit", "multiedit", "notebookedit", "create", "write_file", "replace",
    "str_replace", "str_replace_editor", "apply_patch", "pre_write_code", "edit_file",
    "create_file", "write_to_file", "replace_in_file",
}
PATH_KEYS = {
    "file_path", "filepath", "path", "absolute_path", "target_file", "file", "filename",
    "notebook_path", "paths", "files", "attachments", "dir_path",
}
CMD_KEYS = {"command", "cmd", "command_line", "commandline", "script"}
SKIP_KEYS = {
    "content", "contents", "new_string", "old_string", "edits", "text", "body", "prompt",
    "description", "messages", "instruction", "new_str", "old_str", "file_text", "patch",
}
_GLOB_CHARS = re.compile(r"[*?\[]")


def _collect(obj, paths, cmds, depth=0):
    if depth > 5:
        return
    if isinstance(obj, dict):
        for key, val in obj.items():
            k = str(key).lower()
            if k in CMD_KEYS:
                if isinstance(val, str):
                    cmds.append(val)
                elif isinstance(val, list) and val and all(isinstance(x, str) for x in val):
                    cmds.append(" ".join(shlex.quote(x) for x in val))
            elif k in PATH_KEYS:
                items = val if isinstance(val, list) else [val]
                for x in items:
                    if isinstance(x, str):
                        paths.append(x)
                    elif isinstance(x, dict):
                        _collect(x, paths, cmds, depth + 1)
            elif k not in SKIP_KEYS and isinstance(val, (dict, list)):
                _collect(val, paths, cmds, depth + 1)
    elif isinstance(obj, list):
        for x in obj:
            _collect(x, paths, cmds, depth + 1)


def _maybe_json(value):
    if isinstance(value, str):
        s = value.strip()
        if s[:1] in ("{", "["):
            try:
                return json.loads(s)
            except ValueError:
                return value
    return value


def parse_payload(data):
    """Return (tool_name, tool_arguments, cwd) for any supported agent."""
    event = str(data.get("hook_event_name") or data.get("agent_action_name") or "")
    tool = data.get("tool_name") or data.get("toolName") or ""
    args = data.get("tool_input")
    if args is None:
        args = data.get("toolArgs")
    if args is None:
        args = data.get("tool_info")
    args = _maybe_json(args)
    if event in ("beforeShellExecution", "beforeReadFile", "beforeTabFileRead") and args is None:
        args = {k: data[k] for k in ("command", "file_path", "attachments") if k in data}
    if args is None:
        args = {}
    if not tool:
        tool = event
    cwd = data.get("cwd") or None
    if isinstance(args, dict):
        wd = args.get("working_directory") or args.get("cwd") or args.get("workdir")
        if isinstance(wd, str) and wd:
            cwd = os.path.join(cwd or os.getcwd(), wd)
        if str(tool).lower() == "run_shell_command":
            sub = args.get("dir_path") or args.get("directory")
            if isinstance(sub, str) and sub:
                cwd = os.path.join(cwd or os.getcwd(), sub)
    if not cwd:
        roots = data.get("workspace_roots")
        if isinstance(roots, list) and roots and isinstance(roots[0], str):
            cwd = roots[0]
    return str(tool), args, cwd


def _tool_kind(tool):
    t = tool.lower().replace("-", "_")
    if t in SHELL_TOOLS or "shell" in t or "bash" in t:
        return "shell"
    if t in EDIT_TOOLS:
        return "edit"
    return "read"


_PATCH_FILE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$", re.M)


def evaluate(data, guard, default_cwd=None):
    """Return a Finding if this tool call must be blocked, else None."""
    tool, args, cwd = parse_payload(data)
    cwd = os.path.abspath(cwd or default_cwd or os.getcwd())
    kind = _tool_kind(tool)
    paths, cmds = [], []
    if isinstance(args, (dict, list)):
        _collect(args, paths, cmds)
    elif isinstance(args, str) and args:
        (cmds if kind == "shell" else paths).append(args)

    for c in list(cmds):
        if "*** Begin Patch" in c or tool.lower() == "apply_patch":
            cmds.remove(c)
            kind = "edit"
            for m in _PATCH_FILE.finditer(c):
                paths.append((m.group(1) or m.group(2)).strip())

    for p in paths:
        if not p or not isinstance(p, str) or "\0" in p:
            continue
        p = guard.expand_home(p)
        if _GLOB_CHARS.search(p) and not os.path.lexists(os.path.join(cwd, p)):
            hits = Shell(guard, cwd).glob_hits(p)
            if hits:
                return Finding.read(hits[0])
            continue
        hit = guard.check(os.path.join(cwd, p))
        if hit:
            return Finding.edit(hit) if kind == "edit" else Finding.read(hit)

    ps = "powershell" in tool.lower() or "pwsh" in tool.lower()
    for c in cmds:
        found = Shell(guard, cwd, powershell=ps).analyze(c)
        if found:
            return found
    return None


# ---------------------------------------------------------------------------
# Shell commands
# ---------------------------------------------------------------------------

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "pwsh", "powershell", "cmd"}
INTERPRETERS = {
    "python", "python3", "python2", "py", "pypy", "pypy3", "node", "nodejs", "deno", "bun",
    "ruby", "perl", "php", "lua", "rscript", "osascript", "jshell",
}
# Commands that never print a file's contents.
METADATA_SAFE = {
    "ls", "ll", "la", "dir", "exa", "eza", "lsd", "tree", "stat", "file", "test", "[", "[[",
    "touch", "chmod", "chown", "chgrp", "du", "df", "wc", "realpath", "readlink", "dirname",
    "basename", "echo", "printf", "mkdir", "which", "whereis", "cd", "pushd", "popd", "true",
    "false", ":", "unset", "sha256sum", "sha1sum", "sha512sum", "md5sum", "md5", "shasum",
    "b2sum", "cksum", "test-path", "get-item", "get-childitem", "gci", "set-location",
}
# Tools that use a key file without printing it.
SSH_FAMILY = {"ssh", "scp", "sftp", "ssh-add", "sshfs", "mosh", "autossh"}
READERS = {
    "cat", "head", "tail", "less", "more", "bat", "batcat", "grep", "egrep", "fgrep", "rg",
    "strings", "xxd", "od", "hexdump", "base64", "sed", "awk", "gawk", "mawk", "cut", "sort",
    "uniq", "tac", "nl", "fold", "pr", "column", "jq", "yq", "python", "python3", "node",
    "ruby", "perl", "php", "cp", "rsync", "tar", "zip", "diff", "cmp", "paste", "iconv",
    "view", "vi", "vim", "nvim", "nano", "emacs", "type", "get-content", "gc", "sh", "bash",
}
GREP_NAMES = {"grep", "egrep", "fgrep", "rgrep", "zgrep", "ggrep", "ack", "ack-grep"}
RUNNERS = {"npx", "bunx", "uvx", "uv", "poetry", "pipenv", "bundle", "op", "doppler",
           "dotenv", "dotenvx", "env-cmd", "cross-env", "pnpm", "yarn"}
LOADER_FLAGS = {"--env-file", "--env_file", "--envfile", "--dotenv"}
CONSUMER_FLAGS = {"--kubeconfig", "--key-file", "--keyfile", "-var-file", "--var-file",
                  "--identity-file", "--credentials-file", "--service-account-key-file"}
MESSAGE_FLAGS = {"-m", "--message", "--body", "-b", "--title", "-t", "--description",
                 "--notes", "--comment", "--subject"}
# Flags whose value is a file pattern to include or skip, not a file to read.
FILTER_FLAGS = {"--exclude", "--include", "--exclude-dir", "-g", "--glob", "--iglob", "-name",
                "-iname", "-path", "-ipath", "-wholename", "-iwholename", "--ignore", "--filter",
                "--ignore-glob", "-x"}
OUTPUT_REDIRECTS = {">", ">|", "&>", "1>"}

SECRET_COMMANDS = [(re.compile(p), why) for p, why in [
    (r"^gh auth token\b", "prints your GitHub token"),
    (r"^gh auth status\b.*(?:--show-token|\s-t\b)", "prints your GitHub token"),
    (r"^gcloud auth (?:application-default )?print-(?:access|identity)-token\b",
     "prints a Google Cloud token"),
    (r"^gcloud secrets versions access\b", "prints a Google Cloud secret"),
    (r"^aws configure (?:get|export-credentials)\b", "prints AWS credentials"),
    (r"^aws secretsmanager get-secret-value\b", "prints an AWS secret"),
    (r"^aws ssm get-parameters?\b.*--with-decryption\b", "prints a decrypted AWS parameter"),
    (r"^az account get-access-token\b", "prints an Azure token"),
    (r"^az keyvault secret show\b", "prints an Azure Key Vault secret"),
    (r"^kubectl get secrets?\b.*(?:\s-o\s*=?|--output[= ])(?:yaml|json|jsonpath|go-template|template)",
     "prints Kubernetes secrets"),
    (r"^(?:docker compose|docker-compose)\b.*\sconfig\b", "prints the values from your .env files"),
    (r"^security find-(?:generic|internet)-password\b.*\s-[a-zA-Z]*[wg]",
     "prints a password from your keychain"),
    (r"^op (?:read|inject)\b", "prints a 1Password secret"),
    (r"^op item get\b.*--(?:reveal|fields)", "prints a 1Password secret"),
    (r"^vault (?:kv get|read)\b", "prints a Vault secret"),
    (r"^doppler secrets(?:\s+(?:get|download)\b|\s*$|\s+-)", "prints Doppler secrets"),
    (r"^heroku config(?::get)?(?:\s|$)", "prints your Heroku config vars"),
    (r"^git credential (?:fill|get)\b", "prints git credentials"),
    (r"^(?:terraform|tofu) (?:output\b.*\s-(?:json|raw)\b|show\b.*\s-json\b|state pull\b)",
     "prints Terraform values, including sensitive ones"),
    (r"^(?:dotenv|dotenvx)\b.*\s(?:get|list)\b", "prints values from your .env file"),
    (r"^firebase functions:config:get\b", "prints Firebase config secrets"),
    (r"^npm config get\b.*(?:_auth|token)", "prints an npm token"),
]]

_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_VAR_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)|\$env:([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%", re.I)
_PATHISH = re.compile(r"[\w.~$/\\%:+@-]*[\w~-]")
_QUOTED = re.compile(r"""(['"])([^'"\n]{1,300})\1""")
_CODEISH = re.compile(r"[(){};]|\bopen\b|\brequire\b|readFile|\bcat\b")
_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_HEREDOC = re.compile(r"(?<!<)<<-?(?!<)\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_ENV_DUMP_CODE = re.compile(
    r"os\.environ\s*(?:[)\]},]|$)|os\.environ\.(?:items|values|copy)\s*\(|dict\(\s*os\.environ"
    r"|process\.env\s*(?:[),;}\]]|$)|JSON\.stringify\(\s*process\.env|Object\.(?:entries|values)\(\s*process\.env"
    r"|Deno\.env\.toObject\(|\bENV\.(?:to_h|to_a|each|inspect)\b|System\.getenv\(\s*\)"
    r"|\[Environment\]::GetEnvironmentVariables\(|\$ENV\s*\)|%ENV\b"
)
_ENV_ACCESS_CODE = re.compile(
    r"""os\.environ\[\s*['"](\w+)['"]|os\.(?:environ\.get|getenv)\(\s*['"](\w+)['"]"""
    r"""|process\.env\.(\w+)|process\.env\[\s*['"](\w+)['"]|\bENV\[\s*['"](\w+)['"]"""
    r"""|\bgetenv\(\s*['"](\w+)['"]|Deno\.env\.get\(\s*['"](\w+)['"]|\$env:(\w+)"""
)
_PRINT_CODE = re.compile(
    r"\b(?:print|println|console\.(?:log|error|info|warn|dir)|puts|printf|echo"
    r"|System\.out\.print|Write-(?:Output|Host)|say)\b"
)

_SECRET_WORDS = {
    "SECRET", "SECRETS", "TOKEN", "TOKENS", "PASSWORD", "PASSWORDS", "PASSWD", "PASS",
    "PASSPHRASE", "PWD", "CREDENTIAL", "CREDENTIALS", "CREDS", "DSN", "AUTH", "APIKEY",
    "PRIVATE", "JWT", "PAT", "COOKIE", "SALT", "KEY", "KEYS",
}
_SECRET_NAMES = {
    "DATABASE_URL", "DB_URL", "REDIS_URL", "MONGODB_URI", "MONGO_URI", "MONGO_URL",
    "POSTGRES_URL", "POSTGRESQL_URL", "MYSQL_URL", "AMQP_URL", "RABBITMQ_URL",
    "CONNECTION_STRING", "SENTRY_DSN",
}
_NOT_SECRET = {"PWD", "OLDPWD", "SSH_AUTH_SOCK", "SSH_AGENT_PID", "GPG_TTY", "KEYMAP",
               "KEYTIMEOUT", "TOKENIZERS_PARALLELISM"}


def is_secret_name(name: str) -> bool:
    """Does an environment variable name look like it holds a secret?"""
    up = name.upper()
    if up in _NOT_SECRET:
        return False
    if up in _SECRET_NAMES:
        return True
    words = {w.upper() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+", name)}
    if words & {"PUBLIC", "PUBLISHABLE"}:
        return False
    return bool(words & _SECRET_WORDS)


def _cmd_name(word):
    name = word.strip("'\"").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _tokenize(cmd, powershell=False):
    cmd = cmd.replace("\\\r\n", " ").replace("\\\n", " ").replace("\r\n", "\n").replace("\n", " ; ")
    try:
        lex = shlex.shlex(cmd, posix=not powershell, punctuation_chars=True)
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:
        return cmd.split()


def _segments(tokens):
    """Split tokens into simple commands. Returns [(separator_before, words)]."""
    out, cur, sep = [], [], None
    for t in tokens:
        if t and set(t) <= set(";&|()"):
            if cur:
                out.append((sep, cur))
            cur, sep = [], t
        else:
            cur.append(t)
    if cur:
        out.append((sep, cur))
    return out


def _substitutions(cmd):
    """Contents of $(...), `...`, <(...) and >(...)."""
    out, i, n = [], 0, len(cmd)
    while i < n:
        if (cmd.startswith("$(", i) and not cmd.startswith("$((", i)) or cmd.startswith(("<(", ">("), i):
            j, depth = i + 2, 1
            while j < n and depth:
                if cmd[j] == "(":
                    depth += 1
                elif cmd[j] == ")":
                    depth -= 1
                j += 1
            out.append(cmd[i + 2:j - 1] if depth == 0 else cmd[i + 2:])
            i = j
        elif cmd[i] == "`":
            j = cmd.find("`", i + 1)
            if j == -1:
                break
            out.append(cmd[i + 1:j])
            i = j + 1
        else:
            i += 1
    return out


def _split_heredocs(cmd):
    """Remove here-document bodies. Returns (command, [(before_<<, after_<<, body)])."""
    if "<<" not in cmd:
        return cmd, []
    lines = cmd.split("\n")
    kept, docs, i = [], [], 0
    while i < len(lines):
        line = lines[i]
        kept.append(line)
        i += 1
        for m in _HEREDOC.finditer(line):
            delim, body = m.group(2), []
            while i < len(lines) and lines[i].strip() != delim:
                body.append(lines[i])
                i += 1
            i += 1
            docs.append((line[:m.start()], line[m.end():], "\n".join(body)))
    return "\n".join(kept), docs


_PIPE_TO_SHELL = re.compile(r"\|\s*(?:sudo\s+)?(?:/\S*/)?(?:ba|z|da|k)?sh\b")


def _brace(word):
    m = re.search(r"\{([^{}]*,[^{}]*)\}", word)
    if not m:
        return [word]
    out = []
    for part in m.group(1).split(",")[:20]:
        out.extend(_brace(word[:m.start()] + part + word[m.end():]))
    return out


def _flag_value(args, i):
    """Value of a flag at args[i] given as `--flag value`."""
    return args[i + 1] if i + 1 < len(args) else ""


_POSIX_CLASSES = {
    "alpha": "A-Za-z", "digit": "0-9", "alnum": "A-Za-z0-9", "upper": "A-Z", "lower": "a-z",
    "space": r"\s", "blank": r" \t", "punct": r"!-/:-@\[-`{-~", "xdigit": "0-9A-Fa-f",
    "word": r"\w", "cntrl": r"\x00-\x1f", "print": r"\x20-\x7e", "graph": r"\x21-\x7e",
}


def _to_python_regex(pattern, basic=False):
    """Rewrite a grep/rg search pattern as a Python regex (close enough to decide)."""
    p = re.sub(r"\[:(\w+):\]", lambda m: _POSIX_CLASSES.get(m.group(1), m.group(0)), pattern)
    p = p.replace("\\<", "\\b").replace("\\>", "\\b")
    if not basic:
        return p
    out, i = [], 0
    while i < len(p):  # GNU basic regex: \| \+ \? \( \) \{ \} are special, bare ones are not
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            nxt = p[i + 1]
            out.append(nxt if nxt in "|+?(){}" else c + nxt)
            i += 2
            continue
        out.append("\\" + c if c in "|+?(){}" else c)
        i += 1
    return "".join(out)


class Search:
    """What a grep-like command will look for. Used to skip searches that can't print a secret."""

    def __init__(self):
        self.patterns = []
        self.unknown = False       # patterns from a file, multiline, ... we can't tell
        self.ignore_case = False
        self.smart_case = False
        self.fixed = False
        self.word = False
        self.line = False
        self.invert = False
        self.text = False
        self.basic = False

    def regexes(self):
        if self.unknown or self.invert or not self.patterns:
            return None
        out = []
        for pat in self.patterns:
            src = re.escape(pat) if self.fixed else _to_python_regex(pat, self.basic)
            if self.word:
                src = r"(?<!\w)(?:%s)(?!\w)" % src
            if self.line:
                src = r"^(?:%s)$" % src
            fold = self.ignore_case or (self.smart_case and pat == pat.lower())
            try:
                out.append(re.compile(src, re.I if fold else 0))
            except (re.error, OverflowError, ValueError):
                return None
        return out

    def prints_from(self, files):
        """The files a search would print lines from. If unsure, all of them."""
        regexes = self.regexes()
        if regexes is None:
            return list(files)
        hits = []
        for f in files:
            try:
                if os.path.getsize(f) > 2_000_000:
                    hits.append(f)
                    continue
                with open(f, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            if not self.text and b"\0" in data[:8192]:
                continue  # binary: grep says "Binary file matches" instead of printing it
            lines = data.decode("utf-8", errors="replace").splitlines()
            if any(r.search(line) for line in lines for r in regexes):
                hits.append(f)
        return hits


class Shell:
    def __init__(self, guard, cwd, powershell=False):
        self.g = guard
        self.cwd = cwd
        self.ps = powershell
        self.vars = {}
        self.cfg = guard.config

    # --- entry point ---

    def analyze(self, cmd, depth=0):
        if depth > 4 or not isinstance(cmd, str) or not cmd.strip():
            return None
        cmd = cmd[:100000]
        if re.fullmatch(r"[\w./-]+", self.cwd):
            cmd = cmd.replace("$(pwd)", self.cwd).replace("`pwd`", self.cwd)
        cmd, docs = _split_heredocs(cmd)
        for lead, tail, body in docs:
            found = self._heredoc(lead, tail, body, depth)
            if found:
                return found
        for inner in _substitutions(cmd):
            found = self.analyze(inner, depth + 1)
            if found:
                return found
        prev = None
        for sep, words in _segments(_tokenize(cmd, self.ps)):
            found = self._segment(words, prev if sep == "|" else None, depth)
            if found:
                return found
            prev = words
        return None

    def _heredoc(self, lead, tail, body, depth):
        if _PIPE_TO_SHELL.search(tail):
            return self.analyze(body, depth + 1)  # cat <<EOF | bash
        segs = _segments(_tokenize(lead, self.ps))
        if not segs:
            return None
        words = self._unwrap(segs[-1][1])
        name = _cmd_name(words[0]) if words else ""
        if name in SHELLS:
            return self.analyze(body, depth + 1)
        if name in INTERPRETERS:
            return self._code(body)
        return None  # text fed to cat/tee is data, not a file read

    # --- one simple command ---

    def _expand_vars(self, word):
        if "$" not in word or not self.vars:
            return word
        return re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?",
                      lambda m: self.vars.get(m.group(1), m.group(0)), word)

    def _unwrap(self, words):
        for _ in range(8):
            if not words:
                return words
            name = _cmd_name(words[0])
            if name == "env":
                rest, j = words[1:], 0
                while j < len(rest):
                    t = rest[j]
                    if t in ("-u", "--unset", "-C", "--chdir"):
                        j += 2
                    elif t in ("-S", "--split-string") and j + 1 < len(rest):
                        rest = rest[:j] + _tokenize(rest[j + 1]) + rest[j + 2:]
                    elif t.startswith("-") or _ASSIGN.match(t):
                        j += 1
                    else:
                        break
                if j >= len(rest):
                    return ["env"]  # nothing to run: `env` prints every variable
                words = rest[j:]
            elif name in ("sudo", "doas"):
                j = 1
                while j < len(words) and words[j].startswith("-"):
                    j += 2 if words[j] in ("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U") else 1
                words = words[j:]
            elif name in ("timeout", "gtimeout"):
                j = 1
                while j < len(words) and words[j].startswith("-"):
                    j += 2 if words[j] in ("-s", "-k", "--signal", "--kill-after") else 1
                words = words[j + 1:]
            elif name == "nice":
                j = 1
                while j < len(words) and words[j].startswith("-"):
                    j += 2 if words[j] == "-n" else 1
                words = words[j:]
            elif name in ("stdbuf", "ionice", "nohup", "time", "command", "builtin", "exec",
                          "caffeinate", "chronic", "unbuffer", "nocorrect", "noglob"):
                j = 1
                while j < len(words) and words[j].startswith("-"):
                    j += 1
                words = words[j:]
            else:
                return words
        return words

    def _segment(self, words, pipe_prev, depth):
        words = [self._expand_vars(w) for w in words]
        i = 0
        while i < len(words) and _ASSIGN.match(words[i]):
            key, val = words[i].split("=", 1)
            self.vars[key] = val
            i += 1
        words = self._unwrap(words[i:])
        if not words:
            return None
        name = _cmd_name(words[0])
        args = words[1:]

        if name in SHELLS:
            code = self._shell_code(name, args)
            if code is not None:
                return Shell(self.g, self.cwd, powershell=name in ("pwsh", "powershell")).analyze(code, depth + 1)
        if name == "eval":
            return self.analyze(" ".join(args), depth + 1)
        if name in ("source", "."):
            return None  # loads variables without printing them
        found = self._secret_command(name, args)
        if found:
            return found
        if name in RUNNERS:
            inner = self._runner_inner(name, args)
            if inner:
                return self._segment(inner, None, depth + 1)

        found = self._env_dump(name, args) or self._secret_var(name, args) or self._inline_code(name, args)
        if found:
            return found
        if name == "git":
            return self._git(args)
        if name == "xargs":
            found, inner = self._xargs(args, pipe_prev)
            return found or (self._segment(inner, None, depth + 1) if inner else None)
        found = self._overwrite(args)
        if found:
            return found
        if name not in METADATA_SAFE and name not in SSH_FAMILY:
            found = self._paths(name, args)
            if found:
                return found
        if name in GREP_NAMES:
            return self._grep(name, args)
        if name in ("rg", "ripgrep"):
            return self._rg(args)
        if name == "ag":
            return self._ag(args)
        if name in ("find", "gfind"):
            return self._find(args, reader=self._find_has_reader(args))
        return None

    @staticmethod
    def _shell_code(name, args):
        for i, a in enumerate(args):
            low = a.lower()
            if name == "cmd" and low in ("/c", "/k"):
                return " ".join(args[i + 1:])
            if name in ("pwsh", "powershell") and low in ("-c", "-command", "-commandwithargs"):
                return " ".join(args[i + 1:])
            if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
                return args[i + 1] if i + 1 < len(args) else None
        return None

    @staticmethod
    def _runner_inner(name, args):
        """The command that a runner (npx, uv run, dotenv ...) starts."""
        if "--" in args:
            return args[args.index("--") + 1:]
        if name in ("uv", "poetry", "pipenv", "pnpm", "yarn") and args[:1] in (["run"], ["exec"], ["dlx"]):
            args = args[1:]
        elif name in ("bundle", "op", "doppler") and args[:1] in (["exec"], ["run"]):
            args = args[1:]
        elif name in ("npx", "bunx", "uvx", "env-cmd", "cross-env", "dotenv", "dotenvx"):
            pass
        else:
            return None
        j = 0
        while j < len(args):
            a = args[j]
            if a in LOADER_FLAGS or a in ("-e", "-f", "--from", "--with", "-p", "--package", "--file"):
                j += 2
            elif a.startswith("-") or _ASSIGN.match(a):
                j += 1
            else:
                break
        rest = args[j:]
        if name in ("npx", "bunx", "uvx") and rest:
            return rest  # first word is the package (often also the command)
        return rest or None

    # --- checks ---

    def _secret_command(self, name, args):
        if not self.cfg.get("block_secret_commands"):
            return None
        text = " ".join([name] + args)
        for regex, why in SECRET_COMMANDS:
            if regex.search(text):
                return Finding.secret_command(text, why)
        return None

    def _env_dump(self, name, args):
        if not self.cfg.get("block_env_dump"):
            return None
        if name == "env":
            return Finding.env_dump()
        if name == "printenv":
            real = [a for a in args if not a.startswith("-")]
            if not real:
                return Finding.env_dump()
            if self.cfg.get("block_secret_vars"):
                for a in real:
                    if is_secret_name(a):
                        return Finding.secret_var(a)
            return None
        if name == "set" and not args:
            return Finding.env_dump()
        if name in ("export", "declare", "typeset") and all(a in ("-p", "-x", "-px", "-xp", "--") for a in args):
            return Finding.env_dump()
        if name in ("get-childitem", "gci", "ls", "dir", "get-item") and any(
                a.lower().strip("'\"") in ("env:", "env:\\", "env:/", "env:*") for a in args):
            return Finding.env_dump()
        return None

    def _secret_var(self, name, args):
        if not self.cfg.get("block_secret_vars"):
            return None
        if name in ("echo", "printf", "print", "write-output", "write-host", "say") or "<<<" in args:
            for a in args:
                for m in _VAR_REF.finditer(a):
                    var = next(g for g in m.groups() if g)
                    if is_secret_name(var):
                        return Finding.secret_var(var)
        return None

    def _inline_code(self, name, args):
        if name in INTERPRETERS or name in ("pwsh", "powershell"):
            return self._code(" ".join(args))
        return None

    def _code(self, code):
        if self.cfg.get("block_env_dump") and _ENV_DUMP_CODE.search(code):
            return Finding.env_dump()
        if self.cfg.get("block_secret_vars") and _PRINT_CODE.search(code):
            for m in _ENV_ACCESS_CODE.finditer(code):
                var = next(g for g in m.groups() if g)
                if is_secret_name(var):
                    return Finding.secret_var(var)
        for m in _QUOTED.finditer(code):
            hit = self._hit(m.group(2))
            if hit:
                return Finding.read(hit)
        return None

    def _overwrite(self, args):
        for i, a in enumerate(args[:-1]):
            if a in OUTPUT_REDIRECTS:
                target = args[i + 1]
                p = os.path.join(self.cwd, self.g.expand_home(target))
                if os.path.isfile(p):
                    hit = self.g.check(p)
                    if hit:
                        return Finding.overwrite(hit)
        return None

    def _variants(self, arg, name):
        a = arg.strip()
        if not a or len(a) > 4096:
            return []
        if any(ch.isspace() for ch in a):
            if name in INTERPRETERS or name in SHELLS or _CODEISH.search(a):
                return [m.group(2) for m in _QUOTED.finditer(a)] + _PATHISH.findall(a)
            return []  # prose, like a commit message
        a = a.strip("'\"`")
        out = [a]
        if "=" in a:
            out.append(a.split("=", 1)[1])
        if ":" in a and "://" not in a and not _DRIVE.match(a):
            out.append(a.rsplit(":", 1)[1])
        if any(ch in a for ch in "()'\",;"):
            out.extend(_PATHISH.findall(a))
        return out + [v[1:] for v in out if v.startswith("@")]  # curl -d @file, -F x=@file

    def _expand_path(self, cand):
        cand = cand.strip("'\"`,;()[]")
        if not cand or "://" in cand:
            return []
        home = self.g.home
        for var in ("${HOME}", "$HOME", "$env:USERPROFILE", "%USERPROFILE%", "$USERPROFILE"):
            if cand.startswith(var):
                cand = home + cand[len(var):]
        for var in ("${PWD}", "$PWD", "$(pwd)", "`pwd`"):
            if cand.startswith(var):
                cand = self.cwd + cand[len(var):]
        return _brace(self.g.expand_home(cand))

    def glob_hits(self, pattern, budget=0.5):
        hits = []
        deadline = time.monotonic() + budget
        for cand in self._expand_path(pattern):
            full = cand if os.path.isabs(cand) else os.path.join(self.cwd, cand)
            for match in itertools.islice(globmod.iglob(full, recursive=True), 500):
                hit = self.g.check(match)
                if hit:
                    hits.append(hit)
                if time.monotonic() > deadline:
                    return hits
        return hits

    def _hit(self, cand):
        for c in self._expand_path(cand):
            if _GLOB_CHARS.search(c):
                hits = self.glob_hits(c)
                if hits:
                    return hits[0]
                continue
            full = c if os.path.isabs(c) else os.path.join(self.cwd, c)
            try:
                exists = os.path.lexists(full)
            except (OSError, ValueError):
                continue
            if exists:
                hit = self.g.check(full)
                if hit:
                    return hit
        return None

    def _paths(self, name, args):
        skip = False
        for i, a in enumerate(args):
            if skip:
                skip = False
                continue
            low = a.lower()
            if a in OUTPUT_REDIRECTS or a in (">>", "2>", "2>>", "&>>"):
                skip = True  # output target: writing, not reading
                continue
            if low in LOADER_FLAGS or low in CONSUMER_FLAGS or low in FILTER_FLAGS:
                skip = True
                continue
            if any(low.startswith(f + "=") for f in LOADER_FLAGS | CONSUMER_FLAGS | FILTER_FLAGS):
                continue
            if low in MESSAGE_FLAGS and i + 1 < len(args) and any(ch.isspace() for ch in args[i + 1]):
                skip = True
                continue
            for cand in self._variants(a, name):
                hit = self._hit(cand)
                if hit:
                    return Finding.read(hit)
        return None

    # --- commands that read whole folders ---

    def _targets(self, operands):
        return [os.path.abspath(os.path.join(self.cwd, self.g.expand_home(t))) for t in operands]

    def _grep(self, name, args):
        recursive = name in ("rgrep", "ack", "ack-grep")
        names_only = has_e = False
        includes, excludes, exdirs, operands = [], [], [], []
        search = Search()
        search.basic = name in ("grep", "rgrep", "zgrep", "ggrep")
        search.fixed = name == "fgrep"
        with_arg = set("efABCDdmX")
        i = 0
        while i < len(args):
            a = args[i]
            if a == "--":
                operands.extend(args[i + 1:])
                break
            if a.startswith("--"):
                key, eq, val = a[2:].partition("=")
                if not eq and key in ("include", "exclude", "exclude-dir", "regexp", "file", "max-count",
                                      "after-context", "before-context", "context", "directories", "devices"):
                    val = _flag_value(args, i)
                    i += 1
                if key in ("recursive", "dereference-recursive"):
                    recursive = True
                elif key == "directories" and val == "recurse":
                    recursive = True
                elif key in ("files-with-matches", "files-without-match", "count", "quiet", "silent"):
                    names_only = True
                elif key == "include":
                    includes.append(val)
                elif key == "exclude":
                    excludes.append(val)
                elif key == "exclude-dir":
                    exdirs.append(val)
                elif key == "regexp":
                    has_e = True
                    search.patterns.append(val)
                elif key == "file":
                    has_e = search.unknown = True
                elif key == "ignore-case":
                    search.ignore_case = True
                elif key == "fixed-strings":
                    search.fixed = True
                elif key in ("extended-regexp", "perl-regexp"):
                    search.basic = False
                elif key == "word-regexp":
                    search.word = True
                elif key == "line-regexp":
                    search.line = True
                elif key == "invert-match":
                    search.invert = True
                elif key in ("text", "binary-files") and (key == "text" or val == "text"):
                    search.text = True
                elif key == "null-data":
                    search.unknown = True
            elif a.startswith("-") and len(a) > 1:
                for j in range(1, len(a)):
                    ch = a[j]
                    if ch in "rR":
                        recursive = True
                    elif ch in "lLcq":
                        names_only = True
                    elif ch in "iy":
                        search.ignore_case = True
                    elif ch == "F":
                        search.fixed = True
                    elif ch in "EP":
                        search.basic = False
                    elif ch == "w":
                        search.word = True
                    elif ch == "x":
                        search.line = True
                    elif ch == "v":
                        search.invert = True
                    elif ch == "a":
                        search.text = True
                    elif ch == "z":
                        search.unknown = True
                    if ch in with_arg:
                        val = a[j + 1:] or _flag_value(args, i)
                        if not a[j + 1:]:
                            i += 1
                        if ch == "e":
                            has_e = True
                            search.patterns.append(val)
                        elif ch == "f":
                            has_e = search.unknown = True
                        if ch == "d" and val == "recurse":
                            recursive = True
                        break
            else:
                operands.append(a)
            i += 1
        if not recursive or names_only:
            return None
        if not has_e:
            if operands:
                search.patterns.append(operands[0])
            operands = operands[1:]
        found = self.g.protected_under(self._targets(operands or ["."]))

        def searched(path):
            base = os.path.basename(path)
            if includes and not any(fnmatch.fnmatch(base, g) for g in includes):
                return False
            if any(fnmatch.fnmatch(base, g) for g in excludes):
                return False
            parts = os.path.relpath(path, self.cwd).replace("\\", "/").split("/")[:-1]
            return not any(fnmatch.fnmatch(p, g) for p in parts for g in exdirs)

        found = search.prints_from([f for f in found if searched(f)])
        return Finding.search([self.g.display(f) for f in found]) if found else None

    def _filtered_search(self, targets, hidden, noignore, keep=None, search=None):
        found = []
        for folder in self._targets(targets):
            for f in self.g.protected_under([folder]):
                rel = _relative(f, folder) or os.path.basename(f)
                if not hidden and any(part.startswith(".") for part in rel.split("/")):
                    continue
                if keep is not None and not keep(rel):
                    continue
                found.append(f)
        if found and not noignore:
            ignored = set(self.g.git_ignored(found))
            found = [f for f in found if f not in ignored]
        if found and search is not None:
            found = search.prints_from(found)
        return Finding.search([self.g.display(f) for f in found]) if found else None

    def _rg(self, args):
        hidden = noignore = names_only = types = has_e = False
        globs, operands, u = [], [], 0
        search = Search()
        with_arg = {"-e", "--regexp", "-f", "--file", "-g", "--glob", "--iglob", "-t", "--type",
                    "-T", "--type-not", "-A", "-B", "-C", "--after-context", "--before-context",
                    "--context", "-m", "--max-count", "-j", "--threads", "-M", "--max-columns",
                    "--max-depth", "-d", "--max-filesize", "-r", "--replace", "--type-add",
                    "--sort", "--sortr", "--color", "--colors", "--pre", "--pre-glob", "-E",
                    "--encoding", "--engine", "--ignore-file", "--path-separator"}
        i = 0
        while i < len(args):
            a = args[i]
            if a == "--":
                operands.extend(args[i + 1:])
                break
            key, eq, val = a.partition("=")
            if a in with_arg:
                val = _flag_value(args, i)
                i += 1
            if key in ("--hidden", "-."):
                hidden = True
            elif key in ("--no-ignore", "--no-ignore-vcs", "--no-ignore-dot", "--no-ignore-files"):
                noignore = True
            elif key == "--unrestricted":
                u += 1
            elif key in ("--files-with-matches", "--files-without-match", "--count", "--count-matches",
                         "--quiet", "--files"):
                names_only = True
            elif key in ("-t", "--type"):
                types = True
            elif key in ("-g", "--glob", "--iglob"):
                globs.append(val)
            elif key in ("-e", "--regexp"):
                has_e = True
                search.patterns.append(val)
            elif key in ("-f", "--file", "--multiline", "--multiline-dotall", "--null-data"):
                has_e = has_e or key in ("-f", "--file")
                search.unknown = True
            elif key == "--ignore-case":
                search.ignore_case = True
            elif key == "--smart-case":
                search.smart_case = True
            elif key == "--case-sensitive":
                search.ignore_case = search.smart_case = False
            elif key == "--fixed-strings":
                search.fixed = True
            elif key == "--word-regexp":
                search.word = True
            elif key == "--line-regexp":
                search.line = True
            elif key == "--invert-match":
                search.invert = True
            elif key in ("--text", "--binary"):
                search.text = True
            elif a.startswith("-") and not a.startswith("--") and a not in with_arg:
                for ch in a[1:]:
                    if ch == "u":
                        u += 1
                    elif ch in "lcq":
                        names_only = True
                    elif ch == ".":
                        hidden = True
                    elif ch == "i":
                        search.ignore_case = True
                    elif ch == "S":
                        search.smart_case = True
                    elif ch == "s":
                        search.ignore_case = search.smart_case = False
                    elif ch == "F":
                        search.fixed = True
                    elif ch == "w":
                        search.word = True
                    elif ch == "x":
                        search.line = True
                    elif ch == "v":
                        search.invert = True
                    elif ch == "a":
                        search.text = True
                    elif ch == "U":
                        search.unknown = True
            elif not a.startswith("-"):
                operands.append(a)
            i += 1
        noignore = noignore or u >= 1
        hidden = hidden or u >= 2
        search.text = search.text or u >= 3
        if names_only or types:
            return None
        if not has_e:
            if operands:
                search.patterns.append(operands[0])
            operands = operands[1:]
        return self._filtered_search(operands or ["."], hidden, noignore,
                                     self._glob_filter(globs) if globs else None, search)

    @staticmethod
    def _glob_filter(globs):
        """rg -g semantics: plain globs pick files, "!glob" skips them."""
        pos = Rules.parse("\n".join(g for g in globs if not g.startswith("!")))
        neg = Rules.parse("\n".join(g[1:] for g in globs if g.startswith("!")))
        has_pos = any(not g.startswith("!") for g in globs)

        def keep(rel):
            if has_pos and pos.match(rel, parents=False) is None:
                return False
            return neg.match(rel) is None  # "!dir" skips everything inside dir
        return keep

    def _ag(self, args):
        hidden = noignore = names_only = False
        operands, file_regex = [], None
        search = Search()
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("--hidden",):
                hidden = True
            elif a in ("-u", "--unrestricted"):
                hidden = noignore = True
            elif a in ("-U", "--skip-vcs-ignores"):
                noignore = True
            elif a in ("-l", "-L", "-c", "--count", "--files-with-matches", "-g"):
                names_only = True
            elif a in ("-i", "--ignore-case"):
                search.ignore_case = True
            elif a in ("-S", "--smart-case"):
                search.smart_case = True
            elif a in ("-Q", "--literal"):
                search.fixed = True
            elif a in ("-w", "--word-regexp"):
                search.word = True
            elif a in ("-v", "--invert-match"):
                search.invert = True
            elif a in ("-a", "--all-types", "--search-binary"):
                search.text = True
            elif a in ("-G", "--file-search-regex"):
                file_regex = _flag_value(args, i)
                i += 1
            elif a in ("--ignore", "-A", "-B", "-C", "-m", "--depth"):
                i += 1
            elif not a.startswith("-"):
                operands.append(a)
            i += 1
        if names_only:
            return None
        keep = None
        if file_regex:
            try:
                rx = re.compile(file_regex)
                keep = lambda rel: bool(rx.search(rel))  # noqa: E731
            except re.error:
                keep = None
        search.patterns = operands[:1]
        return self._filtered_search(operands[1:] or ["."], hidden, noignore, keep, search)

    @staticmethod
    def _find_has_reader(args):
        for i, a in enumerate(args):
            if a in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(args):
                if _cmd_name(args[i + 1]) in READERS:
                    return True
        return False

    def _find(self, args, reader):
        if not reader:
            return None
        roots, i = [], 0
        while i < len(args) and not args[i].startswith("-") and args[i] not in ("(", "!", "\\(", "\\!"):
            roots.append(args[i])
            i += 1
        roots = roots or ["."]
        expr = args[i:]
        filters = []
        j = 0
        while j < len(expr):
            t = expr[j]
            if t in ("-exec", "-execdir", "-ok", "-okdir"):
                break
            if t in ("-o", "-or", "!", "-not", "(", ")", "\\(", "\\)", "\\!"):
                filters = None
                break
            if t in ("-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename",
                     "-regex", "-iregex") and j + 1 < len(expr):
                filters.append((t, expr[j + 1]))
                j += 2
                continue
            j += 1
        found = []
        for root in roots:
            base = os.path.abspath(os.path.join(self.cwd, self.g.expand_home(root)))
            for f in self.g.protected_under([base]):
                shown = os.path.join(root, os.path.relpath(f, base)).replace("\\", "/")
                if filters and not all(self._find_ok(f, shown, t, p) for t, p in filters):
                    continue
                found.append(f)
        return Finding.search([self.g.display(f) for f in found]) if found else None

    @staticmethod
    def _find_ok(path, shown, test, pattern):
        fold = test.startswith("-i")
        name = os.path.basename(path)
        if fold:
            name, shown, pattern = name.lower(), shown.lower(), pattern.lower()
        if test in ("-name", "-iname"):
            return fnmatch.fnmatchcase(name, pattern)
        if test in ("-regex", "-iregex"):
            try:
                return re.search(pattern, shown) is not None
            except re.error:
                return True
        return fnmatch.fnmatchcase(shown, pattern)

    def _xargs(self, args, pipe_prev):
        """`... | xargs cat`: which files will the piped command list? Returns (finding, inner)."""
        j = 0
        with_arg = {"-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a", "--arg-file", "--max-args",
                    "--max-procs", "--delimiter", "--replace", "--max-lines", "--max-chars", "--eof"}
        while j < len(args) and args[j].startswith("-"):
            j += 2 if args[j] in with_arg else 1
        inner = args[j:]
        if not inner or _cmd_name(inner[0]) not in READERS or not pipe_prev:
            return None, inner
        src = self._unwrap(list(pipe_prev))
        src_name = _cmd_name(src[0]) if src else ""
        found = []
        if src_name in ("find", "gfind"):
            return self._find(src[1:], reader=True), inner
        if src_name == "git" and "ls-files" in src:
            tracked = self.g.git_tracked()
            found = [f for f in self.g.protected_under([self.cwd]) if f in tracked]
        elif src_name in ("ls", "dir"):
            flags = "".join(a[1:] for a in src[1:] if a.startswith("-") and not a.startswith("--"))
            show_hidden = "a" in flags or "A" in flags or "--all" in src
            folders = self._targets([a for a in src[1:] if not a.startswith("-")] or ["."])
            for folder in folders:
                try:
                    names = os.listdir(folder)
                except OSError:
                    continue
                for name in names:
                    full = os.path.join(folder, name)
                    if (show_hidden or not name.startswith(".")) and os.path.isfile(full) and self.g.check(full):
                        found.append(full)
        return (Finding.search([self.g.display(f) for f in found]) if found else None), inner

    def _git(self, args):
        i = 0
        while i < len(args) and args[i].startswith("-"):
            i += 2 if args[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace") else 1
        if i >= len(args):
            return None
        sub, rest = args[i], args[i + 1:]
        if sub in ("show", "cat-file"):
            for a in rest:
                if ":" in a and not a.startswith("-"):
                    path = a.split(":", 1)[1]
                    hit = self.g.check_rel(path) if path else None
                    if hit:
                        return Finding.read(hit)
            return self._paths("git", rest)
        if sub in ("diff", "log", "blame", "annotate", "stash", "format-patch", "whatchanged",
                   "difftool", "mv", "archive"):
            return self._paths("git", rest)
        if sub == "grep":
            return self._git_grep(rest)
        if sub == "add" and self.cfg.get("block_git_add"):
            return self._git_add(rest)
        return None

    def _git_grep(self, rest):
        if any(a in ("-l", "-L", "-c", "-q", "--name-only", "--files-with-matches", "--count",
                     "--quiet") for a in rest):
            return None
        untracked = "--untracked" in rest
        no_index = "--no-index" in rest
        paths = rest[rest.index("--") + 1:] if "--" in rest else []
        head = rest[:rest.index("--")] if "--" in rest else rest
        search = Search()
        search.basic = True
        has_e = False
        i = 0
        while i < len(head):
            a = head[i]
            if a in ("-e", "--regexp") and i + 1 < len(head):
                search.patterns.append(head[i + 1])
                has_e = True
                i += 1
            elif a in ("-f", "--file"):
                search.unknown = has_e = True
                i += 1
            elif a in ("-i", "--ignore-case"):
                search.ignore_case = True
            elif a in ("-F", "--fixed-strings"):
                search.fixed = True
            elif a in ("-E", "--extended-regexp", "-P", "--perl-regexp"):
                search.basic = False
            elif a in ("-w", "--word-regexp"):
                search.word = True
            elif a in ("-v", "--invert-match"):
                search.invert = True
            elif not a.startswith("-") and not has_e and not search.patterns:
                search.patterns.append(a)
            elif not a.startswith("-"):
                paths.append(a)
            i += 1
        found = self.g.protected_under(self._targets(paths or ["."]))
        if not no_index:
            tracked = self.g.git_tracked()
            if untracked:
                ignored = set(self.g.git_ignored(found))
                found = [f for f in found if f not in ignored]
            else:
                found = [f for f in found if f in tracked]
        found = search.prints_from(found)
        return Finding.search([self.g.display(f) for f in found]) if found else None

    def _git_add(self, rest):
        opts = [a for a in rest if a.startswith("-")]
        paths = [a for a in rest if not a.startswith("-")]
        if any(o in ("-u", "--update", "-n", "--dry-run", "-p", "--patch", "-i", "--interactive")
               for o in opts):
            return None
        everything = any(o in ("-A", "--all", "--no-ignore-removal") for o in opts)
        if not paths and not everything:
            return None
        if everything and not paths:
            targets = [self.g.root]
        else:
            targets = self._targets(paths)
        found = []
        for t in targets:
            matches = list(itertools.islice(globmod.iglob(t, recursive=True), 500)) if _GLOB_CHARS.search(t) else [t]
            for m in matches:
                if os.path.isdir(m):
                    found.extend(self.g.protected_under([m]))
                elif os.path.lexists(m) and self.g.check(m):
                    found.append(os.path.abspath(m))
        if found and not any(o in ("-f", "--force") for o in opts):
            ignored = set(self.g.git_ignored(found))
            found = [f for f in found if f not in ignored]
        return Finding.git_add([self.g.display(f) for f in found]) if found else None


# ---------------------------------------------------------------------------
# Talking back to the agent
# ---------------------------------------------------------------------------

def guess_agent(data):
    event = str(data.get("hook_event_name", ""))
    if event.startswith("before") or "cursor_version" in data:
        return "cursor"
    if "agent_action_name" in data:
        return "windsurf"
    if "toolName" in data:
        return "copilot"
    if event == "BeforeTool":
        return "gemini"
    return "claude"


def respond(agent, finding, out=None, err=None):
    """Print the agent's expected answer. Returns the exit code (2 = blocked)."""
    out = out or sys.stdout
    err = err or sys.stderr
    if finding is None:
        if agent == "cursor":
            out.write('{"permission": "allow"}\n')
        elif agent == "gemini":
            out.write('{"decision": "allow"}\n')
        return 0
    msg = finding.message()
    if agent in ("claude", "codex"):
        body = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": msg}}
    elif agent == "copilot":
        body = {"permissionDecision": "deny", "permissionDecisionReason": msg}
    elif agent == "cursor":
        body = {"permission": "deny", "user_message": msg, "agent_message": msg}
    elif agent == "gemini":
        body = {"decision": "deny", "reason": msg}
    else:
        body = None
    if body is not None:
        out.write(json.dumps(body) + "\n")
    err.write(msg + "\n")
    return 2


def _log(root, agent, tool, finding):
    path = os.path.join(root, DIR_NAME, LOG_FILE)
    try:
        if os.path.exists(path) and os.path.getsize(path) > 256 * 1024:
            with open(path, encoding="utf-8", errors="replace") as fh:
                tail = fh.readlines()[-500:]
            with open(path, "w", encoding="utf-8") as fh:
                fh.writelines(tail)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("%s\t%s\t%s\t%s\n" % (stamp, agent, tool or "-", finding.reason))
    except OSError:
        pass


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    agent = (argv[0] if argv else "auto").lower()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        raw = sys.stdin.read()
    except (OSError, ValueError):
        raw = ""
    finding = None
    try:
        data = json.loads(raw) if raw.strip() else None
        if isinstance(data, dict):
            if agent == "auto":
                agent = guess_agent(data)
            config = load_config(root)
            guard = Guard(root, load_rules(root), config)
            finding = evaluate(data, guard, os.getcwd())
            if finding is not None and config.get("log"):
                _log(root, agent, parse_payload(data)[0], finding)
    except Exception:  # a bug here must never break the agent
        finding = None
    if agent == "auto":
        agent = "claude"
    return respond(agent, finding)


if __name__ == "__main__":
    sys.exit(main())
