"""Find secret files, and secrets written inside other files."""
from __future__ import annotations

import os
import re
import subprocess

from .hook import PRUNE

CONTENT_PATTERNS = [
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{40,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("PyPI token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("database password", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)://"
        r"[^\s:/@'\"]+:([^\s@/'\"]{4,})@([^\s/:'\"?]+)")),
    ("Google service account key", re.compile(r'"type"\s*:\s*"service_account"')),
]

_PLACEHOLDER = re.compile(r"(?i)example|dummy|sample|fake|placeholder|changeme|xxxx|your[_-]|<|\$\{|\{\{")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "db", "postgres", "mysql", "redis", "mongo",
                "mongodb", "rabbitmq", "host.docker.internal"}
_WEAK_PASSWORDS = {"password", "postgres", "root", "admin", "secret", "pass", "test", "example",
                   "changeme", "mysql", "user", "guest", "redis"}
DATA_EXTS = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml",
             ".txt", ".plist", ".config"}
_SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock",
               "go.sum", "composer.lock", "Gemfile.lock", "uv.lock", "Pipfile.lock", "bun.lockb"}


def walk(root, limit=50000):
    """Files under root. Skips heavy folders (node_modules, .git, ...) and symlinks."""
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in PRUNE and not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)
            count += 1
            if count >= limit:
                return


def secret_files(guard):
    """Absolute paths of the files the rules protect."""
    return sorted(guard.protected_under([guard.root], budget=60.0, limit=5000))


def _real(kind, match):
    if kind == "database password":
        password, host = match.group(1), match.group(2)
        return not (password.lower() in _WEAK_PASSWORDS or host.lower() in _LOCAL_HOSTS
                    or _PLACEHOLDER.search(password))
    return not _PLACEHOLDER.search(match.group(0))


def secrets_in_files(root, skip=(), max_size=1_000_000, max_total=300_000_000):
    """Find secrets written inside normal files. Returns [{path, line, kind}]."""
    skip = set(skip)
    results, total = [], 0
    for path in walk(root):
        name = os.path.basename(path)
        if path in skip or name in _SKIP_FILES or name.endswith((".min.js", ".map")):
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size == 0 or size > max_size:
            continue
        total += size
        if total > max_total:
            break
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue
        text = data.decode("utf-8", errors="replace")
        for kind, regex in CONTENT_PATTERNS:
            for m in regex.finditer(text):
                if _real(kind, m):
                    results.append({"path": path, "line": text.count("\n", 0, m.start()) + 1, "kind": kind})
                    break
    return results


def is_data_file(path):
    return os.path.splitext(path)[1].lower() in DATA_EXTS


def git_status(root, paths):
    """Return (tracked, not_ignored) subsets of paths, or (None, None) outside git."""
    try:
        top = subprocess.run(["git", "-C", root, "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None, None
    if top.returncode != 0:
        return None, None
    if not paths:
        return set(), set()
    try:
        listed = subprocess.run(["git", "-C", root, "ls-files", "-z", "--"] + list(paths),
                                capture_output=True, timeout=10)
        tracked = {os.path.abspath(os.path.join(root, p)) for p in
                   listed.stdout.decode(errors="replace").split("\0") if p}
        data = ("\0".join(paths) + "\0").encode()
        ignored_out = subprocess.run(["git", "-C", root, "check-ignore", "--stdin", "-z", "--no-index"],
                                     input=data, capture_output=True, timeout=10)
        ignored = {os.path.abspath(os.path.join(root, p)) for p in
                   ignored_out.stdout.decode(errors="replace").split("\0") if p}
    except (OSError, subprocess.SubprocessError):
        return None, None
    not_ignored = {os.path.abspath(p) for p in paths} - ignored - tracked
    return tracked, not_ignored
