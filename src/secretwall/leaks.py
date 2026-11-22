"""Check whether AI agents have already seen your secrets.

AI coding tools keep chat logs on your computer. If an agent ever read your
.env file, the values are in those logs (and were sent to the model). We look
for your exact secret values there. Everything stays on your machine, and we
never print the values.
"""
from __future__ import annotations

import json
import math
import mmap
import os
import re
import sys
import time

from .hook import is_secret_name

_PEM_BODY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s+(.+?)\s+-----END", re.S)
_URL_PASSWORD = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]+:([^@\s]+)@")
_KV = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-/:]*)\s*[=:]\s*(.*?)\s*$")
_BORING = {"true", "false", "null", "none", "undefined", "localhost", "development",
           "production", "staging", "test"}
SEARCH_EXTS = {".jsonl", ".json", ".md", ".txt", ".log", ".vscdb", ".db", ".sqlite", ".sqlite3",
               ".ndjson", ".history"}


class Secret:
    def __init__(self, label, value):
        self.label = label
        self.value = value

    @property
    def needles(self):
        raw = self.value.encode("utf-8")
        escaped = json.dumps(self.value)[1:-1].encode("utf-8")
        return [raw] if escaped == raw else [raw, escaped]


def mask(value, ellipsis="…"):
    if len(value) >= 16:
        return value[:4] + ellipsis + value[-4:]
    return value[:2] + ellipsis


def _entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(text))
    return -sum(c / n * math.log(c / n, 2) for c in counts.values())


def _unquote(value):
    value = value.strip()
    if value[:1] in ("'", '"'):
        end = value.find(value[0], 1)
        return value[1:end] if end > 0 else value[1:]
    return re.split(r"\s+#", value, maxsplit=1)[0].strip().rstrip(",;")


def _worth_searching(key, value):
    if len(value) < 8 or len(value) > 4096 or "\n" in value:
        return False
    low = value.lower()
    if low in _BORING or value.isdigit() or value.startswith(("${", "$(", "op://", "vault:")):
        return False
    if re.fullmatch(r"https?://[^@\s]*", value):
        return False
    if is_secret_name(key.replace(".", "_").replace("-", "_")):
        return True
    return len(value) >= 16 and _entropy(value) >= 3.5


def _pairs(text, name):
    if name.endswith(".json"):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if data is not None:
            stack = [("", data)]
            while stack:
                prefix, obj = stack.pop()
                if isinstance(obj, dict):
                    stack.extend(((k if not prefix else prefix + "." + str(k)), v) for k, v in obj.items())
                elif isinstance(obj, list):
                    stack.extend((prefix, v) for v in obj)
                elif isinstance(obj, str):
                    yield prefix.rsplit(".", 1)[-1] or "value", obj
            return
    for line in text.splitlines():
        if line.lstrip().startswith(("#", ";", "//")):
            continue
        m = _KV.match(line)
        if m:
            yield m.group(1).rsplit(":", 1)[-1].rsplit("/", 1)[-1], _unquote(m.group(2))


def collect(files, root):
    """Secret values from the given files (absolute paths)."""
    secrets, seen = [], set()

    def add(label, value):
        if value not in seen:
            seen.add(value)
            secrets.append(Secret(label, value))

    def add_key(label, pem_text):
        # One full line from the middle of the key: lines survive copy/paste intact.
        for m in _PEM_BODY.finditer(pem_text):
            lines = [ln for ln in m.group(1).split() if len(ln) >= 40]
            if lines:
                add(label, lines[len(lines) // 2])

    for path in files:
        try:
            if os.path.getsize(path) > 2_000_000:
                continue
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        if b"\0" in data[:4096]:
            continue
        text = data.decode("utf-8", errors="replace")
        rel = os.path.relpath(path, root).replace(os.sep, "/") if path.startswith(root) else path
        if "PRIVATE KEY-----" in text and not path.endswith(".json"):
            add_key("%s: private key" % rel, text)
            continue
        for key, value in _pairs(text, os.path.basename(path)):
            if "PRIVATE KEY-----" in value:
                add_key("%s: %s" % (rel, key), value)
            elif _worth_searching(key, value):
                add("%s: %s" % (rel, key), value)
                pw = _URL_PASSWORD.match(value)
                if pw and len(pw.group(1)) >= 8:
                    add("%s: %s (password)" % (rel, key), pw.group(1))
    return secrets


def _editor_dirs(home):
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support")
    if os.name == "nt":
        return os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
    return os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")


def locations(home, root):
    """Where AI agents keep chat logs: [(agent, path)] that exist."""
    found = []

    def add(agent, *parts):
        path = os.path.join(*parts)
        if os.path.exists(path):
            found.append((agent, path))

    add("Claude Code", home, ".claude", "projects")
    add("Claude Code", home, ".claude", "history.jsonl")
    add("Codex CLI", home, ".codex", "sessions")
    add("Codex CLI", home, ".codex", "archived_sessions")
    add("Codex CLI", home, ".codex", "history.jsonl")
    add("Gemini CLI", home, ".gemini", "tmp")
    add("Copilot CLI", home, ".copilot", "session-state")
    add("Copilot CLI", home, ".copilot", "command-history-state")
    add("Cursor", home, ".cursor", "projects")
    add("Cursor", home, ".cursor", "chats")
    base = _editor_dirs(home)
    for app, label in (("Cursor", "Cursor"), ("Code", "VS Code"), ("Code - Insiders", "VS Code Insiders"),
                       ("Windsurf", "Windsurf")):
        add(label, base, app, "User", "workspaceStorage")
        add(label, base, app, "User", "globalStorage")
    for name in (".aider.chat.history.md", ".aider.input.history", ".aider.llm.history"):
        add("Aider", root, name)
    return found


def _files(path):
    if os.path.isfile(path):
        yield path
        return
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", "CachedData", "logs-old")]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in SEARCH_EXTS:
                yield os.path.join(dirpath, name)


class Result:
    def __init__(self):
        self.hits = {}        # secret index -> [(agent, path, mtime)]
        self.skipped = []     # (path, size) too big to search
        self.files = 0
        self.bytes = 0
        self.seconds = 0.0


def search(secrets, places, max_bytes=1 << 30, progress=None):
    result = Result()
    needles = [(i, n) for i, s in enumerate(secrets) for n in s.needles]
    start = time.monotonic()
    for agent, place in places:
        for path in _files(place):
            try:
                st = os.stat(path)
            except OSError:
                continue
            if st.st_size == 0:
                continue
            if st.st_size > max_bytes:
                result.skipped.append((path, st.st_size))
                continue
            try:
                with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    for idx, needle in needles:
                        if mm.find(needle) != -1:
                            entry = (agent, path, st.st_mtime)
                            bucket = result.hits.setdefault(idx, [])
                            if entry not in bucket:
                                bucket.append(entry)
            except (OSError, ValueError):
                continue
            result.files += 1
            result.bytes += st.st_size
            if progress and result.files % 200 == 0:
                progress(result.files, result.bytes)
    result.seconds = time.monotonic() - start
    return result
