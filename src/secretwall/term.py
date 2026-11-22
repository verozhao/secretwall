"""Small helpers for terminal output: colors, symbols, aligned rows."""
from __future__ import annotations

import os
import re
import sys

_ANSI = re.compile(r"\033\[[0-9;]*m")


class Term:
    def __init__(self, stream=None):
        self.stream = stream or sys.stdout
        self.color = self._color_ok()
        self.unicode = self._unicode_ok()

    def _color_ok(self):
        if os.environ.get("NO_COLOR") is not None or os.environ.get("TERM") == "dumb":
            return False
        if os.environ.get("FORCE_COLOR"):
            return True
        return bool(getattr(self.stream, "isatty", lambda: False)())

    def _unicode_ok(self):
        encoding = getattr(self.stream, "encoding", None) or "ascii"
        try:
            "✔✖…—".encode(encoding)
            return True
        except (UnicodeEncodeError, LookupError):
            return False

    def paint(self, code, text):
        return "\033[%sm%s\033[0m" % (code, text) if self.color else text

    def bold(self, text):
        return self.paint("1", text)

    def dim(self, text):
        return self.paint("2", text)

    def red(self, text):
        return self.paint("31", text)

    def green(self, text):
        return self.paint("32", text)

    def yellow(self, text):
        return self.paint("33", text)

    @property
    def ok(self):
        return self.green("✔" if self.unicode else "OK")

    @property
    def bad(self):
        return self.red("✖" if self.unicode else "X")

    @property
    def warn(self):
        return self.yellow("!")

    @property
    def dash(self):
        return "—" if self.unicode else "-"

    @property
    def ellipsis(self):
        return "…" if self.unicode else "..."

    def line(self, text=""):
        self.stream.write(text + "\n")

    def rows(self, rows, indent=2):
        """Print rows of cells with aligned columns."""
        if not rows:
            return
        widths = [0] * max(len(r) for r in rows)
        for r in rows:
            for i, cell in enumerate(r):
                widths[i] = max(widths[i], len(_ANSI.sub("", cell)))
        for r in rows:
            parts = []
            for i, cell in enumerate(r):
                pad = widths[i] - len(_ANSI.sub("", cell))
                parts.append(cell + (" " * pad if i < len(r) - 1 else ""))
            self.line(" " * indent + "  ".join(parts).rstrip())


def short_path(path, home=None):
    home = home or os.path.expanduser("~")
    if path == home:
        return "~"
    if path.startswith(home + os.sep):
        return "~" + path[len(home):]
    return path


def human_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0
    return "%d B" % n
