"""secretwall command line: init, doctor, check, leaks, remove."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

from . import agents, leaks, scan
from . import hook as H
from .term import Term, human_size, short_path

AGENT_KEYS = [a.key for a in agents.AGENTS]


def find_root(given):
    if given:
        return os.path.abspath(given)
    try:
        out = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            return os.path.abspath(out.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return os.getcwd()


def default_python():
    return "python" if os.name == "nt" else "python3"


def hook_source():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "hook.py")


def _read(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def rule_lines(text):
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def _rel(path, root):
    return os.path.relpath(path, root).replace(os.sep, "/")


def _load_project(root):
    text = _read(os.path.join(root, H.DIR_NAME, H.RULES_FILE))
    return (text if text is not None else H.DEFAULT_RULES), text is None


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

def cmd_init(args):
    t = Term()
    root = find_root(args.root)
    home = os.path.expanduser("~")
    folder = os.path.join(root, H.DIR_NAME)
    rules_text, new_rules = _load_project(root)
    config = H.load_config(root)
    guard = H.Guard(root, H.Rules.parse(rules_text), config)

    t.line(t.bold("secretwall %s" % H.VERSION) + t.dim(" %s keeps AI agents away from your secrets" % t.dash))
    t.line("Project: %s" % short_path(root, home))
    if args.dry_run:
        t.line(t.yellow("Dry run: nothing will be written."))
    t.line()

    files = scan.secret_files(guard)
    found_inside = [] if args.no_scan else scan.secrets_in_files(root, skip=set(files))
    extra = []
    for item in found_inside:
        p = item["path"]
        if scan.is_data_file(p) and p not in extra and not guard.check(p):
            extra.append(p)
    in_code = [item for item in found_inside if item["path"] not in extra]
    if extra:
        rules_text = (rules_text.rstrip("\n") + "\n\n# Found by `secretwall init`: files with secrets inside\n"
                      + "".join("/%s\n" % _rel(p, root) for p in extra))
        guard = H.Guard(root, H.Rules.parse(rules_text), config)
        files = sorted(set(files) | set(extra))
    rel_files = [_rel(p, root) for p in files]

    if files:
        kinds = {item["path"]: item["kind"] for item in found_inside}
        t.line(t.bold("Secret files (%d)" % len(files)))
        for p, rel in list(zip(files, rel_files))[:30]:
            t.line("  " + rel + (t.dim("  (%s inside)" % kinds[p]) if p in kinds else ""))
        if len(files) > 30:
            t.line(t.dim("  and %d more" % (len(files) - 30)))
    else:
        t.line(t.bold("Secret files: ") + "none yet. The rules will protect new ones.")
    t.line()

    tracked, not_ignored = scan.git_status(root, files)
    warnings = []
    for p in sorted(tracked or []):
        warnings.append("%s is committed to git, so its secrets are in your git history. Replace them."
                        % _rel(p, root))
    for p in sorted(not_ignored or []):
        warnings.append("%s is not in .gitignore, so it could get committed." % _rel(p, root))
    for item in in_code[:10]:
        warnings.append("%s line %d: %s written in the code. Move it to .env."
                        % (_rel(item["path"], root), item["line"], item["kind"]))
    if warnings:
        t.line(t.bold("Warnings"))
        for w in warnings:
            t.line("  %s %s" % (t.warn, w))
        t.line()

    if not args.dry_run:
        os.makedirs(folder, exist_ok=True)
        if new_rules or extra:
            _write(os.path.join(folder, H.RULES_FILE), rules_text)
        if not os.path.exists(os.path.join(folder, H.CONFIG_FILE)):
            _write(os.path.join(folder, H.CONFIG_FILE), json.dumps(H.DEFAULT_CONFIG, indent=2) + "\n")
        shutil.copyfile(hook_source(), os.path.join(folder, "hook.py"))
        _write(os.path.join(folder, ".gitignore"), H.LOG_FILE + "\n")

    detected = agents.detect(root, home)
    note = None
    if args.agents:
        keys = [k.strip().lower() for k in args.agents.split(",") if k.strip()]
        unknown = [k for k in keys if k not in agents.BY_KEY]
        if unknown:
            t.line(t.red("Unknown agent: %s. Choose from: %s" % (", ".join(unknown), ", ".join(AGENT_KEYS))))
            return 2
    elif args.all:
        keys = list(AGENT_KEYS)
    else:
        keys = [k for k in AGENT_KEYS if k in detected]
        if not keys:
            keys = list(agents.HOOK_AGENTS)
            note = "No AI agents found on this computer, so I set up the common ones."

    ctx = agents.Context(root, guard.rules, rule_lines(rules_text), rel_files, python=args.python,
                         ps_python="python" if args.python == "python3" else args.python,
                         sandbox=args.sandbox, dry_run=args.dry_run)
    t.line(t.bold("AI agents"))
    rows, notes, failed = [], [], False
    for key in keys:
        agent = agents.BY_KEY[key]
        try:
            changed, detail = agents.install(key, ctx)
        except agents.SetupError as exc:
            rows.append([t.bad, agent.name, str(exc), ""])
            failed = True
            continue
        rows.append([t.ok, agent.name, detail, t.dim(", ".join(changed))])
        if agent.note:
            notes.append(agent.note)
    t.rows(rows)
    if note:
        t.line(t.dim("  " + note))
    skipped = [a.name for a in agents.AGENTS if a.key not in keys]
    if skipped:
        t.line(t.dim("  Not set up: %s. Add them with --agents or --all." % ", ".join(skipped)))
    t.line()

    if args.sandbox:
        notes.append("Claude Code: the sandbox rules only work after you turn the sandbox on with /sandbox.")
    if not shutil.which(args.python.split()[0]):
        notes.append("%s was not found. Without it the hooks let everything through. "
                     "Install Python 3.9+ or pass --python." % args.python)
    if notes:
        t.line(t.bold("Before you start"))
        for n in notes:
            t.line("  " + n)
        t.line()
    t.line(t.bold("Next"))
    t.line("  secretwall doctor   test that the blocking works")
    t.line("  secretwall leaks    check if an AI agent has already seen your secrets")
    t.line("  Commit .secretwall/ and the files above so everyone on the project is protected.")
    return 1 if failed else 0


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

def _test_payloads(agent, tmp):
    env_file = os.path.join(tmp, ".env")

    def cc(tool, tool_input):  # Claude Code / Codex style
        return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input, "cwd": tmp}

    if agent in ("claude", "codex"):
        cases = [("cat .env", cc("Bash", {"command": "cat .env"}), True),
                 ("ls", cc("Bash", {"command": "ls -la"}), False)]
        if agent == "claude":
            cases.insert(0, ("reading .env", cc("Read", {"file_path": env_file}), True))
        else:
            patch = "*** Begin Patch\n*** Update File: .env\n@@\n-A=1\n+A=2\n*** End Patch\n"
            cases.insert(0, ("editing .env", cc("apply_patch", {"command": patch}), True))
        return cases
    if agent == "copilot":
        return [("reading .env", {"toolName": "view", "toolArgs": json.dumps({"path": env_file}), "cwd": tmp}, True),
                ("cat .env", {"toolName": "bash", "toolArgs": json.dumps({"command": "cat .env"}), "cwd": tmp}, True),
                ("ls", {"toolName": "bash", "toolArgs": json.dumps({"command": "ls -la"}), "cwd": tmp}, False)]
    if agent == "cursor":
        return [("reading .env", {"hook_event_name": "beforeReadFile", "file_path": env_file, "content": ""}, True),
                ("cat .env", {"hook_event_name": "beforeShellExecution", "command": "cat .env", "cwd": tmp}, True),
                ("ls", {"hook_event_name": "beforeShellExecution", "command": "ls -la", "cwd": tmp}, False)]
    if agent == "gemini":
        def gm(tool, tool_input):
            return {"hook_event_name": "BeforeTool", "tool_name": tool, "tool_input": tool_input, "cwd": tmp}
        return [("reading .env", gm("read_file", {"file_path": env_file}), True),
                ("cat .env", gm("run_shell_command", {"command": "cat .env"}), True),
                ("ls", gm("run_shell_command", {"command": "ls -la"}), False)]
    if agent == "windsurf":
        return [("reading .env", {"agent_action_name": "pre_read_code", "tool_info": {"file_path": env_file}}, True),
                ("cat .env", {"agent_action_name": "pre_run_command",
                              "tool_info": {"command_line": "cat .env", "cwd": tmp}}, True),
                ("ls", {"agent_action_name": "pre_run_command",
                        "tool_info": {"command_line": "ls -la", "cwd": tmp}}, False)]
    return []


def self_test(agent, python):
    """Run the real hook command the agent runs, in a throwaway project."""
    if os.name == "nt" or not shutil.which("sh"):
        return None, "self-test needs sh (not run on Windows)"
    with tempfile.TemporaryDirectory() as tmp:
        tmp = os.path.realpath(tmp)
        os.makedirs(os.path.join(tmp, H.DIR_NAME))
        shutil.copyfile(hook_source(), os.path.join(tmp, H.DIR_NAME, "hook.py"))
        _write(os.path.join(tmp, ".env"), "SECRETWALL_SELF_TEST=not-a-real-secret\n")
        env = dict(os.environ, CLAUDE_PROJECT_DIR=tmp, GEMINI_PROJECT_DIR=tmp,
                   GIT_CEILING_DIRECTORIES=os.path.dirname(tmp))
        command = agents.posix_command(agent, python)
        for label, payload, expect_block in _test_payloads(agent, tmp):
            try:
                proc = subprocess.run(["sh", "-c", command], input=json.dumps(payload), cwd=tmp, env=env,
                                      capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError) as exc:
                return False, "could not run the hook: %s" % exc
            blocked = proc.returncode == 2
            if blocked != expect_block:
                return False, "%s was %s" % (label, "blocked" if blocked else "NOT blocked")
            if not blocked and agent in ("cursor", "gemini") and "allow" not in proc.stdout:
                return False, "the hook did not answer 'allow'"
    return True, "blocks secret reads and shell commands"


def _python_version(python):
    try:
        out = subprocess.run(python.split() + ["-I", "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
                             capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def cmd_doctor(args):
    t = Term()
    root = find_root(args.root)
    python = args.python or default_python()
    folder = os.path.join(root, H.DIR_NAME)
    t.line(t.bold("secretwall doctor") + t.dim("  " + short_path(root)))
    problems = 0

    hook_text = _read(os.path.join(folder, "hook.py"))
    if hook_text is None:
        t.line("  %s Not set up here. Run: secretwall init" % t.bad)
        return 1
    m = re.search(r'^VERSION = "([^"]+)"', hook_text, re.M)
    installed = m.group(1) if m else "?"
    if installed == H.VERSION:
        t.line("  %s Hook installed (version %s)" % (t.ok, installed))
    else:
        t.line("  %s Hook is version %s, this secretwall is %s. Run: secretwall init" % (t.warn, installed, H.VERSION))

    version = _python_version(python)
    if version is None:
        t.line("  %s %s doesn't run. The hooks let everything through until it does." % (t.bad, python))
        problems += 1
    elif tuple(int(x) for x in version.split(".")) < (3, 9):
        t.line("  %s %s is Python %s. secretwall needs 3.9 or newer." % (t.bad, python, version))
        problems += 1
    else:
        t.line("  %s %s works (Python %s)" % (t.ok, python, version))

    rules_text, missing = _load_project(root)
    guard = H.Guard(root, H.Rules.parse(rules_text), H.load_config(root))
    files = scan.secret_files(guard)
    t.line("  %s Rules: %d, protecting %d file%s now%s" % (
        t.ok, len(guard.rules.rules), len(files), "" if len(files) == 1 else "s",
        t.dim(" (using the default rules)") if missing else ""))
    t.line()

    t.line(t.bold("AI agents"))
    rows = []
    lines = rule_lines(rules_text)
    for agent in agents.AGENTS:
        if not agents.configured(agent.key, root):
            rows.append([t.dim("-"), agent.name, t.dim("not set up")])
            continue
        status, detail = True, "ignore file"
        if agent.hooks:
            status, detail = self_test(agent.key, python)
        if agent.ignore_file:
            current = agents.block_lines(os.path.join(root, agent.ignore_file))
            if current is None:
                detail += "; %s missing" % agent.ignore_file
            elif current != lines:
                detail += "; %s is out of date (run secretwall init)" % agent.ignore_file
                status = status and None
        mark = t.ok if status else (t.dim("?") if status is None else t.bad)
        if status is False:
            problems += 1
        rows.append([mark, agent.name, detail])
    t.rows(rows)
    known = {"cursor": "Some Cursor versions ignore a hook's \"deny\" for file reads; .cursorignore covers that.",
             "codex": "Codex runs project hooks only after you approve them with /hooks.",
             "gemini": "Gemini CLI runs project hooks only after you trust them."}
    for key, text in known.items():
        if agents.configured(key, root):
            t.line(t.dim("  " + text))
    t.line()

    tracked, not_ignored = scan.git_status(root, files)
    risky = [(p, "is committed to git") for p in sorted(tracked or [])] + \
            [(p, "is not in .gitignore") for p in sorted(not_ignored or [])]
    if risky:
        t.line(t.bold("Git"))
        for p, why in risky:
            t.line("  %s %s %s" % (t.warn, _rel(p, root), why))
        t.line()

    log = _read(os.path.join(folder, H.LOG_FILE))
    if log:
        entries = [ln.split("\t") for ln in log.strip().splitlines()][-5:]
        t.line(t.bold("Recent blocks"))
        for e in entries:
            if len(e) >= 4:
                t.line("  %s  %s  %s" % (t.dim(e[0].replace("T", " ")[:16]), e[1], e[3]))
        t.line()

    if problems:
        t.line(t.red("%d problem%s found." % (problems, "" if problems == 1 else "s")))
        return 1
    t.line(t.green("All good."))
    return 0


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

def cmd_check(args):
    t = Term()
    root = find_root(args.root)
    rules_text, _ = _load_project(root)
    guard = H.Guard(root, H.Rules.parse(rules_text), H.load_config(root))
    target = " ".join(args.target)
    cwd = os.getcwd()
    exists = os.path.lexists(os.path.join(cwd, guard.expand_home(target)))
    as_command = args.command or (not exists and re.search(r"\s|[|;&<>$`]", target) is not None)
    if as_command:
        finding = H.Shell(guard, cwd).analyze(target)
    else:
        hit = guard.check(os.path.join(cwd, target))
        finding = H.Finding.read(hit) if hit else None
    if finding:
        t.line("%s %s %s" % (t.bad, t.bold("Blocked:"), finding.reason))
        return 1
    t.line("%s %s" % (t.ok, t.bold("Allowed.")))
    return 0


# ---------------------------------------------------------------------------
# leaks
# ---------------------------------------------------------------------------

def parse_size(text):
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgt]?)b?\s*", text.lower())
    if not m:
        raise argparse.ArgumentTypeError("use a size like 500M or 2G")
    value = float(m.group(1)) * (1024 ** "bkmgt".index(m.group(2) or "b"))
    return int(value) or (1 << 62)


def cmd_leaks(args):
    t = Term()
    root = find_root(args.root)
    home = os.path.expanduser("~")
    rules_text, _ = _load_project(root)
    guard = H.Guard(root, H.Rules.parse(rules_text), H.load_config(root))
    files = scan.secret_files(guard) + [os.path.abspath(f) for f in args.file]
    secrets = leaks.collect(files, root)
    if not secrets:
        t.line("No secret values to look for. secretwall looks inside the files your rules protect, like .env.")
        return 0
    places = leaks.locations(home, root) + [("custom", os.path.abspath(p)) for p in args.path]
    if not places:
        t.line("No AI agent chat logs found on this computer.")
        return 0
    names = sorted({a for a, _ in places})
    t.line("Looking for %d secret value%s from %d file%s in chat logs of: %s" % (
        len(secrets), "" if len(secrets) == 1 else "s", len(files), "" if len(files) == 1 else "s",
        ", ".join(names)))
    t.line(t.dim("Everything stays on this computer. Secret values are never printed."))
    live = t.stream.isatty() if hasattr(t.stream, "isatty") else False

    def progress(count, size):
        if live:
            t.stream.write("\r  searched %d files (%s)" % (count, human_size(size)))
            t.stream.flush()

    result = leaks.search(secrets, places, args.max_file_size, progress)
    if live:
        t.stream.write("\r" + " " * 60 + "\r")
    t.line()
    if result.hits:
        count = len(result.hits)
        t.line(t.red(t.bold("%d of your secrets %s in AI agent chat logs:" % (count, "is" if count == 1 else "are"))))
        for idx in sorted(result.hits):
            secret, entries = secrets[idx], result.hits[idx]
            seen_by = ", ".join(sorted({a for a, _, _ in entries}))
            latest = time.strftime("%Y-%m-%d", time.localtime(max(m for _, _, m in entries)))
            t.line("  %s %s  %s" % (t.bad, secret.label, t.dim(leaks.mask(secret.value, t.ellipsis))))
            t.line("      seen by %s in %d file%s, latest %s" % (
                seen_by, len(entries), "" if len(entries) == 1 else "s", latest))
            if args.verbose:
                for _, path, _ in entries[:10]:
                    t.line(t.dim("        " + short_path(path, home)))
        t.line()
        t.line(t.bold("What to do"))
        t.line("  1. Replace these keys at the service that issued them. Deleting the logs is not")
        t.line("     enough: the agent already sent the values to the AI model.")
        t.line("  2. Run `secretwall init` so agents can't read secret files again.")
    else:
        t.line("%s None of your %d secrets are in %d chat log files (%s)." % (
            t.ok, len(secrets), result.files, human_size(result.bytes)))
    if result.skipped:
        t.line()
        t.line("%s Skipped %d file%s bigger than the --max-file-size limit:" % (
            t.warn, len(result.skipped), "" if len(result.skipped) == 1 else "s"))
        for path, size in result.skipped[:3]:
            t.line(t.dim("    %s (%s)" % (short_path(path, home), human_size(size))))
        t.line(t.dim("  To search them too: secretwall leaks --max-file-size 0"))
    return 1 if result.hits else 0


# ---------------------------------------------------------------------------
# remove
# ---------------------------------------------------------------------------

def cmd_remove(args):
    t = Term()
    root = find_root(args.root)
    rules_text, _ = _load_project(root)
    guard = H.Guard(root, H.Rules.parse(rules_text), H.load_config(root))
    rel_files = [_rel(p, root) for p in scan.secret_files(guard)]
    ctx = agents.Context(root, guard.rules, rule_lines(rules_text), rel_files, dry_run=args.dry_run)
    changed_any = False
    for agent in agents.AGENTS:
        try:
            changed = agents.remove(agent.key, ctx)
        except agents.SetupError as exc:
            t.line("  %s %s: %s" % (t.bad, agent.name, exc))
            continue
        if changed:
            changed_any = True
            t.line("  %s %s  %s" % (t.ok, agent.name, t.dim(", ".join(changed))))
    if not changed_any:
        t.line("Nothing to remove.")
    folder = os.path.join(root, H.DIR_NAME)
    if args.purge and os.path.isdir(folder):
        if not args.dry_run:
            shutil.rmtree(folder)
        t.line("  %s Deleted .secretwall/" % t.ok)
    elif os.path.isdir(folder):
        t.line(t.dim("Kept .secretwall/ (your rules). Use --purge to delete it too."))
    return 0


# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(prog="secretwall",
                                     description="Keep AI coding agents away from your secrets.")
    parser.add_argument("--version", action="version", version="secretwall " + H.VERSION)
    sub = parser.add_subparsers(dest="command", metavar="command")

    p = sub.add_parser("init", help="find secret files and set up your AI agents")
    p.add_argument("--root", help="project folder (default: the git repo you are in)")
    p.add_argument("--agents", help="only these agents, comma separated: " + ",".join(AGENT_KEYS))
    p.add_argument("--all", action="store_true", help="set up every supported agent")
    p.add_argument("--python", default=default_python(), help="Python command for the hook (default: %(default)s)")
    p.add_argument("--sandbox", action="store_true", help="also add Claude Code sandbox rules")
    p.add_argument("--no-scan", action="store_true", help="don't look inside files for secrets")
    p.add_argument("--dry-run", action="store_true", help="show what would change, write nothing")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("doctor", help="check the setup and test that blocking works")
    p.add_argument("--root")
    p.add_argument("--python", help="Python command the hooks use (default: %s)" % default_python())
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("check", help="would this file or command be blocked?")
    p.add_argument("target", nargs="+", help="a file path or a shell command")
    p.add_argument("-c", "--command", action="store_true", help="treat the target as a shell command")
    p.add_argument("--root")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("leaks", help="look for your secrets in AI agents' chat logs")
    p.add_argument("--root")
    p.add_argument("--file", action="append", default=[], help="also look for the secrets in this file")
    p.add_argument("--path", action="append", default=[], help="also search this folder or file")
    p.add_argument("--max-file-size", type=parse_size, default="1G",
                   help="skip bigger log files (default: 1G, 0 = no limit)")
    p.add_argument("-v", "--verbose", action="store_true", help="list the files where secrets were found")
    p.set_defaults(func=cmd_leaks)

    p = sub.add_parser("remove", help="take secretwall out of your agents' settings")
    p.add_argument("--root")
    p.add_argument("--purge", action="store_true", help="also delete .secretwall/")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_remove)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
