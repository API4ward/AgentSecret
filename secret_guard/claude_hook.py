"""Claude Code PreToolUse hook: refuse tool calls that touch protected paths.

Stdlib only and run as a script with `python -I`, so nothing from the agent's
cwd or PYTHONPATH is imported. This is a guardrail inside the agent's own OS
account, not a boundary: it matches strings, it does not confine a process.
"""
import fnmatch
import json
import os
import re
import shlex
import sys

ALLOWED_PREFIX = "mcp__secret_guard__"
# The trusted CLI and package can open the vault; an agent has no reason to run them.
TRUSTED_NAMES = ("secret-guard", "secret_guard", "guardctl")
MESSAGE = ("Secret Guard: blocked ({}). Broker state, credentials and task tokens are off limits to agent tools; "
           "use the mcp__secret_guard__* tools instead. Do not retry with a different spelling.")
VARIABLE = re.compile(r"\$(\w+)|\$\{(\w+)\}")
ASSIGNMENT = re.compile(r"^(\w+)=(.*)$", re.S)
# Absolute paths buried in a quoted argument such as `python -c "open('/x/y')"`.
EMBEDDED = re.compile(r"(?:~|\$\w+|\$\{\w+\})?/[\w.~-][^\s'\"`;,()<>|&=:]*")


def fold(path):
    # macOS volumes are usually case-insensitive; folding everywhere only over-blocks.
    return path.casefold()


class Policy:
    def __init__(self, protect, home=None):
        self.home = home or os.path.expanduser("~")
        plain = {os.path.abspath(os.path.expanduser(p)) for p in protect}
        self.paths = sorted({fold(v) for p in plain for v in (p, os.path.realpath(p))})
        names = {os.path.basename(p) for p in plain} | set(TRUSTED_NAMES)
        self.names = sorted(fold(n) for n in names if len(n) >= 4)

    def relation(self, path):
        """'inside' if path is a protected path or below one, 'ancestor' if a protected path is below it."""
        for candidate in {fold(os.path.normpath(path)), fold(os.path.realpath(path))}:
            candidate = "/" + candidate.lstrip("/")
            for p in self.paths:
                if candidate == p or candidate.startswith(p + "/"):
                    return "inside"
                if p.startswith(candidate.rstrip("/") + "/"):
                    return "ancestor"
        return None

    def glob_reaches(self, pattern):
        """True if a shell or Glob pattern can match a protected path, something below it, or a directory above it."""
        segments = fold(os.path.normpath(re.sub(r"\{[^{}]*\}", "*", pattern))).split("/")
        for p in self.paths:
            target = p.split("/")
            for i, segment in enumerate(segments):
                if segment == "**" or i >= len(target):
                    return True
                if not fnmatch.fnmatchcase(target[i], segment):
                    break
            else:
                return True
        return False

    def expand(self, word, variables):
        word = VARIABLE.sub(lambda m: variables.get(m.group(1) or m.group(2), m.group(0)), word)
        if word == "~" or word.startswith("~/"):
            return self.home + word[1:]
        return os.path.expanduser(word) if word.startswith("~") else word

    def check_path(self, value, cwd, ancestors=False):
        relation = self.relation(os.path.join(cwd, os.path.expanduser(value)))
        if relation == "inside" or (ancestors and relation):
            return "protected path"

    def check_command(self, command, cwd):
        if self.relation(cwd):
            # Relative names and recursive scans cannot be judged from here.
            return "shell started in or above a protected path; keep broker state and token files outside the workspace"
        for text in (fold(command), fold(re.sub(r"['\"\\]", "", command))):
            if any(name in text for name in self.names) or any(p in text for p in self.paths):
                return "command names a protected file or the trusted CLI"
        try:
            lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
            lexer.whitespace_split, lexer.commenters = True, ""
            words = list(lexer)
        except ValueError:
            words = re.split(r"[\s;&|<>()'\"]+", command)
        variables = {**os.environ, "HOME": self.home, "PWD": cwd}
        candidates = []
        for word in words:
            word = word.strip("`")
            assignment = ASSIGNMENT.match(word)
            if assignment:
                variables[assignment.group(1)] = self.expand(assignment.group(2), variables)
            # --file=/x, if=/x, host:/x, a,b
            for piece in {word, *re.split(r"[=:,]", word)}:
                if piece:
                    candidates.append(self.expand(piece, variables))
        candidates += [self.expand(m, variables) for m in EMBEDDED.findall(command)]
        # Any absolute path may be a `cd` target for a later relative word.
        bases = [cwd] + [c for c in candidates if c.startswith("/")][:40]
        for candidate in candidates:
            for base in bases:
                path = os.path.join(base, candidate)
                if self.relation(path) or (re.search(r"[*?\[{]", candidate) and self.glob_reaches(path)):
                    return "command reaches a protected path or a directory above one"
                if candidate.startswith("/"):
                    break

    def check(self, event):
        tool, args = event["tool_name"], event.get("tool_input") or {}
        cwd = event.get("cwd") or os.getcwd()
        if tool.startswith(ALLOWED_PREFIX):
            return None
        if isinstance(args.get("command"), str):
            return self.check_command(args["command"], cwd)
        if tool == "Grep":
            return self.check_path(args.get("path") or ".", cwd, ancestors=True)
        if tool == "Glob":
            root = os.path.join(cwd, os.path.expanduser(args.get("path") or "."))
            if self.relation(root) == "inside" or self.glob_reaches(os.path.join(root, args.get("pattern") or "**")):
                return "pattern reaches a protected path"
            return None
        # Read, Edit, Write, NotebookEdit and anything unknown: every short string may be a path.
        pending = [args]
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
            elif isinstance(value, str) and value and len(value) < 4096 and "\n" not in value:
                reason = self.check_path(value, cwd)
                if reason:
                    return reason


def main(argv=None):
    # Exit 2 blocks the tool call and shows stderr to the model. Any failure blocks too.
    try:
        argv = sys.argv[1:] if argv is None else argv
        protect = [argv[i + 1] for i in range(0, len(argv), 2) if argv[i] == "--protect"]
        if not protect or len(protect) * 2 != len(argv):
            raise ValueError
        reason = Policy(protect).check(json.load(sys.stdin))
    except Exception:
        reason = "hook could not evaluate this call"
    if reason:
        print(MESSAGE.format(reason), file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
