"""PreToolUse hook for Claude Code and Codex (same wire format).

Two jobs. Tool calls that touch AgentSecret's own state (--protect) are refused
outright. Tool calls that would read what the user marked as protected on the
approver (a file, a file-name pattern, a string) start an approval there
automatically, and pass only if the user approves that one call.

Stdlib only and run as a script with `python -I`, so nothing from the agent's
cwd or PYTHONPATH is imported. This is a guardrail inside the agent's own OS
account, not a boundary: it matches strings, it does not confine a process.
"""
import fnmatch
import hashlib
import json
import os
import re
import shlex
import sys
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ALLOWED_PREFIX = "mcp__secret_guard__"
# The trusted CLI and package can open the vault; an agent has no reason to run them.
TRUSTED_NAMES = ("secret-guard", "secret_guard", "agentsecret")
MESSAGE = ("Secret Guard: blocked ({}). Broker state, credentials and task tokens are off limits to agent tools; "
           "use the mcp__secret_guard__* tools instead. Do not retry with a different spelling.")
VARIABLE = re.compile(r"\$(\w+)|\$\{(\w+)\}")
ASSIGNMENT = re.compile(r"^(\w+)=(.*)$", re.S)
# Absolute paths buried in a quoted argument such as `python -c "open('/x/y')"`.
# Commands that read whole trees without naming the files in them.
RECURSIVE = re.compile(r"\b(rg|ag|ack|find|tar|zip|rsync|grep\s+(-\w*[rR]|--recursive)|git\s+grep|cp\s+-\w*[rRa]|scp\s+-\w*r)\b")
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
        # A user's rule (a file somewhere in the workspace) must not fire on every command run
        # near it: a directory above it counts only for commands that read whole trees.
        self.user_rule = False

    def above(self, relation, command):
        return relation and (relation == "inside" or not self.user_rule or bool(RECURSIVE.search(command)))

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
        if self.above(self.relation(cwd), command):
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
                if self.above(self.relation(path), command) or (re.search(r"[*?\[{]", candidate) and self.glob_reaches(path)):
                    return "command reaches a protected path or a directory above one"
                if candidate.startswith("/"):
                    break

    def check(self, event):
        tool, args = event["tool_name"], event.get("tool_input") or {}
        cwd = event.get("cwd") or os.getcwd()
        if tool.startswith(ALLOWED_PREFIX):
            return None
        command = args.get("command")
        if isinstance(command, list) and all(isinstance(c, str) for c in command):
            # Codex may pass argv, e.g. ["bash", "-lc", "cat x"].
            command = " ".join(command)
        if isinstance(command, str):
            return self.check_command(command, cwd)
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


SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__"}
WAIT_SECONDS = 110  # Just under the lifetime of one approval request.
READ_MESSAGE = ("AgentSecret: blocked. This call would read content the user protected ({}), so an approval was requested "
                "on the user's approver and the result is: {}. Do not retry with a different spelling. If you need to "
                "use a credential, ask for it with the mcp__secret_guard__* tools instead of reading it.")


def match_rule(event, rules, home=None):
    """The first protection rule this tool call would touch, or None."""
    tool, args = event["tool_name"], event.get("tool_input") or {}
    cwd = event.get("cwd") or os.getcwd()
    home = home or os.path.expanduser("~")
    if tool.startswith(ALLOWED_PREFIX):
        return None
    raw = fold(json.dumps(args, ensure_ascii=False))
    texts = (raw, fold(re.sub(r"['\"\\]", "", json.dumps(args, ensure_ascii=False))))
    strings, pending = [], [args]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str) and len(value) < 4096 and "\n" not in value:
            strings.append(value)  # File contents being written are not paths.
    command = args.get("command")
    command = " ".join(command) if isinstance(command, list) and all(isinstance(c, str) for c in command) else command if isinstance(command, str) else ""
    strings.append(command)
    commands = (fold(command), fold(re.sub(r"['\"\\]", "", command)))
    words = {w for s in strings for w in re.split(r"[\s;&|<>()'\"`=:,]+", s) if w}
    for rule in rules:
        value = rule["value"]
        if rule["kind"] == "text":
            if any(fold(value) in text for text in texts):
                return rule
            continue
        pattern = fold(value)
        if "/" in value or value.startswith("~"):
            target = os.path.join(home, value[2:]) if value.startswith("~/") else home if value == "~" else value
            if not re.search(r"[*?\[]", value):
                # A fixed file or directory: the same checks that guard AgentSecret's own state.
                policy = Policy([target], home=home)
                policy.names, policy.user_rule = [], True
                if policy.check(event):
                    return rule
            elif any(fnmatch.fnmatchcase(fold(os.path.normpath(os.path.join(cwd, os.path.expanduser(w)))), fold(target)) for w in words):
                return rule
            continue
        # A file name or file-name pattern such as .env or *.pem, wherever the file is.
        if any(fnmatch.fnmatchcase(part, pattern) for w in words for part in fold(w).split("/")):
            return rule
        if len(value) >= 4 and not re.search(r"[*?\[]", value) and any(pattern in text for text in commands):
            return rule
        # A content search reads every file below its root without naming any.
        roots = [args.get("path") or "."] if tool == "Grep" else []
        if RECURSIVE.search(command):
            roots = ["."] + [w for w in words if os.path.isdir(os.path.join(cwd, os.path.expanduser(w)))]
        seen = 0
        for root in roots:
            for _, dirs, files in os.walk(os.path.join(cwd, os.path.expanduser(root))):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                seen += len(files) + 1
                if any(fnmatch.fnmatchcase(fold(name), pattern) for name in files):
                    return rule
                if seen > 20000:
                    break
    return None


def post(url, token, route, body):
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or (parts.scheme == "http" and parts.hostname not in {"127.0.0.1", "localhost"}):
        raise ValueError("invalid injector address")

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *unused):
            return None
    request = Request(url.rstrip("/") + route, data=json.dumps(body).encode(), method="POST",
                      headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=10) as response:
        return json.loads(response.read(1024 * 1024))


def guarded(event, url, token_file, wait=WAIT_SECONDS, call=post):
    """Ask the injector for the user's rules; a matching call waits for the user's decision on the approver."""
    with open(token_file) as f:
        token = f.read().strip()
    rule = match_rule(event, call(url, token, "/rules", {})["rules"])
    if not rule:
        return None
    args = event.get("tool_input") or {}
    command = args.get("command")
    summary = command if isinstance(command, str) else json.dumps(args, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha256(json.dumps([event["tool_name"], args], sort_keys=True).encode()).hexdigest()
    out = call(url, token, "/access", {"tool": event["tool_name"][:128], "rule": rule, "summary": summary[:300], "call": digest})
    deadline = time.monotonic() + wait
    while out.get("state") == "pending" and time.monotonic() < deadline:
        time.sleep(1)
        out = call(url, token, "/status", {"operation_id": out["operation_id"]})
    if out.get("state") == "approved":
        return None
    result = out.get("message") or ("no answer yet" if out.get("state") == "pending" else str(out.get("state")))
    return READ_MESSAGE.format(("file " if rule["kind"] == "path" else "string ") + rule["value"], result)


def main(argv=None):
    # Exit 2 blocks the tool call and shows stderr to the model. Any failure blocks too.
    try:
        argv = sys.argv[1:] if argv is None else argv
        options = {"--protect": [], "--guard-url": [], "--token-file": []}
        if len(argv) % 2:
            raise ValueError
        for flag, value in zip(argv[::2], argv[1::2]):
            options[flag].append(value)
        if not options["--protect"] or len(options["--guard-url"]) != len(options["--token-file"]) or len(options["--guard-url"]) > 1:
            raise ValueError
        event = json.load(sys.stdin)
        reason = Policy(options["--protect"]).check(event)
        message = MESSAGE.format(reason) if reason else None
        if not reason and options["--guard-url"]:
            message = guarded(event, options["--guard-url"][0], options["--token-file"][0])
    except Exception:
        message = MESSAGE.format("hook could not evaluate this call")
    if message:
        print(message, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
