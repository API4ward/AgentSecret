"""PreToolUse and PostToolUse hook for Claude Code and Codex (same input; `--agent codex` selects Codex's output).

Before a tool runs: calls that touch AgentSecret's own state (--protect) are
refused outright, and a call that carries a credential reference such as
{{secretref:age}} starts an approval; approved, the reference becomes the
credential in the tool's input and nowhere else.

After a tool runs, before the model sees the result: the result is sent to the
injector, which holds matchers compiled from the user's credentials. If one is
found an approval starts; approved, the result reaches the model with a
reference in place of the credential, otherwise the text is withheld.

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


WAIT_SECONDS = 110  # Just under the lifetime of one approval request.
REF = re.compile(r"\{\{secretref:([A-Za-z0-9_.-]{1,64})\}\}")
WITHHELD = "[AgentSecret: this text contains a credential of the user and was withheld ({}). Do not try to read it another way.]"
FILL_MESSAGE = ("AgentSecret: blocked. This call uses the credential reference(s) {}, so an approval was requested on the "
                "user's approver and the result is: {}. Do not retry with a different spelling.")


def strings_of(value):
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings_of(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings_of(v)]
    return [value] if isinstance(value, str) else []


def rewrite(value, texts):
    """The same structure with its strings replaced, in the order strings_of lists them."""
    if isinstance(value, dict):
        return {k: rewrite(v, texts) for k, v in value.items()}
    if isinstance(value, list):
        return [rewrite(v, texts) for v in value]
    return texts.pop(0) if isinstance(value, str) else value


def ask(call, url, token, kind, event, names, wait):
    """Start an approval for this tool call and wait for the user's answer on the approver."""
    args = event.get("tool_input") or {}
    command = args.get("command")
    summary = command if isinstance(command, str) else json.dumps(args, ensure_ascii=False, sort_keys=True)
    target = next((args[k] for k in ("file_path", "notebook_path", "path", "url") if isinstance(args.get(k), str)), "")
    digest = hashlib.sha256(json.dumps([event["tool_name"], args], sort_keys=True).encode()).hexdigest()
    out = call(url, token, "/hook", {"kind": kind, "tool": event["tool_name"][:128], "target": target[:300],
                                     "summary": REF.sub("…", summary)[:300] if kind == "reveal" else summary[:300], "call": digest, "secrets": names})
    deadline = time.monotonic() + wait
    while out.get("state") == "pending" and time.monotonic() < deadline:
        time.sleep(0.5)
        out = call(url, token, "/status", {"operation_id": out["operation_id"]})
    return out


def outcome(out):
    return out.get("message") or ("no answer yet" if out.get("state") == "pending" else str(out.get("state")))


def fill(event, url, token, wait=WAIT_SECONDS, call=None):
    """(new tool input, None) when references were approved and filled in, (None, message) when
    the call must not run, (None, None) when the call carries no reference."""
    call = call or post
    args = event.get("tool_input") or {}
    texts = strings_of(args)
    names = sorted({name for text in texts for name in REF.findall(text)})
    if not names or event["tool_name"].startswith(ALLOWED_PREFIX):
        return None, None
    out = ask(call, url, token, "fill", event, names, wait)
    if out.get("state") != "approved":
        return None, FILL_MESSAGE.format(", ".join(names), outcome(out))
    values = call(url, token, "/take", {"operation_id": out["operation_id"]})["values"]
    return rewrite(args, [REF.sub(lambda m: values[m.group(1)], text) for text in texts]), None


def reveal(event, url, token, wait=WAIT_SECONDS, call=None):
    """The tool result as the model may see it, or None when it holds no credential."""
    call = call or post
    response = event.get("tool_response")
    texts = strings_of(response)
    if not texts or event["tool_name"].startswith(ALLOWED_PREFIX):
        return None
    found = call(url, token, "/scan", {"texts": texts})["found"]
    names = sorted({hit[2] for hits in found for hit in hits})
    if not names:
        return None
    out = ask(call, url, token, "reveal", event, names, wait)
    approved = out.get("state") == "approved"
    for i, hits in enumerate(found):
        if hits and approved:
            data = texts[i].encode()
            for start, end, alias in reversed(hits):
                data = data[:start] + ("{{secretref:" + alias + "}}").encode() + data[end:]
            texts[i] = data.decode(errors="replace")
        elif hits:
            texts[i] = WITHHELD.format(outcome(out))
    return rewrite(response, texts)


def replaced(result, agent):
    """The hook answer that puts `result` where the model would have seen the tool result."""
    if agent == "codex":
        # Codex rejects updatedToolOutput as invalid and then hands the model the original result.
        # It does accept a blocked result, and the reason given takes the place of the tool result.
        return {"decision": "block", "reason": result if isinstance(result, str) and result.strip() else json.dumps(result, ensure_ascii=False)}
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": result}}


def post(url, token, route, body):
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or (parts.scheme == "http" and parts.hostname not in {"127.0.0.1", "localhost"}):
        raise ValueError("invalid injector address")

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *unused):
            return None
    request = Request(url.rstrip("/") + route, data=json.dumps(body).encode(), method="POST",
                      headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=60) as response:
        return json.loads(response.read(32 * 1024 * 1024))


def main(argv=None):
    # PreToolUse: exit 2 blocks the call and shows stderr to the model; any failure blocks too.
    # PostToolUse: the tool already ran, so a failure withholds its result instead.
    event = {}
    argv = sys.argv[1:] if argv is None else argv
    # Known before anything can fail: a failure must still be answered in the agent's own format.
    agent = "codex" if ["--agent", "codex"] in [argv[i:i + 2] for i in range(0, len(argv), 2)] else None
    try:
        options = {"--protect": [], "--guard-url": [], "--token-file": [], "--agent": []}
        if len(argv) % 2:
            raise ValueError
        for flag, value in zip(argv[::2], argv[1::2]):
            options[flag].append(value)
        if not options["--protect"] or len(options["--guard-url"]) != len(options["--token-file"]) or len(options["--guard-url"]) > 1:
            raise ValueError
        event = json.load(sys.stdin)
        guard = options["--guard-url"] and (options["--guard-url"][0], open(options["--token-file"][0]).read().strip())
        if event.get("hook_event_name") == "PostToolUse":
            changed = reveal(event, *guard) if guard else None
            if changed is not None:
                print(json.dumps(replaced(changed, agent)))
            return
        reason = Policy(options["--protect"]).check(event)
        message = MESSAGE.format(reason) if reason else None
        if not reason and guard:
            changed, message = fill(event, *guard)
            if changed is not None:
                # The user approved this exact call on the approver; the credential exists only in the tool's input.
                print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow",
                                                         "permissionDecisionReason": "AgentSecret: approved on the user's approver", "updatedInput": changed}}))
    except Exception:
        if event.get("hook_event_name") == "PostToolUse":
            print(json.dumps(replaced(WITHHELD.format("hook could not check this result"), agent)))
            return
        message = MESSAGE.format("hook could not evaluate this call")
    if message:
        print(message, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
