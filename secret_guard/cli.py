import argparse
import getpass
import json
import os
from pathlib import Path
import shlex
import sys


def parser():
    p = argparse.ArgumentParser(description="Secret Guard compatibility MVP")
    p.add_argument("--state", default=str(Path.home() / ".local/share/secret-guard"), help="Trusted broker state; never mount into agent")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    s = sub.add_parser("secret-add")
    s.add_argument("alias")
    s.add_argument("--repo", action="append", required=True)
    s.add_argument("--user", required=True)
    s.add_argument("--project", required=True)
    s = sub.add_parser("task-create")
    s.add_argument("--user", required=True)
    s.add_argument("--project", required=True)
    s.add_argument("--agent", default="codex")
    s.add_argument("--token-file", required=True)
    s = sub.add_parser("device-register")
    s.add_argument("--user", required=True)
    s.add_argument("--device", required=True)
    s.add_argument("--jwk-file", required=True)
    s = sub.add_parser("revoke")
    s.add_argument("kind", choices=["task", "device", "secret", "operation"])
    s.add_argument("identity")
    sub.add_parser("activity")
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--agent-port", type=int, default=8765)
    s.add_argument("--approval-port", type=int, default=8766)
    s.add_argument("--cert")
    s.add_argument("--key")
    s = sub.add_parser("mcp")
    s.add_argument("--url", default="http://127.0.0.1:8765", help="Broker or injector agent API")
    s.add_argument("--token-file", required=True)
    s = sub.add_parser("claude-config", help="Write a per-task Claude Code --mcp-config file")
    s.add_argument("--url", default="http://127.0.0.1:8765")
    s.add_argument("--token-file", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--settings-out", help="Also write a --settings file whose PreToolUse hook keeps Claude's own tools away from broker state and the token")
    s.add_argument("--protect", action="append", default=[], help="Extra path the hook must refuse, e.g. the approval browser profile (repeatable)")
    s = sub.add_parser("codex-config", help="Write a per-task Codex launcher: MCP server, sandbox read-deny profile and PreToolUse hook")
    s.add_argument("--url", default="http://127.0.0.1:8765")
    s.add_argument("--token-file", required=True)
    s.add_argument("--out", required=True, help="Launcher script; run it in place of `codex`")
    s.add_argument("--codex", default="codex")
    s.add_argument("--protect", action="append", default=[], help="Extra path the agent must not read (repeatable)")
    return p


def claude_mcp_config(token_file, url="http://127.0.0.1:8765"):
    # Holds the token file path, never the token. PYTHONPATH lets the bridge
    # start from any cwd, installed or not; Claude Code has no per-server cwd.
    return {"mcpServers": {"secret_guard": {"type": "stdio", "command": sys.executable,
            "args": ["-m", "secret_guard.cli", "mcp", "--url", url, "--token-file", str(Path(token_file).resolve())],
            "env": {"PYTHONPATH": str(Path(__file__).resolve().parent.parent)}}}}


def claude_settings(protect):
    # Guardrail, not a boundary: the hook runs as the agent's own OS user.
    protect = [str(Path(p).expanduser().resolve()) for p in protect]
    hook = [sys.executable, "-I", str(Path(__file__).resolve().with_name("claude_hook.py"))]
    command = shlex.join(hook + [x for p in protect for x in ("--protect", p)])
    deny = [f"{tool}(/{p}{suffix})" for p in protect for tool in ("Read", "Edit") for suffix in ("", "/**")]
    return {"permissions": {"deny": deny},
            "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 10}]}]}}


def toml(value):
    if isinstance(value, dict):
        return "{" + ",".join(f"{json.dumps(k)}={toml(v)}" for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(toml(v) for v in value) + "]"
    return json.dumps(value)


def codex_overrides(token_file, protect, url="http://127.0.0.1:8765"):
    # Passed as -c overrides so the user's ~/.codex/config.toml is never edited.
    # The sandbox profile is the enforcing part: Codex applies it to every shell
    # command through the OS sandbox, however the path is spelled.
    server = claude_mcp_config(token_file, url)["mcpServers"]["secret_guard"]
    return {"mcp_servers.secret_guard": {k: server[k] for k in ("command", "args", "env")},
            "permissions.secret_guard.extends": ":workspace",
            "permissions.secret_guard.filesystem": {str(Path(p).expanduser().resolve()): "none" for p in protect},
            "default_permissions": "secret_guard",
            "hooks.PreToolUse": claude_settings(protect)["hooks"]["PreToolUse"]}


def exclusive_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(value, f, indent=2)


def main():
    args = parser().parse_args()
    if args.command == "mcp":
        # The bridge deliberately does not open the broker database or vault.
        from .mcp import run
        run(args.url, Path(args.token_file).read_text().strip())
        return
    if args.command == "claude-config":
        # No broker access either; refuse overwrite like task-create.
        if not Path(args.token_file).is_file():
            sys.exit("Token file not found; run task-create first.")
        exclusive_json(args.out, claude_mcp_config(args.token_file, args.url))
        written = {"mcp_config": str(Path(args.out).resolve())}
        if args.settings_out:
            # The package directory is protected so the hook cannot be edited away mid-session.
            protect = [args.state, args.token_file, args.out, args.settings_out, Path(__file__).resolve().parent, *args.protect]
            exclusive_json(args.settings_out, claude_settings(protect))
            written["settings"] = str(Path(args.settings_out).resolve())
        print(json.dumps(written))
        return
    if args.command == "codex-config":
        if not Path(args.token_file).is_file():
            sys.exit("Token file not found; run task-create first.")
        protect = [args.state, args.token_file, args.out, Path(__file__).resolve().parent, *args.protect]
        overrides = codex_overrides(args.token_file, protect, args.url)
        lines = ["#!/bin/sh", "# Generated by secret-guard codex-config for one task. Holds the token file path, never the token.",
                 "exec " + shlex.quote(args.codex) + " \\"]
        lines += [f"  -c {shlex.quote(key + '=' + toml(value))} \\" for key, value in overrides.items()]
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines + ['  "$@"']) + "\n")
        print(json.dumps({"launcher": str(Path(args.out).resolve())}))
        return
    from .broker import Broker, GuardError
    try:
        broker = Broker(args.state)
        if args.command == "init":
            print("Initialized trusted broker state.")
        elif args.command == "secret-add":
            broker.add_secret(args.alias, getpass.getpass("Credential (hidden): "), args.repo, args.user, args.project)
            print("Credential encrypted; policy updated; previous grants revoked.")
        elif args.command == "task-create":
            # Refuse overwrite; tokens never printed or placed in command arguments.
            fd = os.open(args.token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            task = None
            try:
                with os.fdopen(fd, "w") as f:
                    task = broker.new_task(args.user, args.project, args.agent)
                    f.write(task["token"] + "\n")
            except BaseException:
                if task:
                    broker.revoke("task", task["task_id"])
                Path(args.token_file).unlink(missing_ok=True)
                raise
            print(json.dumps({"task_id": task["task_id"], "token_file": str(Path(args.token_file).resolve())}))
        elif args.command == "device-register":
            broker.register_device(args.device, args.user, json.loads(Path(args.jwk_file).read_text()))
            print("Device registered through trusted desktop CLI.")
        elif args.command == "revoke":
            broker.revoke(args.kind, args.identity)
            print("Revoked. Already-started external operations require reconciliation.")
        elif args.command == "activity":
            print(json.dumps(broker.activity(), indent=2))
        elif args.command == "serve":
            from .server import serve
            serve(broker, args.host, args.agent_port, args.approval_port, args.cert, args.key)
    except KeyboardInterrupt:
        pass
    except GuardError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("Trusted command failed; check inputs and permissions.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
