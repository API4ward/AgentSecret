import argparse
import getpass
import json
import os
from pathlib import Path
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
    s.add_argument("--agent-socket", help="Serve the agent API on this Unix socket instead of TCP (isolated worker domain)")
    s.add_argument("--container-approval-bind", help="Bind address inside a broker container whose approval port is published to host loopback only")
    s = sub.add_parser("mcp")
    s.add_argument("--url", default="http://127.0.0.1:8765", help="Broker agent API; unix:///absolute/path.sock inside an isolated worker")
    s.add_argument("--token-file", required=True)
    s = sub.add_parser("claude-config", help="Write a per-task Claude Code --mcp-config file")
    s.add_argument("--url", default="http://127.0.0.1:8765")
    s.add_argument("--token-file", required=True)
    s.add_argument("--out", required=True)
    return p


def claude_mcp_config(token_file, url="http://127.0.0.1:8765"):
    # Holds the token file path, never the token. PYTHONPATH lets the bridge
    # start from any cwd, installed or not; Claude Code has no per-server cwd.
    return {"mcpServers": {"secret_guard": {"type": "stdio", "command": sys.executable,
            "args": ["-m", "secret_guard.cli", "mcp", "--url", url, "--token-file", str(Path(token_file).resolve())],
            "env": {"PYTHONPATH": str(Path(__file__).resolve().parent.parent)}}}}


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
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(claude_mcp_config(args.token_file, args.url), f, indent=2)
        print(json.dumps({"mcp_config": str(Path(args.out).resolve())}))
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
            serve(broker, args.host, args.agent_port, args.approval_port, args.cert, args.key, args.agent_socket, args.container_approval_bind)
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
