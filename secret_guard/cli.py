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
    s = sub.add_parser("mcp")
    s.add_argument("--url", default="http://127.0.0.1:8765")
    s.add_argument("--token-file", required=True)
    return p


def main():
    args = parser().parse_args()
    if args.command == "mcp":
        # The bridge deliberately does not open the broker database or vault.
        from .mcp import run
        run(args.url, Path(args.token_file).read_text().strip())
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
