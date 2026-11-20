"""Trusted CLI for the split deployment: relay server, injector, approver.

    agentsecret relay    init | device-register | serve | revoke | activity
    agentsecret injector init | pairing | pair-approver | task-create | serve | revoke | activity
    agentsecret approver init | pairing | pair-injector | secret-add | run | revoke | activity

The agent still connects with `secret-guard mcp --url <injector agent API> --token-file ...`.
"""
import argparse
import getpass
import json
import os
from pathlib import Path
import sys
import time

from . import protocol

BASE = Path.home() / ".local/share/agentsecret"


def parser():
    p = argparse.ArgumentParser(prog="agentsecret", description="AgentSecret: approver, relay server and injector")
    roles = p.add_subparsers(dest="role", required=True)

    r = roles.add_parser("relay", help="Server that connects approvers and injectors; stores no credentials")
    r.add_argument("--state", default=str(BASE / "relay"))
    sub = r.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    s = sub.add_parser("device-register", help="Register a device from its pairing file (public keys only)")
    s.add_argument("--pairing-file", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8780)
    s.add_argument("--cert")
    s.add_argument("--key")
    s.add_argument("--bind", help="Bind address when it differs from the public host name")
    s = sub.add_parser("revoke")
    s.add_argument("kind", choices=["device", "request"])
    s.add_argument("identity")
    sub.add_parser("activity")

    r = roles.add_parser("injector", help="Runs beside the agent; holds a credential only while one request executes")
    r.add_argument("--state", default=str(BASE / "injector"), help="Trusted injector state; keep agents away from it")
    sub = r.add_subparsers(dest="command", required=True)
    s = sub.add_parser("init")
    s.add_argument("--user", required=True)
    s.add_argument("--relay", required=True, help="Relay URL, e.g. https://relay.example.com:8780")
    s = sub.add_parser("pairing", help="Write this injector's public keys for the approver and the relay")
    s.add_argument("--out", required=True)
    s = sub.add_parser("pair-approver")
    s.add_argument("--pairing-file", required=True)
    s = sub.add_parser("task-create")
    s.add_argument("--project", required=True)
    s.add_argument("--agent", default="codex")
    s.add_argument("--token-file", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--agent-port", type=int, default=8765)
    s = sub.add_parser("revoke")
    s.add_argument("kind", choices=["task", "approver", "operation"])
    s.add_argument("identity")
    sub.add_parser("activity")

    r = roles.add_parser("approver", help="Stores credentials and approves requests (terminal reference approver)")
    r.add_argument("--state", default=str(BASE / "approver"), help="Holds every credential; never place on the agent's machine")
    sub = r.add_subparsers(dest="command", required=True)
    s = sub.add_parser("init")
    s.add_argument("--user", required=True)
    s.add_argument("--relay", required=True)
    s = sub.add_parser("pairing")
    s.add_argument("--out", required=True)
    s = sub.add_parser("pair-injector")
    s.add_argument("--pairing-file", required=True)
    s = sub.add_parser("secret-add")
    s.add_argument("alias")
    s.add_argument("--repo", action="append", required=True)
    sub.add_parser("run", help="Show pending requests and approve or deny each at the keyboard")
    s = sub.add_parser("revoke")
    s.add_argument("kind", choices=["secret", "injector"])
    s.add_argument("identity")
    sub.add_parser("activity")
    return p


def write_new(path, text):
    # Refuse to overwrite; pairing files and tokens are created exactly once.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def read_pairing(path, kind):
    data = json.loads(Path(path).read_text())
    if data.get("kind") != kind:
        sys.exit(f"Expected a pairing file from a {kind}.")
    return data


def describe(payload):
    lines = [f"  项目 {payload['project']} · 任务 {payload['task']} · 凭据 {payload['secret_id']}"]
    if payload["kind"] == "use":
        d = payload["details"]
        lines.append(f"  操作 {d['method']} https://{d['host']}{d['path']}?{d['query']}")
    else:
        once = payload["details"]["type"] == "once"
        lines.append("  操作 允许本任务引用该凭据（" + ("一次性：只能发起一次使用申请" if once else "长期：批准后 1 小时内可反复申请使用") + "）；每次使用仍需单独批准")
    lines.append(f"  注入工具 {payload['injector']} · 有效至 {time.strftime('%H:%M:%S', time.localtime(payload['expires_at']))}")
    return "\n".join(lines)


def approve_loop(approver):
    print("审批端已连接。Ctrl-C 退出。", flush=True)
    seen = set()
    while True:
        for item in approver.pending():
            if item["request_id"] in seen:
                continue
            seen.add(item["request_id"])
            payload = item["payload"]
            print("\n" + ("允许这一次具体使用？" if payload.get("kind") == "use" else "允许任务引用凭据？"))
            if item["problem"]:
                # Rules come before the prompt: a forbidden request is rejected with its reason, never offered.
                print(f"  {'已自动拒绝并告知调用方' if item['rejected'] else '不能批准'}：{protocol.explain(item['problem'])}")
                continue
            print(describe(payload))
            answer = input("  批准输入 yes，其余任意输入为拒绝: ").strip()
            print("  " + approver.decide(item, "approve" if answer == "yes" else "deny")["state"])
        time.sleep(1)


def main():
    args = parser().parse_args()
    from .broker import GuardError
    try:
        if args.role == "relay":
            from .relay import Relay
            relay = Relay(args.state)
            if args.command == "init":
                print("Initialized relay state. It stores no credentials.")
            elif args.command == "device-register":
                d = json.loads(Path(args.pairing_file).read_text())
                relay.register_device(d["device"], d["user"], d["kind"], d["jwk"], d.get("enc_jwk"))
                print("Device registered through trusted relay CLI.")
            elif args.command == "serve":
                from .split_server import serve_relay
                serve_relay(relay, args.host, args.port, args.cert, args.key, args.bind)
            elif args.command == "revoke":
                relay.revoke(args.kind, args.identity)
                print("Revoked.")
            elif args.command == "activity":
                print(json.dumps(relay.activity(), indent=2))
        elif args.role == "injector":
            from .injector import Injector
            if args.command == "init":
                injector = Injector(args.state, user=args.user, relay=args.relay)
                print(json.dumps({"device": injector.device}))
                return
            injector = Injector(args.state)
            if args.command == "pairing":
                write_new(args.out, json.dumps(injector.pairing(), indent=2))
                print(json.dumps({"pairing_file": str(Path(args.out).resolve())}))
            elif args.command == "pair-approver":
                d = read_pairing(args.pairing_file, "approver")
                injector.pair_approver(d["device"], d["user"], d["jwk"])
                print("Approver paired. Only its signed decisions will be accepted.")
            elif args.command == "task-create":
                task = None
                try:
                    task = injector.new_task(args.project, args.agent)
                    write_new(args.token_file, task["token"] + "\n")
                except BaseException:
                    if task:
                        injector.revoke("task", task["task_id"])
                    raise
                print(json.dumps({"task_id": task["task_id"], "token_file": str(Path(args.token_file).resolve())}))
            elif args.command == "serve":
                from .split_server import serve_injector
                serve_injector(injector, args.host, args.agent_port)
            elif args.command == "revoke":
                injector.revoke(args.kind, args.identity)
                print("Revoked. Already-started external operations require reconciliation.")
            elif args.command == "activity":
                print(json.dumps(injector.activity(), indent=2))
        else:
            from .approver import Approver
            if args.command == "init":
                approver = Approver(args.state, user=args.user, relay=args.relay)
                print(json.dumps({"device": approver.device}))
                return
            approver = Approver(args.state)
            if args.command == "pairing":
                write_new(args.out, json.dumps(approver.pairing(), indent=2))
                print(json.dumps({"pairing_file": str(Path(args.out).resolve())}))
            elif args.command == "pair-injector":
                d = read_pairing(args.pairing_file, "injector")
                approver.pair_injector(d["device"], d["user"], d["jwk"], d["enc_jwk"])
                print("Injector paired. Credentials are sealed to this injector only.")
            elif args.command == "secret-add":
                approver.add_secret(args.alias, getpass.getpass("密码（不回显；内容由你管理，按原样保存）: "), args.repo)
                print("Credential stored on this approver.")
            elif args.command == "run":
                approve_loop(approver)
            elif args.command == "revoke":
                approver.revoke(args.kind, args.identity)
                print("Revoked.")
            elif args.command == "activity":
                print(json.dumps(approver.activity(), indent=2))
    except KeyboardInterrupt:
        pass
    except GuardError as exc:
        print(protocol.ERRORS.get(str(exc), str(exc)), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("Trusted command failed; check inputs and permissions.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
