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
    s = sub.add_parser("claude-config", help="Write a per-task Claude Code --mcp-config file and the --settings file that installs the hook")
    s.add_argument("--url", default="http://127.0.0.1:8765")
    s.add_argument("--token-file", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--settings-out", required=True)
    s.add_argument("--protect", action="append", default=[], help="Extra path the hook must always refuse (repeatable)")
    s = sub.add_parser("codex-config", help="Write a per-task Codex launcher: MCP server, sandbox read-deny profile and the hook")
    s.add_argument("--url", default="http://127.0.0.1:8765")
    s.add_argument("--token-file", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--codex", default="codex")
    s.add_argument("--protect", action="append", default=[])
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
    s.add_argument("--repo", action="append", default=[], help="Repository the GitHub adapter may use this credential for")
    s.add_argument("--label", default="default", help="Store a further copy under the same alias, e.g. a second API key")
    s = sub.add_parser("mode", help="all: approve everything for a while; ask: back to asking for each request")
    s.add_argument("mode", choices=["all", "ask"])
    s.add_argument("--minutes", type=float, default=10)
    s = sub.add_parser("auto-add", help="Rule-based automatic approval; every field is a glob")
    s.add_argument("--kind", default="*", choices=["*", "reference", "use", "reveal", "fill"])
    s.add_argument("--secret", default="*")
    s.add_argument("--tool", default="*")
    s.add_argument("--target", default="*", help="File path, URL or repository the tool call is aimed at")
    sub.add_parser("auto-list")
    s = sub.add_parser("auto-remove")
    s.add_argument("id", type=int)
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


def publish(approver):
    try:
        approver.publish_matchers()
        return " Matchers published."
    except Exception:
        return " Matchers will be published when this approver next connects."


def describe(payload):
    d = payload["details"]
    if payload["kind"] in protocol.HOOK_KINDS:
        what = "工具返回的内容里有密码；批准后以引用代替密码交给 agent" if payload["kind"] == "reveal" else "工具调用里有密码引用；批准后把引用换成密码再执行"
        lines = [f"  项目 {payload['project']} · 任务 {payload['task']} · 密码 {'、'.join(d['secrets'])}", "  " + what,
                 f"  工具 {d['tool']}" + (f" · 目标 {d['target']}" if d["target"] else "") + f" · 调用 {d['summary']!r}"]
    else:
        lines = [f"  项目 {payload['project']} · 任务 {payload['task']} · 凭据 {payload['secret_id']}"]
        if payload["kind"] == "use":
            lines.append(f"  操作 {d['method']} https://{d['host']}{d['path']}?{d['query']}")
        else:
            once = d["type"] == "once"
            lines.append("  操作 允许本任务引用该凭据（" + ("一次性：只能发起一次使用申请" if once else "长期：批准后 1 小时内可反复申请使用") + "）；每次使用仍需单独批准")
    lines.append(f"  注入工具 {payload['injector']} · 有效至 {time.strftime('%H:%M:%S', time.localtime(payload['expires_at']))}")
    return "\n".join(lines)


TITLES = {"use": "允许这一次具体使用？", "reference": "允许任务引用凭据？", "reveal": "agent 读到的内容里有密码，允许以引用形式交给它？", "fill": "agent 要把密码填进这次调用，允许吗？"}
AUTO = {"all": "全部同意模式", "grant": "此前选择的多次或限时允许", "rule": "自动审批规则"}


def parse_answer(answer):
    """yes | no | <n>x (allow n times) | <n>m (allow for n minutes) -> (decision, grant)."""
    answer = answer.strip().lower()
    if answer in ("yes", "y"):
        return "approve", None
    if answer[:-1].isdigit() and int(answer[:-1]) > 0 and answer[-1] in "xm":
        return "approve", {"times": int(answer[:-1])} if answer[-1] == "x" else {"seconds": int(answer[:-1]) * 60}
    return "deny", None


def approve_loop(approver):
    approver.publish_matchers()
    print("审批端已连接。Ctrl-C 退出。", flush=True)
    seen = set()
    while True:
        for item in approver.pending():
            if item["request_id"] in seen:
                continue
            seen.add(item["request_id"])
            payload = item["payload"]
            print("\n" + TITLES.get(payload.get("kind"), "请求"))
            if item["problem"]:
                # Rules come before the prompt: a forbidden request is rejected with its reason, never offered.
                print(f"  {'已自动拒绝并告知调用方' if item['rejected'] else '不能批准'}：{protocol.explain(item['problem'])}")
                continue
            print(describe(payload))
            if item["auto"]:
                print(f"  已自动批准（{AUTO[item['auto']]}）")
                continue
            decision, grant = parse_answer(input("  yes 允许一次 · 3x 允许 3 次 · 10m 允许 10 分钟 · 其余为拒绝: "))
            choices = {}
            if decision == "approve" and payload["kind"] in ("use", "fill"):
                # The user may return something other than the stored credential.
                for alias in approver.facets(payload)[1]:
                    labels = approver.labels(alias)
                    print(f"  返回给 {alias} 的值：回车=保存的密码" + (f" · copy:<副本名>（{'、'.join(labels[1:])}）" if len(labels) > 1 else "") + " · mock=形状相同的假值 · manual=手动输入")
                    choice = input("  > ").strip() or "default"
                    choices[alias] = "manual:" + getpass.getpass("  手动输入（不回显）: ") if choice == "manual" else choice
            print("  " + approver.decide(item, decision, choices or None, grant)["state"])
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
            elif args.command in ("claude-config", "codex-config"):
                from . import cli
                guard = (args.url, args.token_file)
                (cli.write_claude_config if args.command == "claude-config" else cli.write_codex_launcher)(args, args.state, guard)
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
                approver.add_secret(args.alias, getpass.getpass("密码（不回显；内容由你管理，按原样保存）: "), args.repo, args.label)
                print("Credential stored on this approver." + publish(approver))
            elif args.command == "mode":
                approver.approve_all(args.minutes * 60 if args.mode == "all" else 0)
                print(f"此后 {args.minutes:g} 分钟内，能批准的请求都自动批准（需要 approver run 在运行）。" if args.mode == "all" else "已恢复逐条询问。")
            elif args.command == "auto-add":
                print(json.dumps({"id": approver.add_auto_rule(args.kind, args.secret, args.tool, args.target)}))
            elif args.command == "auto-list":
                print(json.dumps(approver.auto_rules(), indent=2, ensure_ascii=False))
            elif args.command == "auto-remove":
                approver.remove_auto_rule(args.id)
                print("Removed.")
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
