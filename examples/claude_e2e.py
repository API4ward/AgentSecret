"""Headless Claude Code closed loop with fake credentials and zero GitHub network calls.

Starts a throwaway broker, a per-task MCP config and one `claude -p` run. A
synthetic approval device signs every pending request over the approval
listener; that stands in for the human and is NOT evidence of human review.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from secret_guard.broker import Broker
from secret_guard.cli import claude_mcp_config
from secret_guard.crypto import b64
from secret_guard.server import make_server

CANARY = "SYNTHETIC_CLAUDE_E2E_CANARY_40917"
PROMPT = (
    "Use the secret_guard MCP tools to read the workflow run status of repo demo/example with credential alias demo-github. "
    "Request a reference, poll operation_status until it is approved, request the workflow runs with the returned ref, "
    "then poll operation_status until it reaches a final state. Approval happens elsewhere; just poll. "
    "Finally print only the final operation_status JSON."
)
SUBAGENT_PROMPT = PROMPT + " Delegate the workflow request and its polling to a subagent; request the reference yourself and give the subagent the ref."


def approver(port, key, device, stop, decided):
    def sign(text):
        r, s = decode_dss_signature(key.sign(text.encode(), ec.ECDSA(hashes.SHA256())))
        return b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    def post(path, body, token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        with urlopen(Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(), headers=headers), timeout=5) as r:
            return json.load(r)
    session, expires = None, 0
    while not stop.wait(0.5):
        try:
            if time.time() >= expires:
                c = post("/device/challenge", {"device": device})
                session = post("/device/login", {"device": device, "challenge": c["challenge"], "signature": sign(c["message"])})["token"]
                expires = time.time() + 240
            for r in post("/pending", {}, session)["requests"]:
                op = r["payload"]["request_id"]
                post("/decision", {"operation_id": op, "decision": "approve", "signature": sign("secret-guard/decision/v1:approve:" + r["signing_text"])}, session)
                decided.append({"operation_id": op, "kind": r["payload"].get("kind")})
        except Exception as exc:
            decided.append({"error": type(exc).__name__})


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--claude", default="claude")
    p.add_argument("--subagent", action="store_true", help="ask Claude to delegate the use request to a subagent")
    p.add_argument("--transcript", help="write the raw stream-json output here")
    args = p.parse_args()

    state = Path(tempfile.mkdtemp(prefix="secret-guard-claude-e2e-"))
    work = Path(tempfile.mkdtemp(prefix="secret-guard-claude-work-"))
    calls = []
    def fake_transport(request, token):
        calls.append(token == CANARY)
        return json.dumps({"workflow_runs": [{"id": 101, "status": "completed", "conclusion": "success"}]}).encode()
    broker = Broker(state / "broker", transport=fake_transport)
    broker.add_secret("demo-github", CANARY, ["demo/example"], "demo", "demo")
    key = ec.generate_private_key(ec.SECP256R1())
    n = key.public_key().public_numbers()
    broker.register_device("device_e2e", "demo", {"kty": "EC", "crv": "P-256", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))})
    task = broker.new_task("demo", "demo", "claude-code")
    tokenfile = state / "task.token"
    tokenfile.write_text(task["token"] + "\n")
    tokenfile.chmod(0o600)

    agent = make_server(broker, "agent", "127.0.0.1", 0)
    approval = make_server(broker, "approval", "127.0.0.1", 0)
    stop, decided = threading.Event(), []
    def executor():
        while not stop.wait(0.25):
            broker.run_ready()
    for target in (agent.serve_forever, approval.serve_forever, executor):
        threading.Thread(target=target, daemon=True).start()
    threading.Thread(target=approver, args=(approval.server_port, key, "device_e2e", stop, decided), daemon=True).start()

    config = state / "mcp.json"
    config.write_text(json.dumps(claude_mcp_config(tokenfile, f"http://127.0.0.1:{agent.server_port}")))
    command = [args.claude, "-p", SUBAGENT_PROMPT if args.subagent else PROMPT, "--mcp-config", str(config), "--strict-mcp-config",
               "--allowedTools", "mcp__secret_guard__*", "--output-format", "stream-json", "--verbose"]
    try:
        run = subprocess.run(command, cwd=work, text=True, capture_output=True, timeout=600)
    finally:
        stop.set()
        agent.shutdown()
        approval.shutdown()
    if args.transcript:
        Path(args.transcript).write_text(run.stdout)

    tools, results, final, version, model, listed = [], [], None, None, None, []
    for line in run.stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("type") == "system" and event.get("subtype") == "init":
            version, model = event.get("claude_code_version"), event.get("model")
            listed = [t for t in event.get("tools", []) if t.startswith("mcp__")]
        elif event.get("type") == "result":
            final = event.get("result")
        for block in (event.get("message") or {}).get("content") or []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use":
                tools.append({"name": block["name"], "subagent": bool(event.get("parent_tool_use_id"))})
            elif block.get("type") == "tool_result":
                results.append(json.dumps(block.get("content")))
    audit = broker.activity()
    states = [row["event"] for row in reversed(audit)]
    summary = {
        "claude_code_version": version, "model": model, "exit_code": run.returncode,
        "mcp_tools_listed": listed, "tool_calls": tools,
        "approvals_signed_by_synthetic_device": decided,
        "broker_audit_events": states,
        "broker_tasks_seen": sorted({row["task"] for row in audit if row["task"]}),
        "expected_task": task["task_id"],
        "fake_transport_calls_with_real_credential": calls,
        "succeeded": "succeeded" in states and '\\"state\\":\\"succeeded\\"' in "".join(results).replace(" ", ""),
        "canary_in_claude_output": CANARY in run.stdout or CANARY in run.stderr,
        "task_token_in_claude_output": task["token"] in run.stdout or task["token"] in run.stderr,
        "final_message": final,
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    sys.exit(0 if summary["succeeded"] and not summary["canary_in_claude_output"] else 1)


if __name__ == "__main__":
    main()
