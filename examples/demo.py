"""Local browser/MCP demo with fake credentials and zero GitHub network calls."""
import json
from pathlib import Path
import tempfile

from secret_guard.broker import Broker
from secret_guard.server import serve


def main():
    state = Path(tempfile.mkdtemp(prefix="secret-guard-demo-"))
    def fake_transport(request, token):
        return json.dumps({"workflow_runs": [{"id": 101, "status": "completed", "conclusion": "success"}]}).encode()
    broker = Broker(state, transport=fake_transport)
    broker.add_secret("demo-github", "SYNTHETIC_DEMO_CREDENTIAL_ONLY", ["demo/example"], "demo", "demo")
    task = broker.new_task("demo", "demo")
    tokenfile = state / "task.token"
    tokenfile.write_text(task["token"])
    tokenfile.chmod(0o600)
    (state / "task.json").write_text(json.dumps({"task_id": task["task_id"], "token_file": str(tokenfile)}))
    request = broker.reference(task["token"], "demo-github")
    print(json.dumps({"state_dir": str(state), "token_file": str(tokenfile), "reference_operation": request["operation_id"]}), flush=True)
    serve(broker, agent_port=8875, approval_port=8876)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
