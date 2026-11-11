"""Broker for boundary tests: synthetic credential, fake upstream, real listeners."""
import json
import os
from pathlib import Path

from secret_guard.broker import Broker
from secret_guard.server import serve

STATE = Path("/var/lib/secret-guard")


def main():
    canary = os.environ["SG_TEST_CANARY"]
    def fake_transport(request, token):
        if token != canary:
            raise RuntimeError("unexpected credential")
        return json.dumps({"workflow_runs": [{"id": 101, "status": "completed", "conclusion": "success"}]}).encode()
    broker = Broker(STATE, transport=fake_transport)
    broker.add_secret("github", canary, ["acme/payments"], "alice", "payments")
    # Plaintext marker inside the trusted state: lets the probe's control run
    # prove that it would notice a readable broker file.
    marker = STATE / "canary.txt"
    marker.write_text(canary)
    marker.chmod(0o600)
    serve(broker, approval_port=int(os.environ["SG_APPROVAL_PORT"]), agent_socket="/run/secret-guard/agent/agent.sock", approval_bind="0.0.0.0")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
