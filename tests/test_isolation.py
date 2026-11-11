"""OS-isolation boundary tests. Synthetic canaries and a fake upstream only.

The container tests start a throwaway compose project (own volumes, own port),
run the bypass probe as a hostile worker, run the same probe inside the broker
as a control, and drive the full two-stage flow across the boundary. They are
skipped when Docker is not reachable.
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from secret_guard import mcp
from secret_guard.broker import Broker, GuardError
from secret_guard.crypto import b64
from secret_guard.server import make_server, make_unix_server

ROOT = Path(__file__).resolve().parent.parent
GUARDCTL = str(ROOT / "isolation" / "guardctl")
PROBE = "/opt/secret-guard/isolation/bypass_probe.py"
SOCKET_URL = "unix:///run/secret-guard/agent/agent.sock"


def docker_available():
    if os.environ.get("SG_SKIP_DOCKER") or not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


class SocketListenerTests(unittest.TestCase):
    def setUp(self):
        # AF_UNIX paths are short; the default macOS temp dir is too long.
        self.tmp = tempfile.TemporaryDirectory(dir="/tmp")
        self.b = Broker(Path(self.tmp.name) / "state", transport=lambda request, token: b"{}")
        self.b.add_secret("github", "canary_NOT_A_REAL_TOKEN_unit", ["acme/payments"], "alice", "payments")
        self.token = self.b.new_task("alice", "payments")["token"]
        self.path = Path(self.tmp.name) / "agent.sock"
        self.server = make_unix_server(self.b, self.path)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def test_mcp_bridge_reaches_broker_through_socket(self):
        result = mcp.call(f"unix://{self.path}", self.token, "guard.request_reference", {"alias": "github"})
        self.assertEqual(result["state"], "pending")
        self.assertNotIn("ref", result)

    def test_socket_is_group_only_and_agent_role_only(self):
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o660)
        self.assertTrue(stat.S_ISSOCK(self.path.stat().st_mode))
        connection = mcp.UnixConnection(str(self.path), 5)
        try:
            for path, body in [("/pending", {}), ("/decision", {"operation_id": "x", "decision": "approve", "signature": "x"}), ("/device/challenge", {"device": "phone"})]:
                connection.request("POST", path, json.dumps(body).encode(), {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
                response = connection.getresponse()
                self.assertEqual((response.status, json.loads(response.read())), (403, {"error": "route_unavailable"}))
        finally:
            connection.close()

    def test_relative_or_remote_socket_urls_rejected(self):
        for url in ["unix://host/run/agent.sock", "unix:agent.sock", "unix:///run/agent.sock?x=1"]:
            with self.assertRaises(ValueError):
                mcp.call(url, self.token, "guard.request_reference", {"alias": "github"})

    def test_container_bind_is_approval_only_and_pins_host(self):
        with self.assertRaises(GuardError):
            make_server(self.b, "agent", "127.0.0.1", 0, bind="0.0.0.0")
        with self.assertRaises(GuardError):
            make_server(self.b, "approval", "0.0.0.0", 0, bind="0.0.0.0")
        server = make_server(self.b, "approval", "127.0.0.1", 0, bind="0.0.0.0")
        try:
            self.assertEqual(server.expected_host, f"127.0.0.1:{server.server_port}")
        finally:
            server.server_close()


@unittest.skipUnless(docker_available(), "Docker is not reachable")
class ContainerBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.canary = "canary_NOT_A_REAL_TOKEN_" + secrets.token_hex(8)
        cls.host_canary = "canary_HOST_ENV_" + secrets.token_hex(8)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]
        cls.project = "sgtest-" + secrets.token_hex(4)
        cls.env = dict(
            os.environ, SG_PROJECT=cls.project, SG_APPROVAL_PORT=str(cls.port), SG_TEST_CANARY=cls.canary,
            SG_COMPOSE_EXTRA=str(ROOT / "isolation" / "compose.test.yaml"), SG_EGRESS_ALLOW="allowed.invalid",
            # Planted in the launcher's own environment: must never reach a worker.
            HOST_ONLY_SECRET=cls.host_canary,
        )
        cls.addClassCleanup(lambda: subprocess.run([GUARDCTL, "destroy"], env=cls.env, capture_output=True, timeout=300))
        subprocess.run([GUARDCTL, "up", "--egress"], env=cls.env, check=True, capture_output=True, timeout=1200)
        cls.key = ec.generate_private_key(ec.SECP256R1())
        n = cls.key.public_key().public_numbers()
        jwk = {"kty": "EC", "crv": "P-256", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}
        # Pairing stays a trusted-CLI action inside the broker domain.
        subprocess.run([GUARDCTL, "broker", "device-register", "--user", "alice", "--device", "phone", "--jwk-file", "/dev/stdin"], env=cls.env, input=json.dumps(jwk).encode(), check=True, capture_output=True, timeout=120)

    def compose(self, *args, **kwargs):
        return subprocess.run(["docker", "compose", "-p", self.project, "-f", str(ROOT / "isolation" / "compose.yaml"), "-f", self.env["SG_COMPOSE_EXTRA"], *args], env=self.env, capture_output=True, timeout=300, **kwargs)

    def worker_probe(self, *options):
        p = subprocess.run([GUARDCTL, "run", "--user", "alice", "--project", "payments", *options, "--env", f"SG_PROBE_CANARIES={self.canary},{self.host_canary}", "--env", f"SG_APPROVAL_PORT={self.port}", "--", "python", PROBE], env=self.env, capture_output=True, timeout=600, stdin=subprocess.DEVNULL)
        report = json.loads(p.stdout)
        return p.returncode, report, {c["check"]: c for c in report["checks"]}

    # Approval device: lives on the trusted host side, talks to the published port.
    def post(self, path, body, token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        with urlopen(Request(f"http://127.0.0.1:{self.port}{path}", json.dumps(body).encode(), headers), timeout=20) as r:
            return json.loads(r.read())

    def sign(self, text):
        r, s = decode_dss_signature(self.key.sign(text.encode(), ec.ECDSA(hashes.SHA256())))
        return b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def approve(self, operation):
        c = self.post("/device/challenge", {"device": "phone"})
        session = self.post("/device/login", {"device": "phone", "challenge": c["challenge"], "signature": self.sign(c["message"])})["token"]
        pending = next(r for r in self.post("/pending", {}, session)["requests"] if r["payload"]["request_id"] == operation)
        self.post("/decision", {"operation_id": operation, "decision": "approve", "signature": self.sign("secret-guard/decision/v1:approve:" + pending["signing_text"])}, session)

    def test_hostile_worker_without_network_is_contained(self):
        code, report, checks = self.worker_probe()
        self.assertEqual(report["breaches"], [], report)
        self.assertEqual(code, 0)
        self.assertTrue(report["agent_api_usable"])
        for name in ["read_broker_state_files", "scan_filesystem_for_canaries", "read_other_process_memory_env", "own_environment_has_no_host_canary", "broker_state_or_docker_socket_mounted", "host_home_docker_socket_other_tasks_visible", "only_own_task_token_visible", "tamper_with_adapter_socket_token_or_rootfs", "root_or_capabilities_available", "reach_approval_listener_over_tcp", "direct_tcp_egress", "external_dns_resolution", "direct_udp_dns_egress", "approve_or_read_secret_through_agent_socket"]:
            self.assertTrue(checks[name]["blocked"], checks[name])

    def test_hostile_worker_behind_egress_proxy_is_contained(self):
        code, report, checks = self.worker_probe("--egress", "--env", "SG_PROBE_ALLOWED_HOST=allowed.invalid")
        self.assertEqual(report["breaches"], [], report)
        self.assertEqual(code, 0)
        self.assertTrue(checks["proxy_tunnels_outside_allow_list"]["blocked"])
        self.assertTrue(checks["direct_tcp_egress"]["blocked"])
        self.assertTrue(checks["reach_approval_listener_over_tcp"]["blocked"])

    def test_control_probe_inside_broker_domain_finds_the_state(self):
        # Same probe, trusted domain: it must see what the worker could not.
        p = self.compose("exec", "-T", "-e", f"SG_PROBE_CANARIES={self.canary}", "broker", "python", PROBE, "--control")
        report = json.loads(p.stdout)
        self.assertEqual(p.returncode, 1)
        self.assertEqual(sorted(report["breaches"]), ["read_broker_state_files", "scan_filesystem_for_canaries"])

    def test_listeners_exposed_only_as_designed(self):
        ports = self.compose("port", "broker", str(self.port)).stdout.decode().split()
        self.assertEqual(ports, [f"127.0.0.1:{self.port}"])
        inspect = json.loads(subprocess.run(["docker", "inspect", f"{self.project}-broker-1"], capture_output=True, check=True).stdout)[0]
        self.assertEqual(list(inspect["NetworkSettings"]["Ports"]), [f"{self.port}/tcp"])
        self.assertEqual(list(inspect["NetworkSettings"]["Networks"]), [f"{self.project}_broker-net"])
        # The agent API has no TCP listener at all, even inside the broker.
        refused = self.compose("exec", "-T", "broker", "python", "-c", "import socket; print(socket.socket().connect_ex(('127.0.0.1', 8765)))").stdout.decode().strip()
        self.assertNotEqual(refused, "0")

    def test_two_stage_flow_across_the_boundary(self):
        worker = subprocess.Popen([GUARDCTL, "run", "--user", "alice", "--project", "payments", "--", "sh", "-c", f'exec python -m secret_guard.cli mcp --url {SOCKET_URL} --token-file "$SECRET_GUARD_TOKEN_FILE"'], env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(worker.stderr.close)
        self.addCleanup(worker.stdout.close)
        self.addCleanup(worker.wait, 120)
        self.addCleanup(worker.stdin.close)
        ids = iter(range(1, 1000))
        transcript = []
        def tool(name, arguments):
            worker.stdin.write(json.dumps({"jsonrpc": "2.0", "id": next(ids), "method": "tools/call", "params": {"name": name, "arguments": arguments}}) + "\n")
            worker.stdin.flush()
            line = worker.stdout.readline()
            transcript.append(line)
            result = json.loads(line)["result"]
            self.assertFalse(result["isError"], line)
            return json.loads(result["content"][0]["text"])

        first = tool("guard.request_reference", {"alias": "github"})
        self.assertEqual(first["state"], "pending")
        self.approve(first["operation_id"])
        ref = tool("guard.operation_status", {"operation_id": first["operation_id"]})["ref"]
        self.assertTrue(ref.startswith("secretref://"))
        use = tool("guard.github_workflow_runs", {"ref": ref, "repo": "acme/payments", "limit": 5})
        self.assertEqual(use["state"], "pending")
        self.approve(use["operation_id"])
        for _ in range(100):
            status = tool("guard.operation_status", {"operation_id": use["operation_id"]})
            if status["state"] not in {"approved", "executing"}:
                break
            threading.Event().wait(0.2)
        self.assertEqual(status["state"], "succeeded", status)
        self.assertEqual(status["result"], {"workflow_runs": [{"id": 101, "status": "completed", "conclusion": "success"}]})
        self.assertNotIn(self.canary, "".join(transcript))
        self.assertNotIn(self.host_canary, "".join(transcript))

    def test_task_is_revoked_and_token_removed_when_worker_exits(self):
        p = subprocess.run([GUARDCTL, "run", "--user", "alice", "--project", "payments", "--", "sh", "-c", 'echo "$SECRET_GUARD_TASK_ID"'], env=self.env, capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
        task = p.stdout.strip()
        self.assertTrue(task.startswith("task_"), p.stderr)
        query = "import sqlite3, sys; print(sqlite3.connect('/var/lib/secret-guard/guard.sqlite3').execute('SELECT active FROM tasks WHERE id=?', (sys.argv[1],)).fetchone()[0])"
        self.assertEqual(self.compose("exec", "-T", "broker", "python", "-c", query, task).stdout.decode().strip(), "0")
        left = self.compose("exec", "-T", "broker", "ls", "/run/secret-guard/tasks").stdout.decode().split()
        self.assertEqual(left, [])


if __name__ == "__main__":
    unittest.main()
