import base64
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from secret_guard import adapter
from secret_guard.broker import Broker, GuardError
from secret_guard.crypto import b64, canonical
from secret_guard.server import make_server

CANARY = "canary_NOT_A_REAL_TOKEN_73619"
GOOD = json.dumps({"workflow_runs": [{"id": 19, "status": "completed", "conclusion": "success", "name": "untrusted arbitrary name"}]}).encode()


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = 1000.0
        self.calls = []
        def transport(request, token):
            self.calls.append((request, token))
            return GOOD
        self.b = Broker(self.tmp.name, transport=transport, clock=lambda: self.now)
        self.b.add_secret("github", CANARY, ["acme/payments"], "alice", "payments")
        self.t = self.b.new_task("alice", "payments")
        self.key = ec.generate_private_key(ec.SECP256R1())
        n = self.key.public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": "P-256", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}
        self.b.register_device("phone", "alice", self.jwk)
        self.session = self.login()

    def tearDown(self):
        self.tmp.cleanup()

    def sign(self, text):
        r, s = decode_dss_signature(self.key.sign(text.encode(), ec.ECDSA(hashes.SHA256())))
        return b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

    def login(self):
        c = self.b.challenge("phone")
        return self.b.login("phone", c["challenge"], self.sign(c["message"]))["token"]

    def decide(self, op, decision="approve"):
        requests = self.b.pending(self.session)["requests"]
        p = next(r for r in requests if r["payload"]["request_id"] == op)
        signature = self.sign("secret-guard/decision/v1:" + decision + ":" + p["signing_text"])
        self.b.decide(self.session, op, decision, signature)
        return signature

    def ref(self):
        response = self.b.reference(self.t["token"], "github")
        if "ref" in response:
            return response["ref"]
        op = response["operation_id"]
        self.decide(op)
        return self.b.status(self.t["token"], op)["ref"]

    def use(self):
        op = self.b.workflow(self.t["token"], self.ref(), "acme/payments")["operation_id"]
        self.decide(op)
        return op

    def test_two_stages_and_no_secret_in_public_data(self):
        p = self.b.reference(self.t["token"], "github")
        self.assertNotIn("ref", p)
        self.assertEqual(self.calls, [])
        self.decide(p["operation_id"])
        ref = self.b.status(self.t["token"], p["operation_id"])["ref"]
        op = self.b.workflow(self.t["token"], ref, "acme/payments")["operation_id"]
        self.assertFalse(self.b.execute(op))
        self.decide(op)
        self.b.execute(op)
        public = self.b.status(self.t["token"], op)
        self.assertEqual(public["result"], {"workflow_runs": [{"id": 19, "status": "completed", "conclusion": "success"}]})
        self.assertNotIn(CANARY, canonical(public) + canonical(self.b.activity()))
        self.assertEqual(self.calls[0][1], CANARY)
        self.assertNotIn(CANARY.encode(), self.b.db.read_bytes())

    def test_reference_grant_remains_valid_after_prompt_expiry(self):
        ref = self.ref()
        self.now += 121
        self.assertEqual(self.b.reference(self.t["token"], "github")["ref"], ref)

    def test_agent_cannot_approve_or_pair(self):
        with self.assertRaises(GuardError):
            self.b.pending(self.t["token"])
        op = self.b.reference(self.t["token"], "github")["operation_id"]
        with self.assertRaises(GuardError):
            self.b.decide(self.t["token"], op, "approve", "fake")

    def test_signature_tamper_and_replay(self):
        op = self.b.reference(self.t["token"], "github")["operation_id"]
        with self.assertRaises(GuardError):
            self.b.decide(self.session, op, "approve", self.sign("approved=true"))
        signature = self.decide(op)
        with self.assertRaises(GuardError):
            self.b.decide(self.session, op, "approve", signature)

    def test_login_challenge_single_use(self):
        c = self.b.challenge("phone")
        s = self.sign(c["message"])
        self.b.login("phone", c["challenge"], s)
        with self.assertRaises(GuardError):
            self.b.login("phone", c["challenge"], s)

    def test_cross_task_reference_and_status(self):
        ref = self.ref()
        other = self.b.new_task("alice", "payments")
        with self.assertRaises(GuardError):
            self.b.workflow(other["token"], ref, "acme/payments")
        op = self.use()
        with self.assertRaises(GuardError):
            self.b.status(other["token"], op)

    def test_policy_cannot_be_overridden_by_approval(self):
        ref = self.ref()
        with self.assertRaises(GuardError):
            self.b.workflow(self.t["token"], ref, "other/repo")
        for user, project in [("bob", "payments"), ("alice", "other")]:
            t = self.b.new_task(user, project)
            with self.assertRaises(GuardError):
                self.b.reference(t["token"], "github")

    def test_deny_is_sticky_and_pending_is_deduplicated(self):
        p = self.b.reference(self.t["token"], "github")
        self.assertEqual(p, self.b.reference(self.t["token"], "github"))
        self.decide(p["operation_id"], "deny")
        self.assertEqual(self.b.reference(self.t["token"], "github")["state"], "denied")
        self.assertEqual(len(self.b.pending(self.session)["requests"]), 0)

    def test_expired_approval_never_executes(self):
        op = self.use()
        self.now += 121
        self.assertFalse(self.b.execute(op))
        self.assertEqual(self.calls, [])

    def test_concurrent_consumption_and_replay(self):
        op = self.use()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.b.execute(op), range(8)))
        self.assertEqual(sum(results), 1)
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(self.b.execute(op))

    def test_atomic_across_broker_instances(self):
        op = self.use()
        other = Broker(self.tmp.name, self.b.transport, clock=lambda: self.now)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(b.execute, op) for b in [self.b, other]]
            self.assertEqual(sum(f.result() for f in futures), 1)
        self.assertEqual(len(self.calls), 1)

    def test_frozen_parameter_tamper_detected(self):
        op = self.use()
        with self.b.tx() as db:
            p = json.loads(db.execute("SELECT payload FROM requests WHERE id=?", (op,)).fetchone()[0])
            # Even rebuilding a valid adapter request cannot reuse old approval.
            p["details"] = adapter.freeze({"repo": "acme/payments", "limit": 20})
            db.execute("UPDATE requests SET payload=? WHERE id=?", (canonical(p), op))
        self.assertFalse(self.b.execute(op))
        self.assertEqual(self.calls, [])

    def test_adapter_version_change(self):
        from unittest.mock import patch
        op = self.use()
        with patch("secret_guard.adapter.adapter_digest", return_value="new"):
            self.assertFalse(self.b.execute(op))
        self.assertEqual(self.calls, [])

    def test_stolen_session_without_device_signature_cannot_approve(self):
        op = self.b.reference(self.t["token"], "github")["operation_id"]
        other = ec.generate_private_key(ec.SECP256R1())
        p = self.b.pending(self.session)["requests"][0]
        r,s = decode_dss_signature(other.sign(("secret-guard/decision/v1:approve:"+p["signing_text"]).encode(),ec.ECDSA(hashes.SHA256())))
        with self.assertRaises(GuardError):
            self.b.decide(self.session,op,"approve",b64(r.to_bytes(32,"big")+s.to_bytes(32,"big")))

    def test_github_redirect_and_oversize_response_rejected(self):
        from unittest.mock import patch
        class Response:
            status = 302
            def read(self,size):
                return b"x" * size
        class Connection:
            def __init__(self,*args,**kwargs): pass
            def request(self,method,path,headers):
                self.test_headers=headers
            def getresponse(self): return Response()
            def close(self): pass
        with patch("secret_guard.adapter.PinnedTLS",Connection):
            with self.assertRaises(ValueError):
                adapter.fetch(adapter.freeze({"repo":"acme/payments","limit":10}),CANARY)
            Response.status=200
            with self.assertRaises(ValueError):
                adapter.fetch(adapter.freeze({"repo":"acme/payments","limit":10}),CANARY)

    def test_nonpublic_or_mixed_dns_is_rejected_before_connect(self):
        from unittest.mock import patch
        import socket
        for ips in [["127.0.0.1"],["169.254.169.254"],["140.82.112.6","10.0.0.1"]]:
            answers=[(socket.AF_INET,socket.SOCK_STREAM,6,"",(ip,443)) for ip in ips]
            with patch("secret_guard.adapter.socket.getaddrinfo",return_value=answers),patch("secret_guard.adapter.socket.socket") as sock:
                with self.assertRaises(ValueError):
                    adapter.PinnedTLS("api.github.com").connect()
                sock.assert_not_called()

    def test_rotate_secret_invalidates_all_grants(self):
        op = self.use()
        self.b.add_secret("github", "new_fake_token_888", ["acme/payments"], "alice", "payments")
        self.assertFalse(self.b.execute(op))
        self.assertEqual(self.b.status(self.t["token"], op)["state"], "revoked")

    def test_revocation_before_execution(self):
        for kind in ["operation", "task", "secret", "device"]:
            with self.subTest(kind=kind):
                # Each subcase needs a fresh authorization universe.
                if kind != "operation":
                    self.tearDown(); self.setUp()
                op = self.use()
                identity = {"operation": op, "task": self.t["task_id"], "secret": "github", "device": "phone"}[kind]
                self.b.revoke(kind, identity)
                self.assertFalse(self.b.execute(op))
                self.assertEqual(self.calls, [])

    def test_reflected_secret_and_common_encodings_blocked(self):
        for leak in [CANARY, base64.b64encode(CANARY.encode()).decode(), CANARY.encode().hex()]:
            op = self.use()
            self.b.transport = lambda request, token: json.dumps({"workflow_runs": [], "message": leak}).encode()
            self.b.execute(op)
            self.assertEqual(self.b.status(self.t["token"], op)["state"], "unknown")
            self.assertNotIn(leak, canonical(self.b.activity()))

    def test_transport_errors_do_not_leak_or_retry(self):
        op = self.use()
        def bad(request, token):
            raise RuntimeError(CANARY)
        self.b.transport = bad
        self.b.execute(op)
        self.assertEqual(self.b.status(self.t["token"], op)["state"], "unknown")
        self.assertFalse(self.b.execute(op))

    def test_crash_recovery_preserves_unknown(self):
        op = self.use()
        with self.b.tx() as db:
            db.execute("UPDATE requests SET state='executing' WHERE id=?", (op,))
        other = Broker(self.tmp.name, clock=lambda: self.now)
        other.recover()
        self.assertEqual(other.status(self.t["token"], op)["state"], "unknown")
        self.assertFalse(other.execute(op))

    def test_status_does_not_execute(self):
        op = self.use()
        for _ in range(3):
            self.assertEqual(self.b.status(self.t["token"], op)["state"], "approved")
        self.assertEqual(self.calls, [])

    def test_adapter_rejects_target_injection(self):
        for repo in ["https://evil.test", "acme/../secret", "acme/repo?x=y", "acme/repo%2fother", "acme/repo\r\nAuthorization:x"]:
            with self.assertRaises(ValueError):
                adapter.normalize(repo, 10)
        for limit in [True, 0, 101, "10"]:
            with self.assertRaises(ValueError):
                adapter.normalize("acme/payments", limit)

    def test_http_listeners_are_separate_and_origin_checked(self):
        servers = [make_server(self.b, role, "127.0.0.1", 0) for role in ["agent", "approval"]]
        for s in servers:
            threading.Thread(target=s.serve_forever, daemon=True).start()
        def post(server, path, token, body, origin=None):
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + token}
            if origin: headers["Origin"] = origin
            return urlopen(Request(f"http://127.0.0.1:{server.server_port}"+path, data=json.dumps(body).encode(), headers=headers), timeout=2)
        try:
            with post(servers[0], "/reference", self.t["token"], {"alias": "github"}) as r:
                self.assertEqual(json.load(r)["state"], "pending")
            for s,path,token,body,origin in [
                (servers[0],"/decision",self.t["token"],{},None),
                (servers[1],"/pending",self.t["token"],{},None),
                (servers[0],"/reference",self.t["token"],{"alias":"github","approved":True},None),
                (servers[0],"/reference",self.t["token"],{"alias":"github"},"https://evil.test"),
            ]:
                try:
                    post(s,path,token,body,origin)
                except HTTPError as exc:
                    self.assertEqual(exc.code,403)
                    exc.close()
                else:
                    self.fail("forbidden request accepted")
            with urlopen(f"http://127.0.0.1:{servers[1].server_port}/") as r:
                self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])
        finally:
            for s in servers: s.shutdown(); s.server_close()

    def test_remote_listener_requires_tls(self):
        with self.assertRaises(GuardError):
            make_server(self.b, "approval", "0.0.0.0", 0)

    def test_stdio_mcp_wire_protocol(self):
        requests = [{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}, {"jsonrpc":"2.0","method":"notifications/initialized"}, {"jsonrpc":"2.0","id":2,"method":"tools/list"}]
        code = "from secret_guard.mcp import run; run('http://127.0.0.1:1','fake')"
        p = subprocess.run([sys.executable,"-c",code], input="\n".join(json.dumps(r) for r in requests)+"\n", text=True, capture_output=True, check=True)
        results = [json.loads(line) for line in p.stdout.splitlines()]
        self.assertEqual(len(results), 2)
        self.assertEqual(len(results[1]["result"]["tools"]), 3)
        self.assertNotIn("approve", [t["name"] for t in results[1]["result"]["tools"]])


if __name__ == "__main__":
    unittest.main()
