"""Approver / relay / injector split: credentials live on the approver only."""
import json
from pathlib import Path
import tempfile
import threading
import unittest

from secret_guard import protocol
from secret_guard.approver import Approver
from secret_guard.broker import GuardError
from secret_guard.injector import Injector
from secret_guard.link import http_call
from secret_guard.relay import Relay
from secret_guard.seal import jwk, load_or_create_key, seal, sign, unseal
from secret_guard.split_server import make_relay_server

CANARY = "canary_NOT_A_REAL_TOKEN_73619"
GOOD = json.dumps({"workflow_runs": [{"id": 19, "status": "completed", "conclusion": "success", "name": "untrusted"}]}).encode()


class SplitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.now = 1000.0
        self.calls, self.wire = [], []
        clock = lambda: self.now
        self.relay = Relay(self.root / "relay", clock=clock)

        def call(route, body, token=None):
            # Everything any device sends to or receives from the relay.
            result = self.relay.dispatch(route, body, token)
            self.wire.append(json.dumps([route, body, result]))
            return result

        def transport(request, token):
            self.calls.append((request, token))
            return GOOD
        self.call = call
        self.inj = Injector(self.root / "injector", call=call, transport=transport, clock=clock, user="alice")
        self.app = Approver(self.root / "approver", call=call, clock=clock, user="alice")
        i, a = self.inj.pairing(), self.app.pairing()
        self.relay.register_device(i["device"], "alice", "injector", i["jwk"], i["enc_jwk"])
        self.relay.register_device(a["device"], "alice", "approver", a["jwk"])
        self.inj.pair_approver(a["device"], "alice", a["jwk"])
        self.app.pair_injector(i["device"], "alice", i["jwk"], i["enc_jwk"])
        self.app.add_secret("github", CANARY, ["acme/payments"])
        self.t = self.inj.new_task("payments")["token"]

    def tearDown(self):
        self.tmp.cleanup()

    def decide(self, op, decision="approve"):
        item = next(p for p in self.app.pending() if p["request_id"] == op)
        return self.app.decide(item, decision)

    def ref(self, kind="long"):
        op = self.inj.reference(self.t, "github", kind)["operation_id"]
        self.decide(op)
        self.inj.run_ready()
        return self.inj.status(self.t, op)["ref"]

    def use(self, repo="acme/payments"):
        return self.inj.workflow(self.t, self.ref(), repo)["operation_id"]

    def state(self, op):
        return self.inj.status(self.t, op)["state"]

    def test_full_loop_and_credential_never_reaches_relay_or_agent(self):
        op = self.use()
        self.inj.run_ready()
        self.assertEqual(self.calls, [])  # Nothing runs before approval.
        self.decide(op)
        self.inj.run_ready()
        status = self.inj.status(self.t, op)
        self.assertEqual(status, {"operation_id": op, "state": "succeeded", "result": {"workflow_runs": [{"id": 19, "status": "completed", "conclusion": "success"}]}})
        self.assertEqual([c[1] for c in self.calls], [CANARY])
        self.assertNotIn(CANARY, json.dumps(status))
        self.assertNotIn(CANARY, "".join(self.wire))
        for name in ("relay", "injector"):
            for path in (self.root / name).iterdir():
                self.assertNotIn(CANARY.encode(), path.read_bytes(), path)
        events = [e["event"] for e in reversed(self.relay.activity())]
        self.assertEqual(events[-5:], ["requested", "approved", "delivered", "executing", "succeeded"])
        self.inj.run_ready()
        self.assertEqual(len(self.calls), 1)  # One grant, one request.

    def test_relay_cannot_forge_an_approval(self):
        op = self.use()
        # The relay (or anyone who controls it) registers its own approver and approves.
        rogue = load_or_create_key(self.root / "rogue.key")
        self.relay.register_device("rogue", "alice", "approver", jwk(rogue))
        text = next(r for r in self.relay.pending(self.login("rogue", rogue))["requests"] if op in r["request_text"])["request_text"]
        box = seal(self.inj.pairing()["enc_jwk"], b"attacker-chosen-token", protocol.seal_aad(text))
        self.relay.decide(self.login("rogue", rogue), op, "approve", sign(rogue, protocol.decision_message("approve", "rogue", text)), box)
        self.inj.run_ready()
        self.assertEqual(self.state(op), "revoked")
        self.assertEqual(self.calls, [])

    def login(self, device, key):
        c = self.relay.challenge(device)
        return self.relay.login(device, c["challenge"], sign(key, c["message"]))["token"]

    def test_sealed_credential_is_bound_to_its_request(self):
        first, box = self.use(), {}
        real = self.relay.dispatch

        def swap(route, body, token=None):
            result = real(route, body, token)
            if route == "/injector/poll" and "sealed" in result:
                box.setdefault("first", result["sealed"])
                result = dict(result, sealed=box["first"])
            return result
        self.inj.link.call = swap
        self.decide(first)
        self.inj.run_ready()
        self.assertEqual(self.state(first), "succeeded")
        self.now += 1
        second = self.inj.workflow(self.t, self.inj.reference(self.t, "github", "long")["ref"], "acme/payments", 5)["operation_id"]
        self.decide(second)
        self.inj.run_ready()  # Relay replays the first box for the second request.
        self.assertEqual(self.state(second), "revoked")
        self.assertEqual(len(self.calls), 1)

    def test_box_opens_only_for_the_paired_injector(self):
        op = self.use()
        self.decide(op)
        sealed = json.loads(self.wire[-1])[1]["sealed"]
        text = next(json.loads(w)[1]["request_text"] for w in self.wire if "/injector/submit" in w and op in w)
        other = load_or_create_key(self.root / "other.key")
        with self.assertRaises(Exception):
            unseal(other, sealed, protocol.seal_aad(text))
        self.assertEqual(unseal(self.inj.sealing, sealed, protocol.seal_aad(text)), CANARY.encode())

    def test_delivery_is_one_time(self):
        op = self.use()
        self.decide(op)
        token = self.inj.link.token
        self.assertIn("sealed", self.relay.poll(token, op))
        self.assertEqual(self.relay.poll(token, op), {"state": "delivered"})
        self.inj.run_ready()  # The box was taken by the direct poll above.
        self.assertEqual(self.state(op), "revoked")
        self.assertEqual(self.calls, [])

    def test_denial_is_sticky_and_expiry_blocks(self):
        ref = self.ref()
        op = self.inj.workflow(self.t, ref, "acme/payments")["operation_id"]
        self.decide(op, "deny")
        self.inj.run_ready()
        self.assertEqual(self.state(op), "denied")
        self.assertEqual(self.inj.workflow(self.t, ref, "acme/payments"), {"operation_id": op, "state": "denied", "reason": "user_denied", "message": "用户拒绝了这次请求"})
        late = self.inj.workflow(self.t, ref, "acme/payments", 3)["operation_id"]
        self.now += protocol.USE_TTL + 1
        self.assertEqual(self.app.pending(), [])
        self.inj.run_ready()
        self.assertEqual(self.state(late), "expired")
        self.assertEqual(self.calls, [])

    def test_approver_rules_come_before_the_prompt(self):
        ref = self.ref()
        self.app.add_secret("other", "another_fake_token_1", ["acme/other"])
        op = self.inj.workflow(self.t, ref, "acme/elsewhere")["operation_id"]
        item = next(p for p in self.app.pending() if p["request_id"] == op)
        self.assertEqual(item["problem"], "policy_denied")
        with self.assertRaisesRegex(GuardError, "policy_denied"):
            self.app.decide(item, "approve")
        unknown = self.inj.reference(self.t, "missing")["operation_id"]
        self.assertEqual(next(p for p in self.app.pending() if p["request_id"] == unknown)["problem"], "secret_unavailable")
        self.assertNotIn("sealed", "".join(self.wire))

    def test_approver_rejects_requests_from_unpaired_or_impersonated_injectors(self):
        rogue = Injector(self.root / "rogue", call=self.call, clock=lambda: self.now, user="alice")
        p = rogue.pairing()
        self.relay.register_device(p["device"], "alice", "injector", p["jwk"], p["enc_jwk"])
        rogue.pair_approver(self.app.device, "alice", self.app.pairing()["jwk"])
        op = rogue.reference(rogue.new_task("payments")["token"], "github")["operation_id"]
        item = next(p for p in self.app.pending() if p["request_id"] == op)
        self.assertEqual(item["problem"], "injector_not_paired")
        with self.assertRaises(GuardError):
            self.app.decide(item, "approve")
        # A relay that rewrites a queued request breaks the injector's signature.
        op = self.use()
        with self.relay.tx() as db:
            text = db.execute("SELECT request_text FROM requests WHERE id=?", (op,)).fetchone()[0]
            db.execute("UPDATE requests SET request_text=? WHERE id=?", (text.replace("acme/payments", "acme/paymentz"), op))
        self.assertEqual(next(p for p in self.app.pending() if p["request_id"] == op)["problem"], "signature_invalid")

    def test_caller_is_told_why_a_request_cannot_be_approved(self):
        op = self.inj.reference(self.t, "missing")["operation_id"]
        item = next(p for p in self.app.pending() if p["request_id"] == op)
        self.assertTrue(item["rejected"])  # No person involved.
        self.assertEqual(self.app.pending(), [])
        self.inj.run_ready()
        self.assertEqual(self.inj.status(self.t, op), {"operation_id": op, "state": "denied", "reason": "secret_unavailable", "message": "本设备没有这个密码"})
        # Not sticky: once the credential exists the same call starts a fresh request.
        self.app.add_secret("missing", "x", ["acme/payments"])
        self.assertEqual(self.inj.reference(self.t, "missing")["state"], "pending")
        use = self.inj.workflow(self.t, self.ref(), "acme/elsewhere")["operation_id"]
        self.app.pending()
        self.inj.run_ready()
        self.assertEqual(self.inj.status(self.t, use)["reason"], "policy_denied")
        late = self.inj.reference(self.t, "github", "once")["operation_id"]
        self.now += protocol.USE_TTL + 1
        self.assertEqual(self.inj.status(self.t, late)["reason"], "no_response")

    def test_the_agent_call_itself_returns_the_reason(self):
        self.inj.settle_seconds = 5
        stop = threading.Event()

        def approver():
            while not stop.wait(0.05):
                self.app.pending()
        threading.Thread(target=approver, daemon=True).start()
        try:
            out = self.inj.reference(self.t, "missing")
        finally:
            stop.set()
        self.assertEqual((out["state"], out["reason"]), ("denied", "secret_unavailable"))

    def test_relay_cannot_invent_a_reason_and_another_approver_may_still_approve(self):
        op = self.inj.reference(self.t, "missing")["operation_id"]
        real = self.relay.dispatch
        self.inj.link.call = lambda route, body, token=None: dict(real(route, body, token), state="denied", reason="policy_denied") if route == "/injector/poll" else real(route, body, token)
        self.inj.run_ready()
        self.assertEqual(self.inj.status(self.t, op), {"operation_id": op, "state": "denied"})
        self.inj.link.call = real
        # A second approver of the same user holds the credential the first one lacks.
        second = Approver(self.root / "approver2", call=self.call, clock=lambda: self.now, user="alice")
        i, a = self.inj.pairing(), second.pairing()
        self.relay.register_device(a["device"], "alice", "approver", a["jwk"])
        self.inj.pair_approver(a["device"], "alice", a["jwk"])
        second.pair_injector(i["device"], "alice", i["jwk"], i["enc_jwk"])
        second.add_secret("elsewhere", "pw", ["acme/payments"])
        op = self.inj.reference(self.t, "elsewhere")["operation_id"]
        self.assertTrue(next(p for p in self.app.pending() if p["request_id"] == op)["rejected"])
        self.inj.run_ready()
        self.assertEqual(self.state(op), "pending")
        second.decide(next(p for p in second.pending() if p["request_id"] == op), "approve")
        self.inj.run_ready()
        self.assertEqual(self.state(op), "approved")

    def test_reference_types(self):
        op = self.inj.reference(self.t, "github")["operation_id"]  # Default: once.
        self.decide(op)
        self.now += 30
        self.inj.run_ready()
        status = self.inj.status(self.t, op)
        self.assertEqual((status["type"], status["uses_left"], status["expires_at"]), ("once", 1, self.now + 3600))
        first = self.inj.workflow(self.t, status["ref"], "acme/payments")
        self.assertEqual(self.inj.workflow(self.t, status["ref"], "acme/payments"), first)  # Same pending request.
        with self.assertRaisesRegex(GuardError, "reference_used"):
            self.inj.workflow(self.t, status["ref"], "acme/payments", 3)
        self.assertEqual(self.inj.status(self.t, op)["uses_left"], 0)
        self.decide(first["operation_id"])
        self.inj.run_ready()
        self.assertEqual(self.state(first["operation_id"]), "succeeded")  # The one use still runs.
        self.assertNotEqual(self.inj.reference(self.t, "github")["state"], "approved")  # A used reference is not handed out again.
        ref = self.ref("long")
        for limit in (1, 2):
            use = self.inj.workflow(self.t, ref, "acme/payments", limit)["operation_id"]
            self.decide(use)  # Every use is approved separately.
            self.inj.run_ready()
            self.assertEqual(self.state(use), "succeeded")
        self.assertEqual(self.inj.reference(self.t, "github", "long")["ref"], ref)
        self.now += 3601
        with self.assertRaisesRegex(GuardError, "reference_invalid"):
            self.inj.workflow(self.t, ref, "acme/payments", 4)
        with self.assertRaisesRegex(GuardError, "arguments_invalid"):
            self.inj.reference(self.t, "github", "forever")

    def test_credential_is_stored_as_given(self):
        for alias, value in [("short", "x"), ("spaces", "  two words \n"), ("unicode", "密码🔑"), ("long", "k" * 60000)]:
            self.app.add_secret(alias, value, ["acme/payments"])
            with self.app.tx() as db:
                row = db.execute("SELECT * FROM secrets WHERE alias=?", (alias,)).fetchone()
            blob = row["ciphertext"]
            self.assertEqual(self.app.vault.decrypt(blob[:12], blob[12:], json.dumps([alias, 1], separators=(",", ":")).encode()).decode(), value)
        for args, code in [(("bad alias", "x", ["acme/payments"]), "alias_invalid"), (("a", "", ["acme/payments"]), "secret_empty"),
                           (("a", "x", ["nope"]), "repo_invalid"), (("a", "x", []), "empty_policy"), (("a", "x" * 70000, ["acme/payments"]), "secret_too_large")]:
            with self.assertRaisesRegex(GuardError, code):
                self.app.add_secret(*args)
        # The largest credential still travels sealed through the relay to the injector.
        ref = self.ref()
        self.app.add_secret("github", "k" * 60000, ["acme/payments"])
        op = self.inj.workflow(self.t, ref, "acme/payments")["operation_id"]
        self.decide(op)
        self.inj.run_ready()
        self.assertEqual(self.calls[-1][1], "k" * 60000)

    def test_reading_protected_content_triggers_an_approval(self):
        self.app.set_rule("path", ".env")
        self.app.set_rule("text", "GITHUB_TOKEN")
        self.app.publish_rules()
        self.assertTrue(self.inj.sync_rules())
        rules = self.inj.rules(self.t)["rules"]
        self.assertEqual(rules, [{"kind": "path", "value": ".env"}, {"kind": "text", "value": "GITHUB_TOKEN"}])
        call = "ab" * 32
        op = self.inj.access(self.t, "Bash", rules[0], "cat .env", call)["operation_id"]
        self.assertEqual(self.inj.access(self.t, "Bash", rules[0], "cat .env", call)["operation_id"], op)
        item = next(p for p in self.app.pending() if p["request_id"] == op)
        self.assertEqual((item["payload"]["kind"], item["problem"]), ("access", None))  # Needs no credential on the approver.
        self.inj.run_ready()
        self.assertEqual(self.state(op), "pending")  # Nothing passes before the user decides.
        self.app.decide(item, "approve")
        self.inj.run_ready()
        self.assertEqual(self.inj.status(self.t, op), {"operation_id": op, "state": "approved"})
        self.assertNotIn("sealed", "".join(self.wire))
        # Approval covers that one call: the same call again is a new request, and a denial sticks.
        again = self.inj.access(self.t, "Bash", rules[0], "cat .env", call)["operation_id"]
        self.assertNotEqual(again, op)
        self.decide(again, "deny")
        self.inj.run_ready()
        self.assertEqual(self.inj.access(self.t, "Bash", rules[0], "cat .env", call)["reason"], "user_denied")
        with self.assertRaisesRegex(GuardError, "arguments_invalid"):
            self.inj.access(self.t, "Bash", {"kind": "path", "value": "made-up"}, "x", call)
        # A rule removed on the approver is rejected there with a reason, then disappears here.
        other = self.inj.access(self.t, "Read", rules[1], "{}", "cd" * 32)["operation_id"]
        self.app.set_rule("text", "GITHUB_TOKEN", present=False)
        self.app.pending()
        self.inj.run_ready()
        self.assertEqual(self.inj.status(self.t, other)["reason"], "rule_unknown")
        self.now += 1
        self.app.publish_rules()
        self.inj.sync_rules()
        self.assertEqual(self.inj.rules(self.t)["rules"], [rules[0]])

    def test_relay_can_neither_invent_nor_roll_back_rules(self):
        self.app.set_rule("path", ".env")
        self.app.publish_rules()
        old = json.loads(next(w for w in self.wire if "/approver/rules" in w))[1]
        self.inj.sync_rules()
        self.now += 1
        self.app.set_rule("path", "*.pem")
        self.app.publish_rules()
        self.inj.sync_rules()
        self.assertEqual(len(self.inj.rules(self.t)["rules"]), 2)
        rogue = load_or_create_key(self.root / "rogue.key")
        self.relay.register_device("rogue", "alice", "approver", jwk(rogue))
        text = json.dumps({"approver": "rogue", "version": 9 ** 15, "rules": []})
        self.relay.publish_rules(self.login("rogue", rogue), text, sign(rogue, protocol.rules_message(text)))
        with self.relay.tx() as db:  # The relay replays the approver's older, smaller rule set.
            db.execute("UPDATE rules SET rules_text=?, signature=? WHERE approver=?", (old["rules_text"], old["signature"], self.app.device))
        self.inj.sync_rules()
        self.assertEqual(len(self.inj.rules(self.t)["rules"]), 2)

    def test_hook_blocks_until_the_approver_allows_the_read(self):
        import subprocess, sys, time
        from secret_guard import claude_hook, cli
        from secret_guard.server import make_server
        self.inj.clock = self.app.clock = self.relay.clock = time.time  # Real time: the hook is a separate process.
        self.t = self.inj.new_task("payments")["token"]
        token = self.root / "run.token"
        token.write_text(self.t)
        work = self.root / "work"
        work.mkdir()
        (work / ".env").write_text("secret=a")
        self.app.set_rule("path", ".env")
        self.app.publish_rules()
        self.inj.sync_rules()
        server = make_server(self.inj, "agent", "127.0.0.1", 0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        stop, decision = threading.Event(), ["approve"]

        def background():
            while not stop.wait(0.1):
                for item in self.app.pending():
                    self.app.decide(item, decision[0])
                self.inj.run_ready()
        threading.Thread(target=background, daemon=True).start()
        try:
            settings = cli.claude_settings([self.root / "injector"], (f"http://{server.expected_host}", token))
            command = settings["hooks"]["PreToolUse"][0]["hooks"][0]

            def hook(tool, **tool_input):
                return subprocess.run(command["command"], shell=True, capture_output=True, text=True,
                                      input=json.dumps({"tool_name": tool, "tool_input": tool_input, "cwd": str(work)}))
            self.assertEqual(command["timeout"], 130)
            self.assertEqual(hook("Bash", command="ls").returncode, 0)
            self.assertEqual(hook("Bash", command="cat .env").returncode, 0)  # Approved on the approver.
            decision[0] = "deny"
            denied = hook("Read", file_path=str(work / ".env"))
            self.assertEqual(denied.returncode, 2)
            self.assertIn("用户拒绝了这次请求", denied.stderr)
            self.assertEqual(hook("Read", file_path=str(self.root / "injector/device.key")).returncode, 2)  # Own state: never offered.
            events = [e["event"] for e in self.app.activity()]
            self.assertEqual((events.count("approved"), events.count("denied")), (1, 1))
        finally:
            stop.set()
            server.shutdown()
            server.server_close()

    def test_relay_surface(self):
        token = self.inj.link.token or self.login(self.inj.device, self.inj.signing)
        for route, body in [("/device/register", {}), ("/approver/pending", {}), ("/approver/decision", {"request_id": "x", "decision": "approve", "signature": "x"}), ("/export", {})]:
            with self.assertRaises(GuardError):
                self.relay.dispatch(route, body, token)  # An injector session cannot approve or list.
        text = '{"domain":"secret-guard/approval/v2"}'
        with self.assertRaises(GuardError):
            self.relay.submit(token, text, sign(self.inj.signing, protocol.request_message(text)))
        with self.assertRaisesRegex(GuardError, "device_exists"):
            self.relay.register_device(self.inj.device, "alice", "approver", self.app.pairing()["jwk"])
        self.relay.revoke("device", self.app.device)
        with self.assertRaises(GuardError):
            self.app.pending()

    def test_cross_task_reference_and_revocation(self):
        ref = self.ref()
        other = self.inj.new_task("payments")
        with self.assertRaisesRegex(GuardError, "reference_invalid"):
            self.inj.workflow(other["token"], ref, "acme/payments")
        op = self.inj.workflow(self.t, ref, "acme/payments")["operation_id"]
        self.decide(op)
        self.inj.revoke("approver", self.app.device)
        self.inj.run_ready()
        self.assertEqual(self.state(op), "revoked")
        self.assertEqual(self.calls, [])

    def test_reflected_credential_and_crash_recovery(self):
        self.inj.transport = lambda request, token: json.dumps({"workflow_runs": [], "echo": token}).encode()
        op = self.use()
        self.decide(op)
        self.inj.run_ready()
        self.assertEqual(self.inj.status(self.t, op), {"operation_id": op, "state": "unknown"})
        with self.inj.tx() as db:
            db.execute("UPDATE requests SET state='executing' WHERE id=?", (op,))
        self.inj.recover()
        self.assertEqual(self.state(op), "unknown")

    def test_mcp_bridge_reaches_injector_unchanged(self):
        from secret_guard import mcp
        from secret_guard.server import make_server
        server = make_server(self.inj, "agent", "127.0.0.1", 0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://{server.expected_host}"
            op = mcp.call(url, self.t, "guard.request_reference", {"alias": "github", "type": "long"})["operation_id"]
            self.decide(op)
            self.inj.run_ready()
            ref = mcp.call(url, self.t, "guard.operation_status", {"operation_id": op})["ref"]
            use = mcp.call(url, self.t, "guard.github_workflow_runs", {"ref": ref, "repo": "acme/payments"})["operation_id"]
            self.decide(use)
            self.inj.run_ready()
            out = mcp.call(url, self.t, "guard.operation_status", {"operation_id": use})
            self.assertEqual(out["state"], "succeeded")
            self.assertNotIn(CANARY, json.dumps(out))
        finally:
            server.shutdown()
            server.server_close()

    def test_http_round_trip(self):
        server = make_relay_server(self.relay, "127.0.0.1", 0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            call = http_call(f"http://{server.expected_host}")
            self.inj.link.call = self.app.link.call = call
            self.inj.link.token = self.app.link.token = None
            op = self.use()
            self.decide(op)
            self.inj.run_ready()
            self.assertEqual(self.state(op), "succeeded")
            with self.assertRaisesRegex(GuardError, "route_unavailable"):
                call("/device/register", {})
            with self.assertRaisesRegex(GuardError, "device_unauthorized"):
                call("/approver/pending", {}, "s_forged")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
