"""The three scenarios, end to end: real hook process, injector agent API, relay, approver.

Only the agent is simulated: each test feeds the hook the PreToolUse / PostToolUse
events Claude Code would send and applies what the hook answers.
"""
import argparse
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs
from urllib.request import Request, urlopen

from secret_guard import claude_hook, cli
from secret_guard.approver import Approver
from secret_guard.injector import Injector
from secret_guard.relay import Relay
from secret_guard.server import make_server


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.wire = []
        self.relay = Relay(self.root / "relay")

        def call(route, body, token=None):
            result = self.relay.dispatch(route, body, token)
            self.wire.append(json.dumps([route, body, result]))
            return result
        self.inj = Injector(self.root / "injector", call=call, user="alice")
        self.app = Approver(self.root / "approver", call=call, user="alice")
        i, a = self.inj.pairing(), self.app.pairing()
        self.relay.register_device(i["device"], "alice", "injector", i["jwk"], i["enc_jwk"])
        self.relay.register_device(a["device"], "alice", "approver", a["jwk"])
        self.inj.pair_approver(a["device"], "alice", a["jwk"])
        self.app.pair_injector(i["device"], "alice", i["jwk"], i["enc_jwk"])
        token = self.root / "run.token"
        token.write_text(self.inj.new_task("demo")["token"])
        self.server = make_server(self.inj, "agent", "127.0.0.1", 0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        settings = cli.claude_settings([self.root / "injector", token], (f"http://{self.server.expected_host}", token))
        self.assertEqual(set(settings["hooks"]), {"PreToolUse", "PostToolUse"})
        self.command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.work = self.root / "work"
        (self.work / "example").mkdir(parents=True)
        # The user at the approver: answer(item) -> None (leave it) or (decision, choices, grant).
        self.answer = lambda item: ("approve", None, None)
        self.asked, self.stop, seen = [], threading.Event(), set()

        def user():
            while not self.stop.wait(0.05):
                for item in self.app.pending():
                    if item["auto"] or item["rejected"] or item["request_id"] in seen:
                        continue
                    seen.add(item["request_id"])
                    self.asked.append(item["payload"])
                    reply = self.answer(item)
                    if reply:
                        self.app.decide(item, *reply)
                self.inj.run_ready()
        threading.Thread(target=user, daemon=True).start()

    def tearDown(self):
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def secrets(self, **values):
        for alias, value in values.items():
            self.app.add_secret(alias, value)
        self.app.publish_matchers()
        self.assertTrue(self.inj.sync_rules())

    def hook(self, event, tool, tool_input, tool_response=None):
        body = {"hook_event_name": event, "tool_name": tool, "tool_input": tool_input, "cwd": str(self.work)}
        if event == "PostToolUse":
            body["tool_response"] = tool_response
        proc = subprocess.run(self.command, shell=True, capture_output=True, text=True, input=json.dumps(body))
        out = json.loads(proc.stdout)["hookSpecificOutput"] if proc.stdout.strip() else {}
        return proc.returncode, out, proc.stderr

    def read(self, path):
        """The agent reads a file: the Read tool runs, then the hook sees its result before the model does."""
        response = {"type": "text", "file": {"filePath": str(path), "content": Path(path).read_text(), "numLines": 1}}
        code, out, _ = self.hook("PostToolUse", "Read", {"file_path": str(path)}, response)
        self.assertEqual(code, 0)
        return out.get("updatedToolOutput", response)["file"]["content"]

    def write(self, path, content):
        """The agent writes a file: the hook may rewrite the tool input, then the Write tool runs with it."""
        code, out, err = self.hook("PreToolUse", "Write", {"file_path": str(path), "content": content})
        if code == 0:
            final = out.get("updatedInput", {"file_path": str(path), "content": content})
            Path(final["file_path"]).parent.mkdir(parents=True, exist_ok=True)
            Path(final["file_path"]).write_text(final["content"])
        return code, err

    def assert_plaintext_only_on_approver(self, *values):
        for value in values:
            self.assertNotIn(value, "".join(self.wire))
            for name in ("relay", "injector"):
                for path in (self.root / name).iterdir():
                    self.assertNotIn(value.encode(), path.read_bytes(), path)

    # Scenario 1: secret detection.
    def test_secret_in_a_file_is_detected_approved_replaced_and_restored(self):
        self.secrets(age="18year")
        qa = self.work / "example/qa.txt"
        qa.write_text("I am 18year old.")
        (self.work / "notes.txt").write_text("Nothing to see here, 18 years is not it.")
        self.assertEqual(self.read(self.work / "notes.txt"), "Nothing to see here, 18 years is not it.")
        self.assertEqual(self.asked, [])  # No credential, no approval, content untouched.

        self.assertEqual(self.read(qa), "I am {{secretref:age}} old.")
        request = self.asked[-1]
        self.assertEqual((request["kind"], request["details"]["secrets"], request["details"]["tool"], request["details"]["target"]),
                         ("reveal", ["age"], "Read", str(qa)))
        self.assertNotIn("18year", json.dumps(request))

        # Other tools that return the same text are covered the same way.
        code, out, _ = self.hook("PostToolUse", "Bash", {"command": "cat example/qa.txt"}, {"stdout": "I am 18year old.\n", "stderr": "", "interrupted": False})
        self.assertEqual(out["updatedToolOutput"]["stdout"], "I am {{secretref:age}} old.\n")

        # Later the agent writes the reference; it is turned back into the credential for that call.
        code, _ = self.write(self.work / "answer.txt", "The user is {{secretref:age}} old.")
        self.assertEqual(code, 0)
        self.assertEqual((self.work / "answer.txt").read_text(), "The user is 18year old.")
        self.assertEqual(self.asked[-1]["kind"], "fill")
        self.assert_plaintext_only_on_approver("18year")

        # Denied: the content is withheld, and a reference is not filled in.
        self.answer = lambda item: ("deny", None, None)
        qa.write_text("Again: 18year.")
        self.assertIn("withheld", self.read(qa))
        self.assertNotIn("18year", self.read(qa))
        code, err = self.write(self.work / "denied.txt", "x {{secretref:age}}")
        self.assertEqual(code, 2)
        self.assertIn("用户拒绝了这次请求", err)
        self.assertFalse((self.work / "denied.txt").exists())

    def test_any_length_of_credential_is_detected(self):
        # How strong a credential is, is the user's decision; nothing is skipped for being short.
        self.secrets(pin="7", code="ab1")
        (self.work / "p.txt").write_text("pin 7 code ab1")
        self.assertEqual(self.read(self.work / "p.txt"), "pin {{secretref:pin}} code {{secretref:code}}")

    def test_no_answer_and_no_injector_both_withhold(self):
        self.secrets(age="18year")
        self.answer = lambda item: None
        token = (self.root / "run.token").read_text()
        event = {"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_input": {"file_path": "qa.txt"}, "tool_response": "I am 18year old."}
        self.assertIn("no answer yet", claude_hook.reveal(event, f"http://{self.server.expected_host}", token, wait=1.5))
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()
        code, out, _ = self.hook("PostToolUse", "Read", {"file_path": "qa.txt"}, "I am 18year old.")
        self.assertNotIn("18year", json.dumps(out))
        self.assertIn("withheld", out["updatedToolOutput"])
        self.assertEqual(self.hook("PreToolUse", "Write", {"file_path": "x", "content": "{{secretref:age}}"})[0], 2)

    # Codex: same events, but a replaced result has to be sent as a blocked result with the new text as its reason.
    def codex_launcher(self):
        out = self.root / "run.codex"
        args = argparse.Namespace(token_file=str(self.root / "run.token"), out=str(out), codex="codex", protect=[],
                                  url=f"http://{self.server.expected_host}")
        with contextlib.redirect_stdout(io.StringIO()):
            cli.write_codex_launcher(args, str(self.root / "injector"), (args.url, args.token_file))
        return out

    def test_codex_gets_the_replaced_result_in_the_form_it_accepts(self):
        self.secrets(age="18year")
        text = self.codex_launcher().read_text()
        self.assertIn("--dangerously-bypass-hook-trust", text)  # Otherwise Codex skips the hook without a word.
        self.command = next(json.loads(re.search(r'"command"=("(?:[^"\\]|\\.)*")', c).group(1)) for c in shlex.split(text) if c.startswith("hooks.PostToolUse="))
        event = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "cat example/qa.txt"},
                 "tool_response": "I am 18year old.\n", "cwd": str(self.work)}
        run = lambda: json.loads(subprocess.run(self.command, shell=True, capture_output=True, text=True, input=json.dumps(event)).stdout)
        self.assertEqual(run(), {"decision": "block", "reason": "I am {{secretref:age}} old.\n"})
        self.assertEqual(self.asked[-1]["kind"], "reveal")
        self.answer = lambda item: ("deny", None, None)
        self.assertIn("withheld", run()["reason"])
        self.server.shutdown()  # The injector is gone: still withheld, still in Codex's form.
        self.server.server_close()
        out = run()
        self.assertEqual((out["decision"], "18year" in out["reason"], "withheld" in out["reason"]), ("block", False, True))

    @unittest.skipUnless(os.environ.get("AGENTSECRET_REAL_CODEX") and shutil.which("codex"), "set AGENTSECRET_REAL_CODEX=1 to run a real Codex session (needs a login and network)")
    def test_real_codex_session_sees_a_reference_and_can_fill_it(self):
        self.secrets(age="18year")
        (self.work / "example/qa.txt").write_text("I am 18year old.\n")
        launcher = self.codex_launcher()

        def codex(prompt):
            run = subprocess.run([str(launcher), "exec", "--skip-git-repo-check", prompt], cwd=self.work, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)
            self.transcript = run.stderr
            return run.stdout
        said = codex("Run exactly this one shell command and nothing else: cat example/qa.txt  Then repeat its output verbatim.")
        # What the model says about a replaced result varies; that it never got the credential does not.
        self.assertIn("PostToolUse Blocked", self.transcript)
        self.assertNotIn("18year", said)
        self.assertEqual(self.asked[-1]["kind"], "reveal")
        codex("Run exactly this one shell command and nothing else: printf 'The user is {{secretref:age}} old.' > answer.txt  Then say done.")
        self.assertEqual((self.work / "answer.txt").read_text(), "The user is 18year old.")
        self.assertEqual(self.asked[-1]["kind"], "fill")

    # Scenario 3: filling in configuration.
    def test_filling_deepseek_token_into_codex_config_asks_for_approval(self):
        key = "sk-deepseek-0123456789abcdef"
        self.secrets(DEEPSEEK_API_TOKEN=key)
        self.app.add_secret("DEEPSEEK_API_TOKEN", "sk-deepseek-team-fedcba9876543210", label="team")
        self.app.publish_matchers()
        self.inj.sync_rules()
        config = self.root / "home/.codex/config.toml"
        toml = 'model = "deepseek-chat"\nmodel_provider = "deepseek"\n\n[model_providers.deepseek]\nbase_url = "https://api.deepseek.com/v1"\nexperimental_bearer_token = "{{secretref:DEEPSEEK_API_TOKEN}}"\n'

        self.assertEqual(self.write(config, toml)[0], 0)
        request = self.asked[-1]
        self.assertEqual((request["kind"], request["details"]["secrets"], request["details"]["tool"], request["details"]["target"]),
                         ("fill", ["DEEPSEEK_API_TOKEN"], "Write", str(config)))
        self.assertIn(f'experimental_bearer_token = "{key}"', config.read_text())
        # Reading the file back does not hand the key to the agent.
        self.assertIn('experimental_bearer_token = "{{secretref:DEEPSEEK_API_TOKEN}}"', self.read(config))

        # The panel can return something else: another copy with the same name, a mock, or typed text.
        for choice, check in [("copy:team", lambda v: v == "sk-deepseek-team-fedcba9876543210"),
                              ("mock", lambda v: v != key and len(v) == len(key) and v.startswith("sk-")),
                              ("manual:typed-by-hand", lambda v: v == "typed-by-hand")]:
            self.answer = lambda item, choice=choice: ("approve", {"DEEPSEEK_API_TOKEN": choice}, None)
            self.assertEqual(self.write(config, toml)[0], 0)
            value = config.read_text().split('experimental_bearer_token = "')[1].split('"')[0]
            self.assertTrue(check(value), (choice, value))
        self.assert_plaintext_only_on_approver(key, "sk-deepseek-team-fedcba9876543210")

    # Approval modes.
    def test_allow_n_times_then_ask_again(self):
        self.secrets(DEEPSEEK_API_TOKEN="sk-deepseek-0123456789abcdef")
        replies = [("approve", None, {"times": 3})]
        self.answer = lambda item: replies.pop(0) if replies else None
        for i in range(3):
            self.assertEqual(self.write(self.work / f"c{i}.toml", "t={{secretref:DEEPSEEK_API_TOKEN}}")[0], 0)
        self.assertEqual(len(self.asked), 1)  # Asked once, answered three times.
        event = {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": "c3.toml", "content": "t={{secretref:DEEPSEEK_API_TOKEN}}"}}
        token = (self.root / "run.token").read_text()
        self.assertIn("no answer yet", claude_hook.fill(event, f"http://{self.server.expected_host}", token, wait=1.5)[1])
        self.assertEqual(len(self.asked), 2)  # The fourth one is put to the user again.

    def test_allow_for_a_while_and_approve_all(self):
        self.secrets(age="18year", other="another-secret")
        qa = self.work / "example/qa.txt"
        qa.write_text("I am 18year old.")
        replies = [("approve", None, {"seconds": 180})]
        self.answer = lambda item: replies.pop(0) if replies else ("deny", None, None)
        self.assertEqual(self.read(qa), "I am {{secretref:age}} old.")
        self.assertEqual(self.read(qa), "I am {{secretref:age}} old.")
        self.assertEqual(len(self.asked), 1)
        with self.app.tx() as db:  # Three minutes later.
            db.execute("UPDATE grants SET expires=?", (time.time() - 1,))
        self.assertIn("withheld", self.read(qa))
        self.assertEqual(len(self.asked), 2)
        # all: everything approvable is approved for a while, whatever the credential.
        self.app.approve_all(600)
        (self.work / "o.txt").write_text("it is another-secret")
        self.assertEqual(self.read(self.work / "o.txt"), "it is {{secretref:other}}")
        self.assertEqual(self.write(self.work / "w.txt", "{{secretref:age}}")[0], 0)
        self.assertEqual(len(self.asked), 2)
        self.app.approve_all(0)
        self.assertIn("withheld", self.read(self.work / "o.txt"))
        self.assertEqual(len(self.asked), 3)

    def test_rule_based_automatic_approval(self):
        self.secrets(DEEPSEEK_API_TOKEN="sk-deepseek-0123456789abcdef")
        self.answer = lambda item: ("deny", None, None)
        self.app.add_auto_rule(kind="fill", secret="DEEPSEEK_*", tool="Write", target="*/.codex/config.toml")
        self.assertEqual(self.write(self.root / "home/.codex/config.toml", "k={{secretref:DEEPSEEK_API_TOKEN}}")[0], 0)
        self.assertEqual(self.asked, [])  # Matched the rule: never shown to the user.
        self.assertEqual(self.write(self.work / "elsewhere.toml", "k={{secretref:DEEPSEEK_API_TOKEN}}")[0], 2)
        self.assertEqual(len(self.asked), 1)
        # A reference to a credential the approver does not have is rejected with the reason.
        code, err = self.write(self.work / "x.toml", "k={{secretref:NOPE}}")
        self.assertEqual(code, 2)
        self.assertIn("本设备没有这个密码", err)

    # Scenario 2: website login.
    def test_website_login_fills_the_password_and_hides_it_in_the_page(self):
        password = "correct-horse-battery"
        self.secrets(shop_password=password)
        seen = []

        class Site(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
                seen.append(form)
                ok = form.get("user") == ["alice"] and form.get("password") == [password]
                page = f"<h1>Welcome alice</h1><p>Signed in with {password}</p>" if ok else "<h1>Wrong password</h1>"
                self.send_response(200 if ok else 403)
                self.end_headers()
                self.wfile.write(page.encode())
        site = ThreadingHTTPServer(("127.0.0.1", 0), Site)
        threading.Thread(target=site.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{site.server_port}/login"
            tool, tool_input = "mcp__browser__submit_form", {"url": url, "fields": {"user": "alice", "password": "{{secretref:shop_password}}"}}
            code, out, _ = self.hook("PreToolUse", tool, tool_input)
            self.assertEqual((code, out["permissionDecision"]), (0, "allow"))
            request = self.asked[-1]
            self.assertEqual((request["kind"], request["details"]["tool"], request["details"]["target"]), ("fill", tool, url))
            # The browser tool runs with the input the hook returned.
            fields = out["updatedInput"]["fields"]
            try:
                page = urlopen(Request(url, data="&".join(f"{k}={v}" for k, v in fields.items()).encode())).read().decode()
            except Exception as exc:
                page = str(exc)
            self.assertEqual(seen[-1]["password"], [password])
            self.assertIn("Welcome alice", page)
            # The page echoes the password; the agent sees a reference instead.
            code, out, _ = self.hook("PostToolUse", tool, tool_input, [{"type": "text", "text": page}])
            self.assertEqual(out["updatedToolOutput"], [{"type": "text", "text": "<h1>Welcome alice</h1><p>Signed in with {{secretref:shop_password}}</p>"}])
            self.assert_plaintext_only_on_approver(password)
        finally:
            site.shutdown()
            site.server_close()


if __name__ == "__main__":
    unittest.main()
