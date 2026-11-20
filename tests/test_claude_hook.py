import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from secret_guard import claude_hook
from secret_guard.claude_hook import Policy


class ClaudeHookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.home = root / "home"
        self.state = self.home / ".local/share/vaultdir"
        self.token = root / "run/run-01.token"
        self.work = root / "work"
        for d in (self.state, self.token.parent, self.work / "src", self.home / "notes"):
            d.mkdir(parents=True)
        (self.state / "vault.key").write_text("synthetic")
        self.token.write_text("synthetic")
        self.policy = Policy([str(self.state), str(self.token)], home=str(self.home))

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, tool, cwd=None, **tool_input):
        return self.policy.check({"tool_name": tool, "tool_input": tool_input, "cwd": str(cwd or self.work)})

    def denied(self, tool, **tool_input):
        self.assertIsNotNone(self.check(tool, **tool_input), (tool, tool_input))

    def allowed(self, tool, **tool_input):
        self.assertIsNone(self.check(tool, **tool_input), (tool, tool_input))

    def test_file_tools(self):
        self.denied("Read", file_path=str(self.state / "vault.key"))
        self.denied("Read", file_path=str(self.token))
        self.denied("Read", file_path=str(self.state / "VAULT.KEY").replace("vaultdir", "VaultDir"))
        self.denied("Read", file_path="../home/.local/share/vaultdir/guard.sqlite3")
        self.denied("Read", file_path="~/x/../../run/run-01.token".replace("~/x/../..", str(self.token.parent.parent / "work/..")))
        self.denied("Edit", file_path=str(self.token), old_string="a", new_string="b")
        self.denied("Write", file_path=str(self.state / "new"), content="x")
        self.denied("NotebookEdit", notebook_path=str(self.state / "a.ipynb"), new_source="x")
        self.denied("SomeFutureTool", options={"targets": [str(self.token)]})
        self.allowed("Read", file_path=str(self.work / "src/main.py"))
        self.allowed("Read", file_path="src/main.py")
        self.allowed("Write", file_path="notes.md", content="vaultdir is mentioned but not opened")
        self.allowed("Read", file_path=str(self.home / "notes/a.md"))

    def test_symlink_into_protected(self):
        link = self.work / "innocent"
        link.symlink_to(self.state)
        self.denied("Read", file_path=str(link / "vault.key"))
        self.denied("Read", file_path="innocent/vault.key")
        self.denied("Bash", command="cat innocent/vault.key")
        self.denied("Grep", pattern="x", path="innocent")

    def test_search_tools(self):
        self.denied("Grep", pattern="canary", path=str(self.state))
        self.denied("Grep", pattern="canary", path=str(self.home))
        self.denied("Grep", pattern="canary", path="/")
        self.denied("Glob", pattern="**/*.key", path=str(self.home))
        self.denied("Glob", pattern=str(self.home / ".local/share/vault*/*"))
        self.denied("Glob", pattern=str(self.token.parent / "*.token"))
        self.denied("Glob", pattern="../run/*")
        self.denied("Glob", pattern="../{run,other}/*")
        self.allowed("Grep", pattern="vault.key")
        self.allowed("Grep", pattern="x", path="src")
        self.allowed("Glob", pattern="**/*.py")
        self.allowed("Glob", pattern="*.md", path=str(self.home / "notes"))

    def test_bash_denied(self):
        s, t, h = str(self.state), str(self.token), str(self.home)
        for command in [
            f"cat {s}/vault.key",
            f"cat '{t}'",
            "cat ~/.local/share/vaultdir/vault.key",
            "cat $HOME/.local/share/vaultdir/vault.key",
            'cat "${HOME}/.local/share/vaultdir/vault.key"',
            "cat ~/.local/share/vault*/v*",
            "cat ~/.local/share/v?ultdir/vault.key",
            "cat ~/.local/sh[a]re/*/vault.key",
            "cat ~/.local/share/{vaultdir,x}/vault.key",
            "cat ~/.local/share/vault''dir/vault.key",
            "cat ~/.local/share/vault\\dir/vault.key",
            "cat ~/.LOCAL/share/VAULTDIR/vault.key",
            "cd ~/.local/share && cat */vault.key",
            "cd ~ && ls",
            "grep -r canary ~",
            "grep -r canary ~/.local",
            "find / -name '*.key'",
            f"find {h} -type f",
            "tar cf /tmp/x.tar $HOME",
            "d=~/.local/share; cat $d/v*/vault.key",
            f"a={h}/.local; b=$a/share; ls $b/va*",
            f"cd {self.token.parent} && cat *.token",
            f"cat {self.token.parent}/*",
            "cat ../run/*",
            "cat ../run/run-0?.token",
            f"cd /tmp && cat ../{t.lstrip('/')}",
            f"sqlite3 {s}/guard.sqlite3 .dump",
            f"cp {t} /tmp/copy",
            f"dd if={t} of=/tmp/copy",
            f"python3 -c \"print(open('{t}').read())\"",
            f"python3 -c \"import os; print(open(os.path.join('{h}', '.local', 'share', 'vault' + 'dir', 'vault.key')).read())\"",
            f"echo $(cat {s}/vault.key)",
            f"echo `cat {s}/vault.key`",
            f"cat < {t}",
            f"ln -s {s} ./innocent",
            f"cat <<'X' > /tmp/a.sh\ncat {t}\nX",
            f"cat \"{t}",
            "secret-guard activity",
            ".venv/bin/secret-guard secret-add x --repo a/b --user u --project p",
            "python -m secret_guard.cli revoke task task_1",
            "python -c 'from secret_guard.broker import Broker'",
            "agentsecret approver activity",
            "cat run-01.token",
        ]:
            with self.subTest(command=command):
                self.denied("Bash", command=command)

    def test_bash_allowed(self):
        for command in [
            "ls -la",
            "git status && git diff --stat",
            "python -m unittest discover -v 2>/dev/null | tail -5",
            "grep -rn 'TODO' src/ --include='*.py'",
            "cat src/main.py > /tmp/out.txt",
            "sed -i '' 's/a/b/' src/main.py",
            "ls ~/notes && cat $HOME/notes/a.md",
            "curl -s https://example.com/a?b=1",
            "for f in src/*.py; do wc -l $f; done",
            "echo ${UNSET_VARIABLE:-x} $OTHER",
            "cd src && ls ../src",
            "sed 's/x//' src/main.py",
        ]:
            with self.subTest(command=command):
                self.allowed("Bash", command=command)

    def test_known_bypass_is_documented_not_blocked(self):
        # A path assembled at run time never appears in the command text. Out of scope: no sandbox is provided.
        parts = "+".join(f"chr({ord(c)})" for c in str(self.token))
        self.allowed("Bash", command=f"python3 -c 'print(open({parts}).read())'")

    def test_shell_inside_or_above_protected_is_refused(self):
        self.assertIsNotNone(self.check("Bash", cwd=self.home, command="ls"))
        self.assertIsNotNone(self.check("Bash", cwd=self.state, command="ls"))
        self.assertIsNotNone(self.check("Monitor", cwd=self.home, command="ls"))

    def rule(self, kind, value, tool, cwd=None, **tool_input):
        event = {"tool_name": tool, "tool_input": tool_input, "cwd": str(cwd or self.work)}
        return claude_hook.match_rule(event, [{"kind": kind, "value": value}], home=str(self.home))

    def test_user_rules_match_reads_of_protected_content(self):
        (self.work / ".env").write_text("secret=a")
        (self.home / ".aws").mkdir()
        (self.home / ".aws/credentials").write_text("synthetic")
        hit, miss = self.assertIsNotNone, self.assertIsNone
        # A file name, wherever the file is.
        hit(self.rule("path", ".env", "Read", file_path=str(self.work / ".env")))
        hit(self.rule("path", ".env", "Bash", command="cat .env"))
        hit(self.rule("path", ".env", "Bash", command="cat ./src/../.e''nv"))
        hit(self.rule("path", ".env", "Bash", command="bash -c 'source .env && env'"))
        hit(self.rule("path", ".env", "Grep", pattern="secret", path="."))
        hit(self.rule("path", ".env", "Bash", command="grep -r secret ."))
        hit(self.rule("path", "*.pem", "Read", file_path="certs/server.PEM"))
        miss(self.rule("path", ".env", "Read", file_path="src/main.py"))
        miss(self.rule("path", ".env", "Bash", command="ls -la && make test"))
        miss(self.rule("path", ".env", "Grep", pattern="secret", path="src"))
        miss(self.rule("path", ".env", "Edit", file_path="src/app.js", old_string="a", new_string="const x = process.env.PORT\n"))
        miss(self.rule("path", "*.pem", "Read", file_path="docs/pem.md"))
        # A fixed path: reads of it and tree scans above it, but not every command run nearby.
        hit(self.rule("path", "~/.aws", "Read", file_path=str(self.home / ".aws/credentials")))
        hit(self.rule("path", "~/.aws", "Bash", command="cat ~/.aws/credentials"))
        hit(self.rule("path", "~/.aws", "Bash", command="cat $HOME/.aws/credentials", cwd=self.work))
        hit(self.rule("path", "~/.aws", "Bash", command="tar czf /tmp/h.tgz " + str(self.home)))
        hit(self.rule("path", str(self.work / ".env"), "Bash", command="rg secret"))
        miss(self.rule("path", str(self.work / ".env"), "Bash", command="python3 src/main.py"))
        miss(self.rule("path", "~/.aws", "Bash", command="ls " + str(self.home)))
        miss(self.rule("path", "~/.aws", "Read", file_path=str(self.home / "notes/a.md")))
        # A string that may not appear in a tool call.
        hit(self.rule("text", "GITHUB_TOKEN", "Bash", command="echo $github_token"))
        hit(self.rule("text", "GITHUB_TOKEN", "Bash", command="printenv GITHUB_'TOKEN'"))
        hit(self.rule("text", "secret=", "Grep", pattern="secret=", path="src"))
        miss(self.rule("text", "GITHUB_TOKEN", "Bash", command="git status"))
        miss(self.rule("path", ".env", "mcp__secret_guard__guard_operation_status", operation_id=".env"))

    def test_a_matching_call_waits_for_the_users_decision(self):
        token = self.token
        answers, calls = [], []

        def call(url, bearer, route, body):
            calls.append((route, body))
            if route == "/rules":
                return {"rules": [{"kind": "path", "value": ".env"}]}
            return answers.pop(0)
        event = {"tool_name": "Bash", "tool_input": {"command": "cat .env"}, "cwd": str(self.work)}
        run = lambda e=event: claude_hook.guarded(e, "http://127.0.0.1:1", str(token), wait=3, call=call)
        self.assertIsNone(run({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": str(self.work)}))
        self.assertEqual([c[0] for c in calls], ["/rules"])  # Nothing is requested for an ordinary call.
        answers[:] = [{"operation_id": "op_1", "state": "pending"}, {"operation_id": "op_1", "state": "approved"}]
        self.assertIsNone(run())
        access = next(body for route, body in calls if route == "/access")
        self.assertEqual((access["tool"], access["rule"], access["summary"]), ("Bash", {"kind": "path", "value": ".env"}, "cat .env"))
        answers[:] = [{"operation_id": "op_2", "state": "denied", "reason": "user_denied", "message": "用户拒绝了这次请求"}]
        self.assertIn("用户拒绝了这次请求", run())
        answers[:] = [{"operation_id": "op_3", "state": "pending"}] * 10
        self.assertIn("no answer yet", run())
        # No injector, no decision: the call is blocked.
        proc = subprocess.run([sys.executable, "-I", claude_hook.__file__, "--protect", str(self.state), "--guard-url", "http://127.0.0.1:9", "--token-file", str(token)],
                              input=json.dumps(event), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)

    def test_secret_guard_tools_pass(self):
        self.allowed("mcp__secret_guard__guard_request_reference", alias="github", repo="acme/payments")
        self.denied("mcp__other__read", path=str(self.token))

    def run_hook(self, stdin, *argv):
        return subprocess.run([sys.executable, "-I", claude_hook.__file__, *argv], input=stdin, capture_output=True, text=True)

    def test_script_exit_codes_and_fail_closed(self):
        argv = ["--protect", str(self.state), "--protect", str(self.token)]
        event = lambda **i: json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": i, "cwd": str(self.work)})
        ok = self.run_hook(event(file_path="src/main.py"), *argv)
        self.assertEqual((ok.returncode, ok.stdout, ok.stderr), (0, "", ""))
        blocked = self.run_hook(event(file_path=str(self.token)), *argv)
        self.assertEqual(blocked.returncode, 2)
        self.assertIn("Secret Guard: blocked", blocked.stderr)
        self.assertNotIn(str(self.token), blocked.stderr)
        self.assertEqual(self.run_hook("not json", *argv).returncode, 2)
        self.assertEqual(self.run_hook(json.dumps({"tool_input": {}}), *argv).returncode, 2)
        self.assertEqual(self.run_hook(event(file_path="src/main.py")).returncode, 2)
        self.assertEqual(self.run_hook(event(file_path="src/main.py"), "--protect").returncode, 2)

    def test_claude_config_writes_settings_with_hook(self):
        out, settings = str(self.work / "run.mcp.json"), str(self.work / "run.settings.json")
        profile = self.home / "approval-profile"
        base = [sys.executable, "-m", "secret_guard.cli", "--state", str(self.state), "claude-config", "--token-file", str(self.token), "--out", out]
        subprocess.run(base + ["--settings-out", settings, "--protect", str(profile)], check=True, capture_output=True)
        self.assertEqual(os.stat(settings).st_mode & 0o777, 0o600)
        data = json.loads(Path(settings).read_text())
        (entry,) = data["hooks"]["PreToolUse"]
        self.assertEqual(entry["matcher"], "*")
        command = entry["hooks"][0]["command"]
        self.assertNotIn("synthetic", Path(settings).read_text())
        self.assertIn(f"Read(/{self.state.resolve()}/**)", data["permissions"]["deny"])
        package = Path(claude_hook.__file__).resolve().parent
        for target in (self.state / "vault.key", self.token, out, settings, profile / "Cookies", package / "claude_hook.py"):
            event = json.dumps({"tool_name": "Read", "tool_input": {"file_path": str(target)}, "cwd": str(self.work / "src")})
            run = subprocess.run(command, shell=True, input=event, capture_output=True, text=True)
            self.assertEqual(run.returncode, 2, target)
        event = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "main.py"}, "cwd": str(self.work / "src")})
        self.assertEqual(subprocess.run(command, shell=True, input=event, capture_output=True, text=True).returncode, 0)
        self.assertNotEqual(subprocess.run(base + ["--settings-out", settings], capture_output=True).returncode, 0)

    def test_codex_argv_command(self):
        self.denied("shell", command=["bash", "-lc", f"cat {self.token}"])
        self.denied("shell", command=["cat", "../run/run-01.token"])
        self.allowed("shell", command=["bash", "-lc", "ls src"])

    def codex_launcher(self):
        out = str(self.token.parent / "codex-run")
        subprocess.run([sys.executable, "-m", "secret_guard.cli", "--state", str(self.state), "codex-config",
                        "--token-file", str(self.token), "--out", out], check=True, capture_output=True)
        return out

    def test_codex_config_launcher(self):
        out = self.codex_launcher()
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o700)
        text = Path(out).read_text()
        self.assertNotIn("synthetic", text)
        self.assertIn(f'"{self.state.resolve()}"="none"', text)
        self.assertIn(f'"{self.token.resolve()}"="none"', text)
        self.assertIn('default_permissions="secret_guard"', text)
        self.assertIn("hooks.PreToolUse=", text)
        self.assertIn("mcp_servers.secret_guard=", text)
        self.assertEqual(subprocess.run(["sh", "-n", out]).returncode, 0)
        again = subprocess.run([sys.executable, "-m", "secret_guard.cli", "codex-config", "--token-file", str(self.token), "--out", out], capture_output=True)
        self.assertNotEqual(again.returncode, 0)

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("codex"), "needs the Codex CLI sandbox on macOS")
    def test_codex_sandbox_denies_reads_however_the_path_is_built(self):
        out = self.codex_launcher()
        (self.work / "readme.txt").write_text("hello")
        (self.work / "innocent").symlink_to(self.state)
        def sandboxed(*command):
            return subprocess.run([out, "sandbox", "--", *command], cwd=self.work, capture_output=True, text=True)
        assembled = "+".join(f"chr({ord(c)})" for c in str(self.token))
        for command in (["cat", str(self.state / "vault.key")], ["cat", str(self.token)], ["cat", "innocent/vault.key"],
                        ["ls", str(self.state)], ["python3", "-c", f"print(open({assembled}).read())"]):
            run = sandboxed(*command)
            self.assertNotEqual(run.returncode, 0, command)
            self.assertNotIn("synthetic", run.stdout + run.stderr)
        self.assertEqual(sandboxed("cat", "readme.txt").stdout, "hello")


if __name__ == "__main__":
    unittest.main()
