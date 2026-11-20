import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import adapter
from .crypto import canonical, digest, opaque, public_key, verify


class GuardError(Exception):
    """Only fixed, public error codes may cross the agent boundary."""


SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets(alias TEXT PRIMARY KEY, version INTEGER, ciphertext BLOB, repos TEXT, active INTEGER);
CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY, user TEXT, project TEXT, agent TEXT, token_hash TEXT UNIQUE, expires REAL, active INTEGER);
CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, user TEXT, jwk TEXT, active INTEGER);
CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY, device TEXT, expires REAL, consumed INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, device TEXT, expires REAL);
CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, task TEXT, alias TEXT, kind TEXT, payload TEXT, state TEXT, ref TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS refs(id TEXT PRIMARY KEY, task TEXT, alias TEXT, version INTEGER, device TEXT, expires REAL, active INTEGER);
CREATE TABLE IF NOT EXISTS approvals(request_id TEXT PRIMARY KEY, payload TEXT, signature TEXT);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL, event TEXT, request_id TEXT, task TEXT);
"""


class Broker:
    def __init__(self, state, transport=None, clock=time.time):
        self.state = Path(state).resolve()
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state, 0o700)
        self.db = self.state / "guard.sqlite3"
        self.keyfile = self.state / "vault.key"
        if not self.keyfile.exists():
            fd = os.open(self.keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(AESGCM.generate_key(bit_length=256))
        self.vault = AESGCM(self.keyfile.read_bytes())
        self.clock = clock
        self.transport = transport or adapter.fetch
        self.lock = threading.RLock()
        with self.tx() as db:
            db.executescript(SCHEMA)
        os.chmod(self.db, 0o600)

    @contextmanager
    def tx(self):
        with self.lock:
            db = sqlite3.connect(self.db, timeout=30)
            db.row_factory = sqlite3.Row
            try:
                db.execute("BEGIN IMMEDIATE")
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()

    def audit(self, db, event, request_id="", task=""):
        db.execute("INSERT INTO audit(at,event,request_id,task) VALUES(?,?,?,?)", (self.clock(), event, request_id, task))

    def add_secret(self, alias, value, repos, user, project):
        if not alias or not value or len(value) < 8 or len(value) > 4096:
            raise GuardError("invalid_secret")
        normalized = sorted({adapter.normalize(repo, 1)["repo"] for repo in repos})
        if not normalized or not user or not project:
            raise GuardError("empty_policy")
        with self.tx() as db:
            row = db.execute("SELECT version FROM secrets WHERE alias=?", (alias,)).fetchone()
            version = row[0] + 1 if row else 1
            nonce = secrets.token_bytes(12)
            ciphertext = nonce + self.vault.encrypt(nonce, value.encode(), canonical([alias, version]).encode())
            policy = {"repos": normalized, "user": user, "project": project}
            db.execute("INSERT OR REPLACE INTO secrets VALUES(?,?,?,?,1)", (alias, version, ciphertext, canonical(policy)))
            db.execute("UPDATE refs SET active=0 WHERE alias=?", (alias,))
            db.execute("UPDATE requests SET state='revoked' WHERE alias=? AND state IN ('pending','approved')", (alias,))
            self.audit(db, "secret_updated")

    def decrypt(self, row):
        value = row["ciphertext"]
        return self.vault.decrypt(value[:12], value[12:], canonical([row["alias"], row["version"]]).encode()).decode()

    def new_task(self, user, project, agent="codex", ttl=28800):
        if not user or not project or not agent or not 1 <= ttl <= 28800:
            raise GuardError("invalid_task")
        token, task = opaque("t_"), opaque("task_")
        with self.tx() as db:
            db.execute("INSERT INTO tasks VALUES(?,?,?,?,?,?,1)", (task, user, project, agent, digest(token), self.clock() + ttl))
            self.audit(db, "task_created", task=task)
        return {"task_id": task, "token": token}

    def register_device(self, device, user, jwk):
        public_key(jwk)
        with self.tx() as db:
            # Identity/key replacement requires explicit revoke then a NEW id.
            db.execute("INSERT INTO devices VALUES(?,?,?,1)", (device, user, canonical(jwk)))
            self.audit(db, "device_registered")

    def task(self, db, token):
        row = db.execute("SELECT * FROM tasks WHERE token_hash=?", (digest(token),)).fetchone()
        if not row or not row["active"] or row["expires"] <= self.clock():
            raise GuardError("task_unauthorized")
        return row

    def device(self, db, device):
        row = db.execute("SELECT * FROM devices WHERE id=? AND active=1", (device,)).fetchone()
        if not row:
            raise GuardError("device_unauthorized")
        return row

    def challenge(self, device):
        with self.tx() as db:
            self.device(db, device)
            db.execute("DELETE FROM challenges WHERE expires<=?", (self.clock(),))
            count = db.execute("SELECT count(*) FROM challenges WHERE device=? AND consumed=0", (device,)).fetchone()[0]
            if count >= 5:
                raise GuardError("too_many_challenges")
            challenge = opaque("challenge_")
            db.execute("INSERT INTO challenges VALUES(?,?,?,0)", (challenge, device, self.clock() + 60))
        return {"challenge": challenge, "message": "secret-guard/login/v1:" + challenge}

    def login(self, device, challenge, signature):
        with self.tx() as db:
            dev = self.device(db, device)
            row = db.execute("SELECT * FROM challenges WHERE id=? AND device=?", (challenge, device)).fetchone()
            if not row or row["consumed"] or row["expires"] <= self.clock():
                raise GuardError("challenge_invalid")
            try:
                verify(json.loads(dev["jwk"]), "secret-guard/login/v1:" + challenge, signature)
            except Exception:
                raise GuardError("signature_invalid") from None
            db.execute("UPDATE challenges SET consumed=1 WHERE id=?", (challenge,))
            token = opaque("s_")
            db.execute("DELETE FROM sessions WHERE expires<=?", (self.clock(),))
            db.execute("INSERT INTO sessions VALUES(?,?,?)", (digest(token), device, self.clock() + 300))
        return {"token": token, "expires_in": 300}

    def session(self, db, token):
        row = db.execute("SELECT * FROM sessions WHERE token_hash=?", (digest(token),)).fetchone()
        if not row or row["expires"] <= self.clock():
            raise GuardError("device_unauthorized")
        return self.device(db, row["device"])

    def secret(self, db, alias):
        row = db.execute("SELECT * FROM secrets WHERE alias=? AND active=1", (alias,)).fetchone()
        if not row:
            raise GuardError("secret_unavailable")
        return row

    def policy(self, task, secret):
        policy = json.loads(secret["repos"])
        if policy["user"] != task["user"] or policy["project"] != task["project"]:
            raise GuardError("policy_denied")
        return policy

    def payload(self, task, secret, kind, details):
        preview = {"kind": kind, "project": task["project"], "task": task["id"], "credential": secret["alias"], "details": details}
        return {"domain": "secret-guard/approval/v1", "request_id": opaque("op_"), "nonce": opaque("n_"),
                "principal": task["user"], "task": task["id"], "agent": task["agent"],
                "secret_id": secret["alias"], "secret_version": secret["version"], "kind": kind,
                "policy_version": digest(json.loads(secret["repos"])),
                "preview": preview, "preview_digest": digest(preview),
                "expires_at": min(self.clock() + 120, task["expires"]), "max_uses": 1,
                "details": details}

    def create_request(self, db, task, secret, kind, details, ref=None):
        # Denials remain sticky for identical requests within a task. Trusted CLI
        # must create a new task to retry; an agent cannot reset this record.
        for row in db.execute("SELECT * FROM requests WHERE task=? AND alias=? AND kind=?", (task["id"], secret["alias"], kind)):
            p = json.loads(row["payload"])
            if p["details"] == details and p["secret_version"] == secret["version"] and row["ref"] == ref:
                if row["state"] == "denied":
                    return self.safe(db, row)
                if row["state"] in {"pending", "approved"} and p["expires_at"] > self.clock():
                    return self.safe(db, row)
        pending = db.execute("SELECT count(*) FROM requests WHERE task=? AND state IN ('pending','approved')", (task["id"],)).fetchone()[0]
        if pending >= 20:
            raise GuardError("too_many_pending_requests")
        payload = self.payload(task, secret, kind, details)
        db.execute("INSERT INTO requests VALUES(?,?,?,?,?,'pending',?,NULL)",
                   (payload["request_id"], task["id"], secret["alias"], kind, canonical(payload), ref))
        self.audit(db, "requested", payload["request_id"], task["id"])
        return {"operation_id": payload["request_id"], "state": "pending"}

    def reference(self, token, alias, type="once"):
        # The MCP tool offers `type` for the injector backend; here every reference behaves the same way.
        if type not in ("once", "long"):
            raise GuardError("request_invalid")
        with self.tx() as db:
            task, secret = self.task(db, token), self.secret(db, alias)
            self.policy(task, secret)
            row = db.execute("SELECT * FROM refs WHERE task=? AND alias=? AND active=1 AND expires>? AND version=?", (task["id"], alias, self.clock(), secret["version"])).fetchone()
            if row:
                self.device(db, row["device"])
                return {"state": "approved", "ref": row["id"], "expires_at": row["expires"]}
            return self.create_request(db, task, secret, "reference", {"scope": "task_reference_only", "ttl_seconds": 28800})

    def valid_ref(self, db, task, ref, secret):
        row = db.execute("SELECT * FROM refs WHERE id=? AND task=? AND alias=? AND version=? AND active=1 AND expires>?", (ref, task["id"], secret["alias"], secret["version"], self.clock())).fetchone()
        if not row:
            raise GuardError("reference_invalid")
        self.device(db, row["device"])
        return row

    def workflow(self, token, ref, repo, limit=10):
        try:
            details = adapter.freeze(adapter.normalize(repo, limit))
        except Exception:
            raise GuardError("arguments_invalid") from None
        with self.tx() as db:
            task = self.task(db, token)
            r = db.execute("SELECT alias FROM refs WHERE id=? AND task=?", (ref, task["id"])).fetchone()
            if not r:
                raise GuardError("reference_invalid")
            secret = self.secret(db, r["alias"])
            self.valid_ref(db, task, ref, secret)
            if details["args"]["repo"] not in self.policy(task, secret)["repos"]:
                raise GuardError("policy_denied")
            return self.create_request(db, task, secret, "use", details, ref)

    def safe(self, db, row):
        state = row["state"]
        payload = json.loads(row["payload"])
        if (state == "pending" or (state == "approved" and row["kind"] == "use")) and payload["expires_at"] <= self.clock():
            state = "expired"
            db.execute("UPDATE requests SET state='expired' WHERE id=?", (row["id"],))
        out = {"operation_id": row["id"], "state": state}
        if row["kind"] == "reference" and state == "approved" and row["ref"]:
            task = db.execute("SELECT * FROM tasks WHERE id=?", (row["task"],)).fetchone()
            try:
                ref = self.valid_ref(db, task, row["ref"], self.secret(db, row["alias"]))
                out.update(ref=ref["id"], expires_at=ref["expires"])
            except GuardError:
                out["state"] = "revoked"
        if state == "succeeded":
            out["result"] = json.loads(row["result"])
        return out

    def status(self, token, operation_id):
        with self.tx() as db:
            task = self.task(db, token)
            row = db.execute("SELECT * FROM requests WHERE id=? AND task=?", (operation_id, task["id"])).fetchone()
            if not row:
                raise GuardError("operation_unavailable")
            return self.safe(db, row)

    def pending(self, token):
        with self.tx() as db:
            device = self.session(db, token)
            out = []
            for row in db.execute("SELECT r.* FROM requests r JOIN tasks t ON r.task=t.id WHERE t.user=? AND t.active=1 AND t.expires>? AND r.state='pending'", (device["user"], self.clock())).fetchall():
                if self.safe(db, row)["state"] == "pending":
                    payload = json.loads(row["payload"])
                    # Bind each signature to its registered signing device.
                    payload["device"] = device["id"]
                    out.append({"payload": payload, "signing_text": canonical(payload)})
            return {"requests": out}

    def decide(self, token, operation_id, decision, signature):
        if decision not in {"approve", "deny"}:
            raise GuardError("decision_invalid")
        with self.tx() as db:
            device = self.session(db, token)
            row = db.execute("SELECT * FROM requests WHERE id=?", (operation_id,)).fetchone()
            if not row or self.safe(db, row)["state"] != "pending":
                raise GuardError("request_not_pending")
            payload = json.loads(row["payload"])
            task = db.execute("SELECT * FROM tasks WHERE id=? AND active=1 AND expires>?", (row["task"], self.clock())).fetchone()
            if not task or task["user"] != device["user"]:
                raise GuardError("device_unauthorized")
            secret = self.secret(db, row["alias"])
            if secret["version"] != payload["secret_version"] or digest(json.loads(secret["repos"])) != payload["policy_version"]:
                raise GuardError("request_changed")
            payload["device"] = device["id"]
            try:
                verify(json.loads(device["jwk"]), "secret-guard/decision/v1:" + decision + ":" + canonical(payload), signature)
            except Exception:
                raise GuardError("signature_invalid") from None
            db.execute("INSERT INTO approvals VALUES(?,?,?)", (operation_id, canonical(payload), signature))
            state, ref = ("approved" if decision == "approve" else "denied"), row["ref"]
            if decision == "approve" and row["kind"] == "reference":
                ref = opaque("secretref://r_")
                db.execute("INSERT INTO refs VALUES(?,?,?,?,?,?,1)", (ref, task["id"], secret["alias"], secret["version"], device["id"], min(self.clock() + 28800, task["expires"])))
            db.execute("UPDATE requests SET state=?,ref=?,payload=? WHERE id=?", (state, ref, canonical(payload), operation_id))
            self.audit(db, state, operation_id, task["id"])
        return {"state": state}

    def execute(self, operation_id):
        with self.tx() as db:
            row = db.execute("SELECT * FROM requests WHERE id=? AND kind='use' AND state='approved'", (operation_id,)).fetchone()
            if not row:
                return False
            payload = json.loads(row["payload"])
            task = db.execute("SELECT * FROM tasks WHERE id=? AND active=1 AND expires>?", (row["task"], self.clock())).fetchone()
            try:
                secret = self.secret(db, row["alias"])
                device = self.device(db, payload["device"])
                approval = db.execute("SELECT * FROM approvals WHERE request_id=?", (operation_id,)).fetchone()
                if not approval or approval["payload"] != canonical(payload):
                    raise GuardError("request_changed")
                verify(json.loads(device["jwk"]), "secret-guard/decision/v1:approve:" + approval["payload"], approval["signature"])
                if not task or payload["expires_at"] <= self.clock():
                    raise GuardError("expired")
                self.valid_ref(db, task, row["ref"], secret)
                if secret["version"] != payload["secret_version"] or digest(json.loads(secret["repos"])) != payload["policy_version"]:
                    raise GuardError("request_changed")
                if payload["details"] != adapter.freeze(payload["details"]["args"]):
                    raise GuardError("request_changed")
                if payload["details"]["args"]["repo"] not in self.policy(task, secret)["repos"]:
                    raise GuardError("policy_denied")
                token = self.decrypt(secret)
                # Retain all currently registered matching material inside broker.
                protected = [self.decrypt(s) for s in db.execute("SELECT * FROM secrets").fetchall()]
            except Exception:
                db.execute("UPDATE requests SET state='revoked' WHERE id=?", (operation_id,))
                self.audit(db, "execution_blocked", operation_id, row["task"])
                return False
            # Durable atomic consumption BEFORE network. Never restore this grant.
            db.execute("UPDATE requests SET state='executing' WHERE id=?", (operation_id,))
            self.audit(db, "consumed", operation_id, row["task"])
        try:
            raw = self.transport(payload["details"], token)
            self.check_output(raw, protected)
            result = adapter.structured_result(raw, payload["details"]["args"]["limit"])
            self.check_output(canonical(result).encode(), protected)
            state = "succeeded"
        except Exception:
            # Conservatively unknown: no external error body, no automatic retry.
            result, state = None, "unknown"
        finally:
            token = None
            protected = None
        with self.tx() as db:
            db.execute("UPDATE requests SET state=?,result=? WHERE id=? AND state='executing'", (state, canonical(result) if result else None, operation_id))
            self.audit(db, state, operation_id, row["task"])
        return True

    @staticmethod
    def check_output(raw, protected):
        for value in protected:
            variants = {value, base64.b64encode(value.encode()).decode(), value.encode().hex(), quote(value, safe=""), canonical(value)[1:-1]}
            if any(v.encode() in raw for v in variants):
                raise GuardError("protected_output")

    def recover(self):
        with self.tx() as db:
            for row in db.execute("SELECT id,task FROM requests WHERE state='executing'").fetchall():
                db.execute("UPDATE requests SET state='unknown' WHERE id=?", (row["id"],))
                self.audit(db, "recovered_unknown", row["id"], row["task"])

    def run_ready(self):
        with self.tx() as db:
            ids = [r[0] for r in db.execute("SELECT id FROM requests WHERE kind='use' AND state='approved'")]
        for operation_id in ids:
            self.execute(operation_id)

    def revoke(self, kind, identity):
        with self.tx() as db:
            if kind == "task":
                db.execute("UPDATE tasks SET active=0 WHERE id=?", (identity,))
                db.execute("UPDATE refs SET active=0 WHERE task=?", (identity,))
                db.execute("UPDATE requests SET state='revoked' WHERE task=? AND state IN ('pending','approved')", (identity,))
            elif kind == "secret":
                db.execute("UPDATE secrets SET active=0 WHERE alias=?", (identity,))
                db.execute("UPDATE refs SET active=0 WHERE alias=?", (identity,))
                db.execute("UPDATE requests SET state='revoked' WHERE alias=? AND state IN ('pending','approved')", (identity,))
            elif kind == "device":
                db.execute("UPDATE devices SET active=0 WHERE id=?", (identity,))
                db.execute("UPDATE refs SET active=0 WHERE device=?", (identity,))
                db.execute("DELETE FROM sessions WHERE device=?", (identity,))
            elif kind == "operation":
                db.execute("UPDATE requests SET state='revoked' WHERE id=? AND state IN ('pending','approved')", (identity,))
                db.execute("UPDATE refs SET active=0 WHERE id=(SELECT ref FROM requests WHERE id=? AND kind='reference')", (identity,))
            else:
                raise GuardError("revoke_invalid")
            self.audit(db, "revoked_" + kind)

    def activity(self):
        with self.tx() as db:
            return [dict(row) for row in db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 100")]
