"""Injector: the agent's MCP backend and the only place on the agent's machine
where a credential exists, in memory, for the length of one request.

It stores no credentials. It freezes and signs each request, sends it to the
relay, and acts only on a decision signed by an approver it was paired with in
person. The relay's word that something is approved is never enough.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time

from . import adapter, matcher, protocol
from .broker import Broker, GuardError
from .crypto import canonical, digest, opaque, verify
from .link import DeviceLink, http_call
from .seal import clean_jwk, jwk, load_or_create_key, sign, unseal

SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY, project TEXT, agent TEXT, token_hash TEXT UNIQUE, expires REAL, active INTEGER);
CREATE TABLE IF NOT EXISTS approvers(id TEXT PRIMARY KEY, jwk TEXT, active INTEGER);
CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, task TEXT, alias TEXT, kind TEXT, request_text TEXT, state TEXT, ref TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS refs(id TEXT PRIMARY KEY, task TEXT, alias TEXT, approver TEXT, expires REAL, active INTEGER);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL, event TEXT, request_id TEXT, task TEXT);
CREATE TABLE IF NOT EXISTS rules(approver TEXT PRIMARY KEY, version INTEGER, rules_text TEXT);
"""
MIGRATIONS = ["ALTER TABLE requests ADD COLUMN reason TEXT", "ALTER TABLE refs ADD COLUMN type TEXT", "ALTER TABLE refs ADD COLUMN used INTEGER DEFAULT 0"]
ALIAS = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def load_config(state, kind, user=None, relay=None):
    """Device identity for an injector or approver; created once by the trusted CLI."""
    state = Path(state).resolve()
    path = state / "config.json"
    if not path.exists():
        if not user:
            raise GuardError("not_initialized")
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"kind": kind, "user": user, "relay": relay, "device": opaque(kind + "_")[:40]}, f)
    os.chmod(state, 0o700)
    config = json.loads(path.read_text())
    if config.get("kind") != kind:
        raise GuardError("not_initialized")
    return state, config


class Injector:
    def __init__(self, state, call=None, transport=None, clock=time.time, user=None, relay=None):
        self.state, self.config = load_config(state, "injector", user, relay)
        self.user, self.device = self.config["user"], self.config["device"]
        self.signing = load_or_create_key(self.state / "device.key")
        self.sealing = load_or_create_key(self.state / "seal.key")
        self.link = DeviceLink(call or http_call(self.config["relay"]), self.device, self.signing)
        self.db = self.state / "injector.sqlite3"
        self.clock = clock
        self.transport = transport or adapter.fetch
        self.lock = threading.RLock()
        self.running = threading.Lock()
        self.settle_seconds = 0
        self.values = {}  # operation id -> {alias: value}, in memory until the hook takes them
        with self.tx() as db:
            db.executescript(SCHEMA)
            for statement in MIGRATIONS:
                try:
                    db.execute(statement)
                except sqlite3.OperationalError:
                    pass
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

    # Trusted CLI surface.
    def pairing(self):
        """Public keys only. Shown to the approver and registered with the relay."""
        return {"kind": "injector", "device": self.device, "user": self.user, "jwk": jwk(self.signing), "enc_jwk": jwk(self.sealing)}

    def pair_approver(self, device, user, public):
        if user != self.user or not isinstance(device, str) or not device:
            raise GuardError("pairing_invalid")
        try:
            public = clean_jwk(public)
        except Exception:
            raise GuardError("pairing_invalid") from None
        with self.tx() as db:
            if db.execute("SELECT 1 FROM approvers WHERE id=?", (device,)).fetchone():
                raise GuardError("device_exists")
            db.execute("INSERT INTO approvers VALUES(?,?,1)", (device, canonical(public)))
            self.audit(db, "approver_paired")

    def new_task(self, project, agent="codex", ttl=28800):
        if not project or not agent or not 1 <= ttl <= 28800:
            raise GuardError("invalid_task")
        token, task = opaque("t_"), opaque("task_")
        with self.tx() as db:
            db.execute("INSERT INTO tasks VALUES(?,?,?,?,?,1)", (task, project, agent, digest(token), self.clock() + ttl))
            self.audit(db, "task_created", task=task)
        return {"task_id": task, "token": token}

    def revoke(self, kind, identity):
        with self.tx() as db:
            if kind == "task":
                db.execute("UPDATE tasks SET active=0 WHERE id=?", (identity,))
                db.execute("UPDATE refs SET active=0 WHERE task=?", (identity,))
                db.execute("UPDATE requests SET state='revoked' WHERE task=? AND state='pending'", (identity,))
            elif kind == "approver":
                db.execute("UPDATE approvers SET active=0 WHERE id=?", (identity,))
                db.execute("UPDATE refs SET active=0 WHERE approver=?", (identity,))
            elif kind == "operation":
                db.execute("UPDATE requests SET state='revoked' WHERE id=? AND state='pending'", (identity,))
                db.execute("UPDATE refs SET active=0 WHERE id=(SELECT ref FROM requests WHERE id=? AND kind='reference')", (identity,))
            else:
                raise GuardError("revoke_invalid")
            self.audit(db, "revoked_" + kind)

    def activity(self):
        with self.tx() as db:
            return [dict(row) for row in db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 100")]

    # Agent surface: the same three calls the MCP bridge already speaks.
    def task(self, db, token):
        row = db.execute("SELECT * FROM tasks WHERE token_hash=?", (digest(token),)).fetchone()
        if not row or not row["active"] or row["expires"] <= self.clock():
            raise GuardError("task_unauthorized")
        return row

    def valid_ref(self, db, task, ref, alias=None):
        row = db.execute("SELECT * FROM refs WHERE id=? AND task=? AND active=1 AND expires>?", (ref, task["id"], self.clock())).fetchone()
        if not row or (alias and row["alias"] != alias):
            raise GuardError("reference_invalid")
        if not db.execute("SELECT 1 FROM approvers WHERE id=? AND active=1", (row["approver"],)).fetchone():
            raise GuardError("reference_invalid")
        return row

    def create_request(self, db, task, alias, kind, details, ref=None, once=False):
        # A person's denial stays sticky for the identical request within a task. An automatic
        # rejection does not: its cause (a missing credential, a pairing) can be fixed and retried.
        for row in db.execute("SELECT * FROM requests WHERE task=? AND alias=? AND kind=?", (task["id"], alias, kind)):
            p = json.loads(row["request_text"])
            if p["details"] == details and row["ref"] == (ref if kind == "use" else row["ref"]):
                sticky = row["state"] == "denied" and row["reason"] in (None, "user_denied")
                if sticky or (row["state"] == "pending" and p["expires_at"] > self.clock()):
                    return self.safe(db, row)
        if once and db.execute("SELECT used FROM refs WHERE id=?", (ref,)).fetchone()[0]:
            raise GuardError("reference_used")
        if db.execute("SELECT count(*) FROM requests WHERE task=? AND state='pending'", (task["id"],)).fetchone()[0] >= 20:
            raise GuardError("too_many_pending_requests")
        preview = {"kind": kind, "project": task["project"], "task": task["id"], "credential": alias, "details": details}
        request_text = canonical({
            "domain": protocol.REQUEST_DOMAIN, "request_id": opaque("op_"), "nonce": opaque("n_"),
            "principal": self.user, "project": task["project"], "task": task["id"], "agent": task["agent"],
            "injector": self.device, "secret_id": alias, "kind": kind,
            "preview": preview, "preview_digest": digest(preview),
            "expires_at": min(self.clock() + protocol.USE_TTL, task["expires"]), "max_uses": 1, "details": details})
        request_id = json.loads(request_text)["request_id"]
        # Nothing is recorded as pending unless the relay accepted the signed request.
        self.link.request("/injector/submit", {"request_text": request_text, "signature": sign(self.signing, protocol.request_message(request_text))})
        db.execute("INSERT INTO requests VALUES(?,?,?,?,?,'pending',?,NULL,NULL)", (request_id, task["id"], alias, kind, request_text, ref))
        if once:
            db.execute("UPDATE refs SET used=1 WHERE id=?", (ref,))
        self.audit(db, "requested", request_id, task["id"])
        return {"operation_id": request_id, "state": "pending"}

    def reference(self, token, alias, type="once"):
        if not isinstance(alias, str) or not ALIAS.fullmatch(alias) or type not in protocol.REF_TYPES:
            raise GuardError("arguments_invalid")
        with self.tx() as db:
            task = self.task(db, token)
            for row in db.execute("SELECT * FROM refs WHERE task=? AND alias=? AND type=? AND used=0 AND active=1 AND expires>?", (task["id"], alias, type, self.clock())).fetchall():
                try:
                    self.valid_ref(db, task, row["id"])
                    return {"state": "approved", "ref": row["id"], "type": type, "expires_at": row["expires"]}
                except GuardError:
                    pass
            out = self.create_request(db, task, alias, "reference", protocol.reference_details(type))
        return self.settle(token, out)

    # Hook surface. The hook beside the agent sends what a tool returned (scan) or what a tool
    # is about to receive (fill); the matchers and, briefly, an approved value stay in here.
    def matcher_sets(self, db):
        rows = db.execute("SELECT r.rules_text FROM rules r JOIN approvers a ON a.id=r.approver WHERE a.active=1").fetchall()
        return [json.loads(row["rules_text"]) for row in rows]

    def scan(self, token, texts):
        """Where credentials sit in each text: [[start, end, alias], ...] in UTF-8 byte offsets."""
        if not isinstance(texts, list) or not all(isinstance(t, str) for t in texts):
            raise GuardError("arguments_invalid")
        with self.tx() as db:
            self.task(db, token)
            sets = self.matcher_sets(db)
        try:
            return {"found": [matcher.scan(text.encode(), sets) for text in texts]}
        except ValueError:
            raise GuardError("content_too_large") from None

    def hook_request(self, token, kind, tool, target, summary, call, secrets):
        """Ask the approver about one tool call: may this content reach the agent (reveal),
        may these references become credentials for this call (fill)."""
        if not (kind in protocol.HOOK_KINDS and isinstance(tool, str) and 0 < len(tool) <= 128
                and isinstance(target, str) and len(target) <= 300 and isinstance(summary, str) and len(summary) <= 600
                and isinstance(call, str) and re.fullmatch(r"[0-9a-f]{64}", call) and isinstance(secrets, list)
                and 0 < len(secrets) <= 20 and all(isinstance(a, str) and ALIAS.fullmatch(a) for a in secrets)):
            raise GuardError("arguments_invalid")
        with self.tx() as db:
            task = self.task(db, token)
            out = self.create_request(db, task, "", kind, protocol.hook_details(kind, tool, target, summary, call, sorted(set(secrets))))
        return self.settle(token, out)

    def take(self, token, operation_id):
        """Hand an approved fill's values to the hook, once. They were never written to disk."""
        with self.tx() as db:
            task = self.task(db, token)
            done = db.execute("UPDATE requests SET state='used' WHERE id=? AND task=? AND kind='fill' AND state='approved'", (operation_id, task["id"])).rowcount
            values = self.values.pop(operation_id, None)
            if not done or values is None:
                raise GuardError("operation_unavailable")
            self.audit(db, "filled", operation_id, task["id"])
        return {"values": values}

    def sync_rules(self):
        """Fetch the approvers' compiled matchers from the relay. Only a paired approver's signature
        counts, and a version never goes backwards, so the relay can neither invent nor roll back a set."""
        try:
            entries = self.link.request("/injector/rules", {})["rules"]
        except Exception:
            return False
        with self.tx() as db:
            for entry in entries:
                try:
                    paired = db.execute("SELECT * FROM approvers WHERE id=? AND active=1", (entry["approver"],)).fetchone()
                    verify(json.loads(paired["jwk"]), protocol.rules_message(entry["rules_text"]), entry["signature"])
                    payload = json.loads(entry["rules_text"])
                    old = db.execute("SELECT version FROM rules WHERE approver=?", (paired["id"],)).fetchone()
                    if payload["approver"] != paired["id"] or type(payload["version"]) is not int or (old and payload["version"] <= old[0]) \
                            or not matcher.valid_set(payload):
                        continue
                    db.execute("INSERT OR REPLACE INTO rules VALUES(?,?,?)", (paired["id"], payload["version"], entry["rules_text"]))
                    self.audit(db, "rules_updated")
                except Exception:
                    continue
        return True

    def settle(self, token, out):
        """Give a just-submitted request a moment to be rejected automatically, so the
        caller sees the reason in this answer instead of a bare pending."""
        deadline = time.monotonic() + self.settle_seconds
        while out.get("state") == "pending" and time.monotonic() < deadline:
            time.sleep(0.2)
            self.run_ready(out["operation_id"])
            out = self.status(token, out["operation_id"])
        return out

    def workflow(self, token, ref, repo, limit=10):
        try:
            details = adapter.freeze(adapter.normalize(repo, limit))
        except Exception:
            raise GuardError("arguments_invalid") from None
        with self.tx() as db:
            task = self.task(db, token)
            row = self.valid_ref(db, task, ref)
            out = self.create_request(db, task, row["alias"], "use", details, ref, row["type"] == "once")
        return self.settle(token, out)

    def safe(self, db, row):
        state = row["state"]
        if state == "pending" and json.loads(row["request_text"])["expires_at"] <= self.clock():
            state = "expired"
            db.execute("UPDATE requests SET state='expired' WHERE id=?", (row["id"],))
        out = {"operation_id": row["id"], "state": state}
        reason = "no_response" if state == "expired" else row["reason"]
        if reason:
            out.update(reason=reason, message=protocol.explain(reason))
        if row["kind"] == "reference" and state == "approved":
            task = db.execute("SELECT * FROM tasks WHERE id=?", (row["task"],)).fetchone()
            try:
                ref = self.valid_ref(db, task, row["ref"], row["alias"])
                out.update(ref=ref["id"], type=ref["type"], expires_at=ref["expires"])
                if ref["type"] == "once":
                    out["uses_left"] = 0 if ref["used"] else 1
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

    # Background work: collect decisions from the relay and act on them.
    def report(self, request_id, event):
        try:
            self.link.request("/injector/report", {"request_id": request_id, "event": event})
        except Exception:
            pass  # Audit at the relay is best effort; local state is authoritative.

    def approver_key(self, db, device, request_text, signature):
        """The decision must be signed by an approver this injector was paired with."""
        row = db.execute("SELECT * FROM approvers WHERE id=? AND active=1", (device,)).fetchone()
        if not row:
            raise GuardError("device_unauthorized")
        verify(json.loads(row["jwk"]), protocol.decision_message("approve", device, request_text), signature)

    def denial(self, db, row, answer):
        """Reason for a denial, believed only when signed by a paired approver."""
        approver, reason = answer.get("approver"), answer.get("reason") or ""
        if reason and reason not in protocol.REASONS:
            return None
        paired = db.execute("SELECT * FROM approvers WHERE id=? AND active=1", (approver,)).fetchone()
        if not paired:
            return "approver_not_paired" if approver else None
        try:
            verify(json.loads(paired["jwk"]), protocol.decision_message("deny", approver, row["request_text"], reason), answer.get("signature"))
        except Exception:
            return None
        return reason or "user_denied"

    def run_ready(self, only=None):
        # One collector at a time: a sealed credential is delivered once, to one reader.
        with self.running:
            self.collect(only)

    def collect(self, only):
        with self.tx() as db:
            rows = [r for r in db.execute("SELECT * FROM requests WHERE state='pending'").fetchall()
                    if only in (None, r["id"]) and self.safe(db, r)["state"] == "pending"]
        for row in rows:
            try:
                answer = self.link.request("/injector/poll", {"request_id": row["id"]})
            except Exception:
                continue  # Relay unreachable: nothing executes; try again later.
            state = answer.get("state")
            if state == "pending":
                continue
            if state == "approved" and row["kind"] == "use":
                self.execute(row["id"], answer)
            elif state == "approved":
                self.grant(row["id"], answer)
            else:
                with self.tx() as db:
                    final = state if state in {"denied", "expired"} else "revoked"
                    reason = self.denial(db, row, answer) if final == "denied" else None
                    db.execute("UPDATE requests SET state=?,reason=? WHERE id=? AND state='pending'", (final, reason, row["id"]))
                    self.audit(db, final, row["id"], row["task"])

    def grant(self, request_id, answer):
        """An approved reference becomes a ref; an approved reveal or fill lets the hook finish that one tool call."""
        with self.tx() as db:
            row = db.execute("SELECT * FROM requests WHERE id=? AND kind IN ('reference','reveal','fill') AND state='pending'", (request_id,)).fetchone()
            if not row:
                return False
            task = db.execute("SELECT * FROM tasks WHERE id=? AND active=1 AND expires>?", (row["task"], self.clock())).fetchone()
            try:
                self.approver_key(db, answer["approver"], row["request_text"], answer["signature"])
                if not task or json.loads(row["request_text"])["expires_at"] <= self.clock():
                    raise GuardError("expired")
                kind = json.loads(row["request_text"])["details"]["type"] if row["kind"] == "reference" else None
                if row["kind"] == "reference" and kind not in protocol.REF_TYPES:
                    raise GuardError("request_invalid")
            except Exception as exc:
                db.execute("UPDATE requests SET state='revoked',reason=? WHERE id=?", ("approver_not_paired" if str(exc) == "device_unauthorized" else None, request_id))
                self.audit(db, "approval_rejected", request_id, row["task"])
                return False
            if row["kind"] == "fill":
                try:
                    # Opens only if sealed to this injector for exactly this request.
                    values = json.loads(unseal(self.sealing, answer["sealed"], protocol.seal_aad(row["request_text"])))
                    wanted = json.loads(row["request_text"])["details"]["secrets"]
                    if sorted(values) != wanted or not all(isinstance(v, str) for v in values.values()):
                        raise ValueError
                except Exception:
                    db.execute("UPDATE requests SET state='revoked' WHERE id=?", (request_id,))
                    self.audit(db, "execution_blocked", request_id, row["task"])
                    return False
                self.values[request_id] = values
            if row["kind"] in protocol.HOOK_KINDS:
                db.execute("UPDATE requests SET state='approved' WHERE id=?", (request_id,))
                self.audit(db, row["kind"] + "_approved", request_id, task["id"])
                return True
            ref = opaque("secretref://r_")
            # The expiry is fixed here, when the approval arrives, and reported in status.
            db.execute("INSERT INTO refs VALUES(?,?,?,?,?,1,?,0)", (ref, task["id"], row["alias"], answer["approver"], min(self.clock() + protocol.REF_TTL, task["expires"]), kind))
            db.execute("UPDATE requests SET state='approved',ref=? WHERE id=?", (ref, request_id))
            self.audit(db, "approved", request_id, task["id"])
        return True

    def execute(self, request_id, answer):
        with self.tx() as db:
            row = db.execute("SELECT * FROM requests WHERE id=? AND kind='use' AND state='pending'", (request_id,)).fetchone()
            if not row:
                return False
            payload = json.loads(row["request_text"])
            task = db.execute("SELECT * FROM tasks WHERE id=? AND active=1 AND expires>?", (row["task"], self.clock())).fetchone()
            try:
                self.approver_key(db, answer["approver"], row["request_text"], answer["signature"])
                if not task or payload["expires_at"] <= self.clock():
                    raise GuardError("expired")
                self.valid_ref(db, task, row["ref"], row["alias"])
                if payload["details"] != adapter.freeze(payload["details"]["args"]):
                    raise GuardError("request_changed")
                # Opens only if sealed to this injector for exactly this request.
                token = unseal(self.sealing, answer["sealed"], protocol.seal_aad(row["request_text"])).decode()
            except Exception as exc:
                db.execute("UPDATE requests SET state='revoked',reason=? WHERE id=?", ("approver_not_paired" if str(exc) == "device_unauthorized" else None, request_id))
                self.audit(db, "execution_blocked", request_id, row["task"])
                blocked = True
            else:
                blocked = False
                # Durable atomic consumption BEFORE network. Never restore this grant.
                db.execute("UPDATE requests SET state='executing' WHERE id=?", (request_id,))
                self.audit(db, "consumed", request_id, row["task"])
        if blocked:
            self.report(request_id, "blocked")
            return False
        self.report(request_id, "executing")
        try:
            raw = self.transport(payload["details"], token)
            Broker.check_output(raw, [token])
            result = adapter.structured_result(raw, payload["details"]["args"]["limit"])
            Broker.check_output(canonical(result).encode(), [token])
            state = "succeeded"
        except Exception:
            # Conservatively unknown: no external error body, no automatic retry.
            result, state = None, "unknown"
        finally:
            token = None
        with self.tx() as db:
            db.execute("UPDATE requests SET state=?,result=? WHERE id=? AND state='executing'", (state, canonical(result) if result else None, request_id))
            self.audit(db, state, request_id, row["task"])
        self.report(request_id, state)
        return True

    def recover(self):
        with self.tx() as db:
            for row in db.execute("SELECT id,task FROM requests WHERE state='executing'").fetchall():
                db.execute("UPDATE requests SET state='unknown' WHERE id=?", (row["id"],))
                self.audit(db, "recovered_unknown", row["id"], row["task"])
