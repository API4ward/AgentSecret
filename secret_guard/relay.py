"""Relay server: connects approvers and injectors. It stores no credentials.

It authenticates registered devices, queues frozen requests, forwards signed
decisions, and audits. An approved use request carries a box sealed to the
injector; the relay cannot open it and hands it out exactly once.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time

from . import protocol
from .broker import GuardError
from .crypto import canonical, digest, opaque, verify
from .seal import clean_jwk, valid_box

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, user TEXT, kind TEXT, jwk TEXT, enc_jwk TEXT, active INTEGER);
CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY, device TEXT, expires REAL, consumed INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, device TEXT, expires REAL);
CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, user TEXT, injector TEXT, kind TEXT, expires REAL, request_text TEXT,
    signature TEXT, state TEXT, approver TEXT, approval TEXT, sealed TEXT);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL, event TEXT, request_id TEXT, device TEXT);
CREATE TABLE IF NOT EXISTS rules(approver TEXT PRIMARY KEY, user TEXT, rules_text TEXT, signature TEXT);
"""
# Columns added after the first prototype; applied to existing databases too.
MIGRATIONS = ["ALTER TABLE requests ADD COLUMN reason TEXT", "ALTER TABLE requests ADD COLUMN declines TEXT"]
IDENT = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
KINDS = {"approver", "injector"}
REPORTS = {"executing", "succeeded", "unknown", "blocked"}
MAX_PENDING = 20


class Relay:
    def __init__(self, state, clock=time.time):
        self.state = Path(state).resolve()
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state, 0o700)
        self.db = self.state / "relay.sqlite3"
        self.clock = clock
        self.lock = threading.RLock()
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

    def audit(self, db, event, request_id="", device=""):
        db.execute("INSERT INTO audit(at,event,request_id,device) VALUES(?,?,?,?)", (self.clock(), event, request_id, device))

    # Trusted administration. Devices never register themselves over the network.
    def register_device(self, device, user, kind, jwk, enc_jwk=None):
        if kind not in KINDS or not user or not isinstance(device, str) or not IDENT.fullmatch(device):
            raise GuardError("device_invalid")
        if (kind == "injector") != bool(enc_jwk):
            raise GuardError("device_invalid")
        try:
            jwk = clean_jwk(jwk)
            enc_jwk = clean_jwk(enc_jwk) if enc_jwk else None
        except Exception:
            raise GuardError("device_invalid") from None
        with self.tx() as db:
            # Replacing a key requires an explicit revoke and a NEW device id.
            if db.execute("SELECT 1 FROM devices WHERE id=?", (device,)).fetchone():
                raise GuardError("device_exists")
            db.execute("INSERT INTO devices VALUES(?,?,?,?,?,1)", (device, user, kind, canonical(jwk), canonical(enc_jwk) if enc_jwk else None))
            self.audit(db, "device_registered", device=device)

    def revoke(self, kind, identity):
        with self.tx() as db:
            if kind == "device":
                db.execute("UPDATE devices SET active=0 WHERE id=?", (identity,))
                db.execute("DELETE FROM sessions WHERE device=?", (identity,))
                db.execute("UPDATE requests SET state='revoked',sealed=NULL WHERE (injector=? OR approver=?) AND state IN ('pending','approved')", (identity, identity))
            elif kind == "request":
                db.execute("UPDATE requests SET state='revoked',sealed=NULL WHERE id=? AND state IN ('pending','approved')", (identity,))
            else:
                raise GuardError("revoke_invalid")
            self.audit(db, "revoked_" + kind, identity if kind == "request" else "", identity if kind == "device" else "")

    def activity(self):
        with self.tx() as db:
            return [dict(row) for row in db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 100")]

    # Device authentication: one-time signed challenge, then a short session.
    def device(self, db, device, kind=None):
        row = db.execute("SELECT * FROM devices WHERE id=? AND active=1", (device,)).fetchone()
        if not row or (kind and row["kind"] != kind):
            raise GuardError("device_unauthorized")
        return row

    def challenge(self, device):
        with self.tx() as db:
            self.device(db, device)
            db.execute("DELETE FROM challenges WHERE expires<=?", (self.clock(),))
            if db.execute("SELECT count(*) FROM challenges WHERE device=? AND consumed=0", (device,)).fetchone()[0] >= 5:
                raise GuardError("too_many_challenges")
            challenge = opaque("challenge_")
            db.execute("INSERT INTO challenges VALUES(?,?,?,0)", (challenge, device, self.clock() + 60))
        return {"challenge": challenge, "message": protocol.LOGIN + challenge}

    def login(self, device, challenge, signature):
        with self.tx() as db:
            dev = self.device(db, device)
            row = db.execute("SELECT * FROM challenges WHERE id=? AND device=?", (challenge, device)).fetchone()
            if not row or row["consumed"] or row["expires"] <= self.clock():
                raise GuardError("challenge_invalid")
            try:
                verify(json.loads(dev["jwk"]), protocol.LOGIN + challenge, signature)
            except Exception:
                raise GuardError("signature_invalid") from None
            db.execute("UPDATE challenges SET consumed=1 WHERE id=?", (challenge,))
            token = opaque("s_")
            db.execute("DELETE FROM sessions WHERE expires<=?", (self.clock(),))
            db.execute("INSERT INTO sessions VALUES(?,?,?)", (digest(token), device, self.clock() + 300))
        return {"token": token, "expires_in": 300}

    def session(self, db, token, kind):
        row = db.execute("SELECT * FROM sessions WHERE token_hash=?", (digest(token or ""),)).fetchone()
        if not row or row["expires"] <= self.clock():
            raise GuardError("device_unauthorized")
        return self.device(db, row["device"], kind)

    def live(self, db, row):
        """Current state, expiring an unanswered request in place."""
        if row["state"] in {"pending", "approved"} and row["expires"] <= self.clock():
            db.execute("UPDATE requests SET state='expired',sealed=NULL WHERE id=?", (row["id"],))
            return "expired"
        return row["state"]

    # Injector side.
    def submit(self, token, request_text, signature):
        if not isinstance(request_text, str) or not 0 < len(request_text) <= protocol.MAX_REQUEST_TEXT:
            raise GuardError("request_invalid")
        try:
            payload = json.loads(request_text)
            if canonical(payload) != request_text or payload["domain"] != protocol.REQUEST_DOMAIN:
                raise ValueError
            request_id, kind, expires = payload["request_id"], payload["kind"], payload["expires_at"]
            if not IDENT.fullmatch(request_id) or kind not in {"reference", "use", "access"} or type(expires) not in {int, float}:
                raise ValueError
        except Exception:
            raise GuardError("request_invalid") from None
        with self.tx() as db:
            injector = self.session(db, token, "injector")
            if payload.get("injector") != injector["id"] or payload.get("principal") != injector["user"]:
                raise GuardError("request_invalid")
            if not self.clock() < expires <= self.clock() + protocol.USE_TTL + 60:
                raise GuardError("request_invalid")
            try:
                verify(json.loads(injector["jwk"]), protocol.request_message(request_text), signature)
            except Exception:
                raise GuardError("signature_invalid") from None
            if db.execute("SELECT 1 FROM requests WHERE id=?", (request_id,)).fetchone():
                raise GuardError("request_exists")
            pending = [r for r in db.execute("SELECT * FROM requests WHERE injector=? AND state='pending'", (injector["id"],)).fetchall() if self.live(db, r) == "pending"]
            if len(pending) >= MAX_PENDING:
                raise GuardError("too_many_pending_requests")
            db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,'pending',NULL,NULL,NULL,NULL,NULL)",
                       (request_id, injector["user"], injector["id"], kind, expires, request_text, signature))
            self.audit(db, "requested", request_id, injector["id"])
        return {"state": "pending"}

    def poll(self, token, request_id):
        with self.tx() as db:
            injector = self.session(db, token, "injector")
            row = db.execute("SELECT * FROM requests WHERE id=? AND injector=?", (request_id, injector["id"])).fetchone()
            if not row:
                raise GuardError("request_unavailable")
            out = {"state": self.live(db, row)}
            if out["state"] == "approved":
                out.update(approver=row["approver"], signature=row["approval"])
                if row["kind"] == "use":
                    # One delivery only. The box leaves the relay and is not kept.
                    out["sealed"] = json.loads(row["sealed"])
                    db.execute("UPDATE requests SET state='delivered',sealed=NULL WHERE id=?", (request_id,))
                    self.audit(db, "delivered", request_id, injector["id"])
            elif out["state"] == "denied":
                # Signed by the approver, so the injector can show a reason the relay cannot invent.
                out.update(approver=row["approver"], signature=row["approval"], reason=row["reason"] or "")
            return out

    def rules(self, token):
        """Protection rules of this user's approvers, each still carrying its approver's signature."""
        with self.tx() as db:
            injector = self.session(db, token, "injector")
            rows = db.execute("SELECT r.* FROM rules r JOIN devices d ON d.id=r.approver WHERE r.user=? AND d.active=1", (injector["user"],)).fetchall()
            return {"rules": [{"approver": r["approver"], "rules_text": r["rules_text"], "signature": r["signature"]} for r in rows]}

    def publish_rules(self, token, rules_text, signature):
        if not 0 < len(rules_text) <= protocol.MAX_RULES_TEXT:
            raise GuardError("request_invalid")
        with self.tx() as db:
            approver = self.session(db, token, "approver")
            try:
                verify(json.loads(approver["jwk"]), protocol.rules_message(rules_text), signature)
            except Exception:
                raise GuardError("signature_invalid") from None
            db.execute("INSERT OR REPLACE INTO rules VALUES(?,?,?,?)", (approver["id"], approver["user"], rules_text, signature))
            self.audit(db, "rules_published", device=approver["id"])
        return {"state": "published"}

    def report(self, token, request_id, event):
        if event not in REPORTS:
            raise GuardError("request_invalid")
        with self.tx() as db:
            injector = self.session(db, token, "injector")
            done = db.execute("UPDATE requests SET state=? WHERE id=? AND injector=? AND state IN ('delivered','executing')", (event, request_id, injector["id"])).rowcount
            if not done:
                raise GuardError("request_unavailable")
            self.audit(db, event, request_id, injector["id"])
        return {"state": event}

    # Approver side.
    def pending(self, token):
        with self.tx() as db:
            approver = self.session(db, token, "approver")
            rows = db.execute("SELECT * FROM requests WHERE user=? AND state='pending' ORDER BY rowid", (approver["user"],)).fetchall()
            injectors = [r["id"] for r in db.execute("SELECT id FROM devices WHERE user=? AND kind='injector' AND active=1", (approver["user"],))]
            return {"injectors": injectors, "requests": [
                {"request_text": r["request_text"], "signature": r["signature"]} for r in rows
                if self.live(db, r) == "pending" and approver["id"] not in json.loads(r["declines"] or "{}")]}

    def decide(self, token, request_id, decision, signature, sealed=None, reason=""):
        # A reason marks an automatic rejection: this approver cannot approve the request at all.
        if decision not in {"approve", "deny"} or (reason and (decision != "deny" or reason not in protocol.REASONS)):
            raise GuardError("decision_invalid")
        with self.tx() as db:
            approver = self.session(db, token, "approver")
            row = db.execute("SELECT * FROM requests WHERE id=? AND user=?", (request_id, approver["user"])).fetchone()
            if not row or self.live(db, row) != "pending":
                raise GuardError("request_not_pending")
            self.device(db, row["injector"], "injector")
            # Only an approved use carries a credential, and it must arrive sealed.
            needs_box = decision == "approve" and row["kind"] == "use"
            if needs_box != (sealed is not None) or (needs_box and not valid_box(sealed)):
                raise GuardError("decision_invalid")
            try:
                verify(json.loads(approver["jwk"]), protocol.decision_message(decision, approver["id"], row["request_text"], reason), signature)
            except Exception:
                raise GuardError("signature_invalid") from None
            if reason:
                # Another approver of the same user may hold the credential; final only when none can.
                declines = json.loads(row["declines"] or "{}")
                declines[approver["id"]] = reason
                db.execute("UPDATE requests SET declines=? WHERE id=?", (canonical(declines), request_id))
                others = [r["id"] for r in db.execute("SELECT id FROM devices WHERE user=? AND kind='approver' AND active=1", (row["user"],)) if r["id"] not in declines]
                if others:
                    self.audit(db, "declined", request_id, approver["id"])
                    return {"state": "pending"}
            state = "approved" if decision == "approve" else "denied"
            db.execute("UPDATE requests SET state=?,approver=?,approval=?,sealed=?,reason=? WHERE id=?",
                       (state, approver["id"], signature, canonical(sealed) if sealed else None, reason or None, request_id))
            self.audit(db, state, request_id, approver["id"])
        return {"state": state}

    ROUTES = {
        "/device/challenge": ("challenge", {"device"}, False),
        "/device/login": ("login", {"device", "challenge", "signature"}, False),
        "/injector/submit": ("submit", {"request_text", "signature"}, True),
        "/injector/poll": ("poll", {"request_id"}, True),
        "/injector/report": ("report", {"request_id", "event"}, True),
        "/injector/rules": ("rules", set(), True),
        "/approver/rules": ("publish_rules", {"rules_text", "signature"}, True),
        "/approver/pending": ("pending", set(), True),
        "/approver/decision": ("decide", {"request_id", "decision", "signature"}, True),
    }

    def dispatch(self, route, body, token=None):
        """The whole network surface. No registration, export or admin route exists."""
        if route not in self.ROUTES or not isinstance(body, dict):
            raise GuardError("route_unavailable")
        name, fields, auth = self.ROUTES[route]
        optional = {"sealed", "reason"} if name == "decide" else set()
        if not fields <= set(body) or set(body) - fields - optional:
            raise GuardError("route_unavailable")
        if any(not isinstance(v, str) for k, v in body.items() if k != "sealed"):
            raise GuardError("request_invalid")
        return getattr(self, name)(token, **body) if auth else getattr(self, name)(**body)
