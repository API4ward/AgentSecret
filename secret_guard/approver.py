"""Approver: where credentials are stored, and the only party that can approve.

This is the reference approver (terminal or headless). The browser approver in
web/ speaks the same protocol. A credential leaves this device only when the
user approves one frozen request, and then only sealed to the injector that
was paired here in person; the relay forwards a box it cannot open.
"""
from contextlib import contextmanager
import json
import os
import secrets
import sqlite3
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import adapter, protocol
from .broker import GuardError
from .crypto import canonical, verify
from .injector import ALIAS, load_config
from .link import DeviceLink, http_call
from .seal import MAX_PLAINTEXT, clean_jwk, jwk, load_or_create_key, seal, sign

SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets(alias TEXT PRIMARY KEY, version INTEGER, ciphertext BLOB, policy TEXT, active INTEGER);
CREATE TABLE IF NOT EXISTS injectors(id TEXT PRIMARY KEY, jwk TEXT, enc_jwk TEXT, active INTEGER);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL, event TEXT, request_id TEXT);
CREATE TABLE IF NOT EXISTS rules(kind TEXT, value TEXT, PRIMARY KEY(kind, value));
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value INTEGER);
"""


class Approver:
    def __init__(self, state, call=None, clock=time.time, user=None, relay=None):
        self.state, self.config = load_config(state, "approver", user, relay)
        self.user, self.device = self.config["user"], self.config["device"]
        self.signing = load_or_create_key(self.state / "device.key")
        keyfile = self.state / "vault.key"
        if not keyfile.exists():
            fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(AESGCM.generate_key(bit_length=256))
        self.vault = AESGCM(keyfile.read_bytes())
        self.link = DeviceLink(call or http_call(self.config["relay"]), self.device, self.signing)
        self.db = self.state / "approver.sqlite3"
        self.clock = clock
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

    def audit(self, db, event, request_id=""):
        db.execute("INSERT INTO audit(at,event,request_id) VALUES(?,?,?)", (self.clock(), event, request_id))

    def pairing(self):
        return {"kind": "approver", "device": self.device, "user": self.user, "jwk": jwk(self.signing)}

    def pair_injector(self, device, user, public, enc_public):
        if user != self.user or not isinstance(device, str) or not device:
            raise GuardError("pairing_invalid")
        try:
            public, enc_public = clean_jwk(public), clean_jwk(enc_public)
        except Exception:
            raise GuardError("pairing_invalid") from None
        with self.tx() as db:
            if db.execute("SELECT 1 FROM injectors WHERE id=?", (device,)).fetchone():
                raise GuardError("device_exists")
            db.execute("INSERT INTO injectors VALUES(?,?,?,1)", (device, canonical(public), canonical(enc_public)))
            self.audit(db, "injector_paired")

    def add_secret(self, alias, value, repos):
        # The credential is the user's to manage: stored exactly as given, never inspected.
        # The alias is what tells credentials apart, so only the alias has a format.
        if not isinstance(alias, str) or not ALIAS.fullmatch(alias):
            raise GuardError("alias_invalid")
        if not isinstance(value, str) or not value:
            raise GuardError("secret_empty")
        if len(value.encode()) > MAX_PLAINTEXT:
            raise GuardError("secret_too_large")
        try:
            normalized = sorted({adapter.normalize(repo, 1)["repo"] for repo in repos})
        except Exception:
            raise GuardError("repo_invalid") from None
        if not normalized:
            raise GuardError("empty_policy")
        with self.tx() as db:
            row = db.execute("SELECT version FROM secrets WHERE alias=?", (alias,)).fetchone()
            version = row[0] + 1 if row else 1
            nonce = secrets.token_bytes(12)
            ciphertext = nonce + self.vault.encrypt(nonce, value.encode(), canonical([alias, version]).encode())
            db.execute("INSERT OR REPLACE INTO secrets VALUES(?,?,?,?,1)", (alias, version, ciphertext, canonical({"repos": normalized})))
            self.audit(db, "secret_updated")

    # Protection rules: what the agent's own tools may not read without an approval from here.
    def list_rules(self):
        with self.tx() as db:
            return [{"kind": r["kind"], "value": r["value"]} for r in db.execute("SELECT * FROM rules ORDER BY kind, value")]

    def set_rule(self, kind, value, present=True):
        rule = {"kind": kind, "value": value.strip() if isinstance(value, str) else value}
        if not protocol.valid_rule(rule):
            raise GuardError("rule_invalid")
        with self.tx() as db:
            if present:
                db.execute("INSERT OR IGNORE INTO rules VALUES(?,?)", (rule["kind"], rule["value"]))
            elif not db.execute("DELETE FROM rules WHERE kind=? AND value=?", (rule["kind"], rule["value"])).rowcount:
                raise GuardError("rule_unknown")
            self.audit(db, "rule_added" if present else "rule_removed")
        return rule

    def publish_rules(self):
        """Sign the whole rule set and hand it to the relay for this user's injectors."""
        with self.tx() as db:
            rules = [{"kind": r["kind"], "value": r["value"]} for r in db.execute("SELECT * FROM rules ORDER BY kind, value")]
            last = db.execute("SELECT value FROM meta WHERE key='rules_version'").fetchone()
            version = max(int(self.clock() * 1000), (last[0] if last else 0) + 1)
            db.execute("INSERT OR REPLACE INTO meta VALUES('rules_version',?)", (version,))
        text = canonical({"approver": self.device, "version": version, "rules": rules})
        return self.link.request("/approver/rules", {"rules_text": text, "signature": sign(self.signing, protocol.rules_message(text))})

    def revoke(self, kind, identity):
        with self.tx() as db:
            if kind == "secret":
                db.execute("UPDATE secrets SET active=0 WHERE alias=?", (identity,))
            elif kind == "injector":
                db.execute("UPDATE injectors SET active=0 WHERE id=?", (identity,))
            else:
                raise GuardError("revoke_invalid")
            self.audit(db, "revoked_" + kind)

    def activity(self):
        with self.tx() as db:
            return [dict(row) for row in db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 100")]

    def check(self, db, entry):
        """Rules come before the prompt: returns (payload, injector row, problem code or None)."""
        text = entry["request_text"]
        payload = json.loads(text)
        injector = db.execute("SELECT * FROM injectors WHERE id=? AND active=1", (payload.get("injector"),)).fetchone()
        if not injector:
            return payload, None, "injector_not_paired"
        try:
            verify(json.loads(injector["jwk"]), protocol.request_message(text), entry["signature"])
        except Exception:
            return payload, None, "signature_invalid"
        if canonical(payload) != text or payload.get("domain") != protocol.REQUEST_DOMAIN or payload.get("principal") != self.user:
            return payload, injector, "request_invalid"
        if payload["expires_at"] <= self.clock():
            return payload, injector, "expired"
        if payload.get("kind") == "access":
            # A read of protected content carries no credential; the rule it names must be one of ours.
            d = payload.get("details")
            try:
                if d != protocol.access_details(d["tool"], d["rule"], d["summary"], d["call"]) or not protocol.valid_rule(d["rule"]) \
                        or not all(isinstance(d[k], str) for k in ("tool", "summary", "call")):
                    return payload, injector, "request_invalid"
            except Exception:
                return payload, injector, "request_invalid"
            known = db.execute("SELECT 1 FROM rules WHERE kind=? AND value=?", (d["rule"]["kind"], d["rule"]["value"])).fetchone()
            return payload, injector, None if known else "rule_unknown"
        secret = db.execute("SELECT * FROM secrets WHERE alias=? AND active=1", (payload.get("secret_id"),)).fetchone()
        if not secret:
            return payload, injector, "secret_unavailable"
        if payload["kind"] == "use":
            try:
                # Rebuild the request from its arguments with this device's own adapter copy.
                if payload["details"] != adapter.freeze(payload["details"]["args"]):
                    return payload, injector, "request_changed"
            except Exception:
                return payload, injector, "request_changed"
            if payload["details"]["args"]["repo"] not in json.loads(secret["policy"])["repos"]:
                return payload, injector, "policy_denied"
        elif payload["kind"] != "reference" or payload["details"].get("type") not in protocol.REF_TYPES \
                or payload["details"] != protocol.reference_details(payload["details"]["type"]):
            return payload, injector, "request_invalid"
        return payload, injector, None

    def pending(self, reject=True):
        """Requests waiting for this user. One this device can never approve is rejected at
        once with its reason, so the caller is told why instead of waiting for a person."""
        entries = self.link.request("/approver/pending", {})["requests"]
        out = []
        with self.tx() as db:
            for entry in entries:
                try:
                    payload, _, problem = self.check(db, entry)
                except Exception:
                    continue  # Not even parseable: never shown, never signed.
                out.append({"request_id": payload["request_id"], "payload": payload, "problem": problem, "entry": entry, "rejected": False})
        for item in out:
            if reject and item["problem"] in protocol.REASONS:
                try:
                    self.decide(item, "deny")
                    item["rejected"] = True
                except GuardError:
                    pass
        return out

    def decide(self, item, decision):
        if decision not in {"approve", "deny"}:
            raise GuardError("decision_invalid")
        text = item["entry"]["request_text"]
        body = {"request_id": item["request_id"], "decision": decision}
        with self.tx() as db:
            payload, injector, problem = self.check(db, item["entry"])
            if decision == "approve":
                if problem:
                    raise GuardError(problem)
                if payload["kind"] == "use":
                    row = db.execute("SELECT * FROM secrets WHERE alias=? AND active=1", (payload["secret_id"],)).fetchone()
                    blob = row["ciphertext"]
                    value = self.vault.decrypt(blob[:12], blob[12:], canonical([row["alias"], row["version"]]).encode())
                    # Sealed to the key recorded at pairing, never to a key the relay supplies.
                    body["sealed"] = seal(json.loads(injector["enc_jwk"]), value, protocol.seal_aad(text))
                    value = None
            reason = problem if decision == "deny" and problem in protocol.REASONS else ""
            if reason:
                body["reason"] = reason
            body["signature"] = sign(self.signing, protocol.decision_message(decision, self.device, text, reason))
            self.audit(db, "approved" if decision == "approve" else "denied", item["request_id"])
        return self.link.request("/approver/decision", body)
