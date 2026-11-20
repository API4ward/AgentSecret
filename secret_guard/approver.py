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

import fnmatch

from . import adapter, matcher, protocol
from .broker import GuardError
from .crypto import canonical, verify
from .injector import ALIAS, load_config
from .link import DeviceLink, http_call
from .seal import MAX_PLAINTEXT, clean_jwk, jwk, load_or_create_key, seal, sign

SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets(alias TEXT PRIMARY KEY, version INTEGER, ciphertext BLOB, policy TEXT, active INTEGER);
CREATE TABLE IF NOT EXISTS injectors(id TEXT PRIMARY KEY, jwk TEXT, enc_jwk TEXT, active INTEGER);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL, event TEXT, request_id TEXT);
CREATE TABLE IF NOT EXISTS copies(alias TEXT, label TEXT, ciphertext BLOB, PRIMARY KEY(alias, label));
CREATE TABLE IF NOT EXISTS grants(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, secrets TEXT, project TEXT, remaining INTEGER, expires REAL, choices BLOB);
CREATE TABLE IF NOT EXISTS auto_rules(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, secret TEXT, tool TEXT, target TEXT);
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

    def add_secret(self, alias, value, repos=(), label="default"):
        """Store a credential. Further copies under the same alias (say, several API keys of one
        service) take a label; the approval panel can hand out any of them."""
        if label != "default":
            return self.add_copy(alias, label, value)
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
        with self.tx() as db:
            row = db.execute("SELECT version FROM secrets WHERE alias=?", (alias,)).fetchone()
            version = row[0] + 1 if row else 1
            nonce = secrets.token_bytes(12)
            ciphertext = nonce + self.vault.encrypt(nonce, value.encode(), canonical([alias, version]).encode())
            db.execute("INSERT OR REPLACE INTO secrets VALUES(?,?,?,?,1)", (alias, version, ciphertext, canonical({"repos": normalized})))
            self.audit(db, "secret_updated")

    def add_copy(self, alias, label, value):
        if not isinstance(label, str) or not ALIAS.fullmatch(label):
            raise GuardError("alias_invalid")
        if not isinstance(value, str) or not value:
            raise GuardError("secret_empty")
        if len(value.encode()) > MAX_PLAINTEXT:
            raise GuardError("secret_too_large")
        with self.tx() as db:
            if not db.execute("SELECT 1 FROM secrets WHERE alias=? AND active=1", (alias,)).fetchone():
                raise GuardError("secret_unavailable")
            nonce = secrets.token_bytes(12)
            blob = nonce + self.vault.encrypt(nonce, value.encode(), canonical([alias, "copy", label]).encode())
            db.execute("INSERT OR REPLACE INTO copies VALUES(?,?,?)", (alias, label, blob))
            self.audit(db, "copy_updated")

    def values(self, db, alias):
        """Every stored copy of one credential: {"default": ..., label: ...}. Plaintext; stays on this device."""
        row = db.execute("SELECT * FROM secrets WHERE alias=? AND active=1", (alias,)).fetchone()
        if not row:
            return {}
        blob = row["ciphertext"]
        out = {"default": self.vault.decrypt(blob[:12], blob[12:], canonical([row["alias"], row["version"]]).encode()).decode()}
        for copy in db.execute("SELECT * FROM copies WHERE alias=? ORDER BY label", (alias,)):
            blob = copy["ciphertext"]
            out[copy["label"]] = self.vault.decrypt(blob[:12], blob[12:], canonical([alias, "copy", copy["label"]]).encode()).decode()
        return out

    def labels(self, alias):
        with self.tx() as db:
            return list(self.values(db, alias))

    def publish_matchers(self):
        """Compile every stored credential into a matcher, sign the set, and hand it to the relay
        for this user's injectors. The plaintext stays here; see matcher.py for what a matcher gives away."""
        with self.tx() as db:
            base = matcher.new_base()
            compiled = [matcher.compile_one(row["alias"], value, base)
                        for row in db.execute("SELECT alias FROM secrets WHERE active=1 ORDER BY alias").fetchall()
                        for value in self.values(db, row["alias"]).values()]
            last = db.execute("SELECT value FROM meta WHERE key='rules_version'").fetchone()
            version = max(int(self.clock() * 1000), (last[0] if last else 0) + 1)
            db.execute("INSERT OR REPLACE INTO meta VALUES('rules_version',?)", (version,))
        text = canonical({"approver": self.device, "version": version, "base": str(base), "matchers": [m for m in compiled if m]})
        return self.link.request("/approver/rules", {"rules_text": text, "signature": sign(self.signing, protocol.rules_message(text))})

    # Approval modes. All of them are this device answering for the user; every answer is
    # still an individually signed decision, so the relay and the injector see nothing new.
    def approve_all(self, seconds):
        """Approve everything approvable for a while (0 turns it off)."""
        with self.tx() as db:
            db.execute("INSERT OR REPLACE INTO meta VALUES('approve_all_until',?)", (int(self.clock() + seconds) if seconds > 0 else 0,))
            self.audit(db, "approve_all_on" if seconds > 0 else "approve_all_off")

    def add_auto_rule(self, kind="*", secret="*", tool="*", target="*"):
        """Rule-based automatic approval: request kind, credential alias, tool and target, each a glob."""
        if kind not in ("*", "reference", "use", *protocol.HOOK_KINDS) or not all(isinstance(v, str) and 0 < len(v) <= 256 for v in (secret, tool, target)):
            raise GuardError("rule_invalid")
        with self.tx() as db:
            self.audit(db, "auto_rule_added")
            return db.execute("INSERT INTO auto_rules(kind,secret,tool,target) VALUES(?,?,?,?)", (kind, secret, tool, target)).lastrowid

    def remove_auto_rule(self, identity):
        with self.tx() as db:
            if not db.execute("DELETE FROM auto_rules WHERE id=?", (identity,)).rowcount:
                raise GuardError("rule_invalid")

    def auto_rules(self):
        with self.tx() as db:
            return [dict(row) for row in db.execute("SELECT * FROM auto_rules ORDER BY id")]

    @staticmethod
    def facets(payload):
        """What a mode or rule looks at: kind, credentials, tool, target."""
        d = payload["details"]
        if payload["kind"] in protocol.HOOK_KINDS:
            return payload["kind"], d["secrets"], d["tool"], d["target"]
        return payload["kind"], [payload["secret_id"]], "github" if payload["kind"] == "use" else "", d.get("args", {}).get("repo", "")

    def automatic(self, db, payload):
        """Whether a mode answers this request without the user: (why, choices) or None."""
        kind, names, tool, target = self.facets(payload)
        until = db.execute("SELECT value FROM meta WHERE key='approve_all_until'").fetchone()
        if until and until[0] > self.clock():
            return "all", None
        for g in db.execute("SELECT * FROM grants WHERE kind=? AND secrets=? AND project=?", (kind, canonical(names), payload["project"])).fetchall():
            if (g["expires"] is None or g["expires"] > self.clock()) and (g["remaining"] is None or g["remaining"] > 0):
                if g["remaining"] is not None:
                    db.execute("UPDATE grants SET remaining=remaining-1 WHERE id=?", (g["id"],))
                blob = g["choices"]
                return "grant", json.loads(self.vault.decrypt(blob[:12], blob[12:], b"grant")) if blob else None
        for r in db.execute("SELECT * FROM auto_rules").fetchall():
            if r["kind"] in ("*", kind) and all(fnmatch.fnmatchcase(n, r["secret"]) for n in names) \
                    and fnmatch.fnmatchcase(tool, r["tool"]) and fnmatch.fnmatchcase(target, r["target"]):
                return "rule", None
        return None

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
        if payload.get("kind") in protocol.HOOK_KINDS:
            # The hook's requests name credentials by alias; every one must be stored here.
            d = payload.get("details")
            try:
                if d != protocol.hook_details(payload["kind"], d["tool"], d["target"], d["summary"], d["call"], d["secrets"]) \
                        or not all(isinstance(d[k], str) for k in ("tool", "target", "summary", "call")) \
                        or not d["secrets"] or not all(isinstance(a, str) for a in d["secrets"]):
                    return payload, injector, "request_invalid"
            except Exception:
                return payload, injector, "request_invalid"
            known = all(db.execute("SELECT 1 FROM secrets WHERE alias=? AND active=1", (a,)).fetchone() for a in d["secrets"])
            return payload, injector, None if known else "secret_unavailable"
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

    def pending(self, reject=True, automate=True):
        """Requests waiting for this user. One this device can never approve is rejected at once
        with its reason; one a mode covers (approve-all, a standing grant, an automatic rule) is
        approved at once; the rest are for the user."""
        entries = self.link.request("/approver/pending", {})["requests"]
        out = []
        with self.tx() as db:
            for entry in entries:
                try:
                    payload, _, problem = self.check(db, entry)
                except Exception:
                    continue  # Not even parseable: never shown, never signed.
                out.append({"request_id": payload["request_id"], "payload": payload, "problem": problem, "entry": entry, "rejected": False, "auto": None})
        for item in out:
            try:
                if reject and item["problem"] in protocol.REASONS:
                    self.decide(item, "deny")
                    item["rejected"] = True
                elif automate and not item["problem"]:
                    with self.tx() as db:
                        auto = self.automatic(db, item["payload"])
                    if auto:
                        self.decide(item, "approve", choices=auto[1])
                        item["auto"] = auto[0]
            except GuardError:
                pass
        return out

    def resolve(self, db, alias, choice):
        """The value an approval returns for one credential: the stored one, another copy with the
        same alias, a mock of the same shape, or whatever the user typed."""
        stored = self.values(db, alias)
        if choice in (None, "default"):
            return stored["default"]
        if choice == "mock":
            return matcher.mock(stored["default"])
        if isinstance(choice, str) and choice.startswith("copy:"):
            if choice[5:] not in stored:
                raise GuardError("copy_unknown")
            return stored[choice[5:]]
        if isinstance(choice, str) and choice.startswith("manual:") and len(choice) > 7:
            return choice[7:]
        raise GuardError("choice_invalid")

    def decide(self, item, decision, choices=None, grant=None):
        """choices: {alias: "default" | "copy:<label>" | "mock" | "manual:<text>"} for what is returned.
        grant: {"times": n} or {"seconds": s} to answer the same kind of request again without asking."""
        if decision not in {"approve", "deny"}:
            raise GuardError("decision_invalid")
        text = item["entry"]["request_text"]
        body = {"request_id": item["request_id"], "decision": decision}
        with self.tx() as db:
            payload, injector, problem = self.check(db, item["entry"])
            if decision == "approve":
                if problem:
                    raise GuardError(problem)
                kind, names, _, _ = self.facets(payload)
                if kind in ("use", "fill"):
                    picked = {alias: self.resolve(db, alias, (choices or {}).get(alias)) for alias in names}
                    value = picked[names[0]].encode() if kind == "use" else canonical(picked).encode()
                    # Sealed to the key recorded at pairing, never to a key the relay supplies.
                    body["sealed"] = seal(json.loads(injector["enc_jwk"]), value, protocol.seal_aad(text))
                    value = picked = None
                if grant:
                    times, seconds = grant.get("times"), grant.get("seconds")
                    if (times is None) == (seconds is None) or (times is not None and not 1 <= times <= 1000) or (seconds is not None and not 0 < seconds <= 86400):
                        raise GuardError("decision_invalid")
                    nonce = secrets.token_bytes(12)
                    blob = nonce + self.vault.encrypt(nonce, canonical(choices).encode(), b"grant") if choices else None
                    db.execute("INSERT INTO grants(kind,secrets,project,remaining,expires,choices) VALUES(?,?,?,?,?,?)",
                               (kind, canonical(names), payload["project"], times - 1 if times else None, self.clock() + seconds if seconds else None, blob))
            reason = problem if decision == "deny" and problem in protocol.REASONS else ""
            if reason:
                body["reason"] = reason
            body["signature"] = sign(self.signing, protocol.decision_message(decision, self.device, text, reason))
            self.audit(db, "approved" if decision == "approve" else "denied", item["request_id"])
        return self.link.request("/approver/decision", body)
