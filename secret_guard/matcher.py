"""Compiled matchers: how the agent's machine recognises a credential without holding it.

The approver, which has the plaintext, turns each credential into a matcher:
its length, a 16-bit tag of a rolling hash, and a salted PBKDF2 digest. The
injector slides a window over text; the tag discards almost every position
cheaply and the digest confirms a real hit. Nothing here can be decoded back
into the credential. A matcher answers yes or no for a guess, so whoever can
read it can test guesses offline at the cost of one PBKDF2 each; the tag
narrows guesses by 16 bits. The strength of a credential is the user's choice.
"""
import base64
import hashlib
import hmac
import secrets

MOD = (1 << 61) - 1
ITERATIONS = 50_000
MAX_SCAN = 4 * 1024 * 1024


def _b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _roll(data, base):
    h = 0
    for byte in data:
        h = (h * base + byte) % MOD
    return h


def new_base():
    return secrets.randbelow(MOD - 257) + 257


def compile_one(alias, value, base):
    """One credential copy -> one matcher. `value` never leaves the caller."""
    data = value.encode()
    # How strong a credential is, is the user's decision: every value is compiled, whatever its length.
    if not data:
        return None
    salt = secrets.token_bytes(16)
    return {"alias": alias, "length": len(data), "tag": _roll(data, base) & 0xFFFF, "salt": _b64(salt),
            "digest": _b64(hashlib.pbkdf2_hmac("sha256", data, salt, ITERATIONS))}


def valid_set(value):
    try:
        return (isinstance(value["base"], str) and 256 < int(value["base"]) < MOD and isinstance(value["matchers"], list)
                and all(set(m) == {"alias", "length", "tag", "salt", "digest"} and isinstance(m["alias"], str)
                        and type(m["length"]) is int and m["length"] >= 1 and type(m["tag"]) is int
                        and isinstance(m["salt"], str) and isinstance(m["digest"], str) for m in value["matchers"]))
    except Exception:
        return False


def scan(data, sets):
    """Non-overlapping [start, end, alias] spans of `data` (bytes) that are a compiled credential."""
    if len(data) > MAX_SCAN:
        raise ValueError("content too large to scan")
    hits = []
    for compiled in sets:
        base = int(compiled["base"])
        by_length = {}
        for m in compiled["matchers"]:
            by_length.setdefault(m["length"], {}).setdefault(m["tag"], []).append(m)
        for length, tags in by_length.items():
            if length > len(data):
                continue
            top = pow(base, length - 1, MOD)
            h = _roll(data[:length], base)
            for start in range(len(data) - length + 1):
                if start:
                    h = ((h - data[start - 1] * top) * base + data[start + length - 1]) % MOD
                for m in tags.get(h & 0xFFFF, ()):
                    salt = base64.urlsafe_b64decode(m["salt"] + "=" * (-len(m["salt"]) % 4))
                    digest = _b64(hashlib.pbkdf2_hmac("sha256", data[start:start + length], salt, ITERATIONS))
                    if hmac.compare_digest(digest, m["digest"]):
                        hits.append([start, start + length, m["alias"]])
    out, end = [], 0
    for hit in sorted(hits, key=lambda h: (h[0], -h[1])):
        if hit[0] >= end:
            out.append(hit)
            end = hit[1]
    return out


def mock(value):
    """A stand-in of the same shape: same length, letters for letters, digits for digits. Not the credential."""
    def swap(c):
        if c.isdigit():
            return secrets.choice("0123456789")
        if c.isalpha() and c.isascii():
            pool = "abcdefghijklmnopqrstuvwxyz"
            return secrets.choice(pool.upper() if c.isupper() else pool)
        return c
    # Keep a short leading tag such as "sk-" so the stand-in still looks like its kind.
    cut = max(value.find("-", 0, 8), value.find("_", 0, 8)) + 1
    return value[:cut] + "".join(swap(c) for c in value[cut:])
