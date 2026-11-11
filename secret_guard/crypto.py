import base64
import hashlib
import json
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def opaque(prefix):
    return prefix + secrets.token_urlsafe(32)


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def public_key(jwk):
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" in jwk:
        raise ValueError("invalid public key")
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(unb64(jwk["x"]), "big"),
        int.from_bytes(unb64(jwk["y"]), "big"), ec.SECP256R1()
    ).public_key()


def verify(jwk, message, signature):
    raw = unb64(signature)
    if len(raw) != 64:
        raise ValueError("invalid signature")
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    public_key(jwk).verify(der, message.encode(), ec.ECDSA(hashes.SHA256()))
