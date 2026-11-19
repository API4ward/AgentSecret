"""Device keys and end-to-end sealing between approver and injector.

Sealing is ECIES over P-256: an ephemeral ECDH key, HKDF-SHA256 and AES-256-GCM.
Every step exists in WebCrypto, so a browser approver produces the same box.
The relay server only ever carries the box; it holds neither private key.
"""
import os
from pathlib import Path
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto import b64, public_key, unb64

INFO = b"secret-guard/seal/v1"
MAX_PLAINTEXT = 4096


def load_or_create_key(path):
    """A P-256 private key in a 0600 file. Created once; never overwritten."""
    path = Path(path)
    if not path.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def jwk(private):
    n = private.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}


def clean_jwk(value):
    """Keep only the public fields; reject anything that is not a P-256 public key."""
    public_key(value)
    return {"kty": "EC", "crv": "P-256", "x": value["x"], "y": value["y"]}


def sign(private, text):
    """WebCrypto-compatible signature: 64 bytes r || s, base64url."""
    r, s = decode_dss_signature(private.sign(text.encode(), ec.ECDSA(hashes.SHA256())))
    return b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _raw(public):
    return public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def _key(shared, ephemeral_raw, recipient_raw):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=ephemeral_raw + recipient_raw, info=INFO).derive(shared)


def seal(recipient_jwk, plaintext, aad):
    """Encrypt plaintext to the recipient's public key, bound to aad."""
    if not isinstance(plaintext, bytes) or not 0 < len(plaintext) <= MAX_PLAINTEXT:
        raise ValueError("invalid plaintext")
    recipient = public_key(recipient_jwk)
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    epk = _raw(ephemeral.public_key())
    key = _key(ephemeral.exchange(ec.ECDH(), recipient), epk, _raw(recipient))
    nonce = secrets.token_bytes(12)
    return {"epk": b64(epk), "nonce": b64(nonce), "ct": b64(AESGCM(key).encrypt(nonce, plaintext, aad))}


def unseal(private, box, aad):
    """Raises on any mismatch: wrong recipient, altered box, or a different aad."""
    if not isinstance(box, dict) or set(box) != {"epk", "nonce", "ct"}:
        raise ValueError("invalid box")
    epk, nonce = unb64(box["epk"]), unb64(box["nonce"])
    if len(epk) != 65 or len(nonce) != 12:
        raise ValueError("invalid box")
    ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epk)
    key = _key(private.exchange(ec.ECDH(), ephemeral), epk, _raw(private.public_key()))
    return AESGCM(key).decrypt(nonce, unb64(box["ct"]), aad)


def valid_box(box):
    """Shape check the relay can do without being able to open the box."""
    return (isinstance(box, dict) and set(box) == {"epk", "nonce", "ct"}
            and all(isinstance(v, str) and 0 < len(v) <= 8192 for v in box.values()))
