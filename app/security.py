"""Cryptography + capability tokens."""
import base64, hashlib, hmac, json, os, time
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _aes_key() -> bytes:
    raw = os.getenv("AES_KEY")
    if not raw:
        raise RuntimeError("AES_KEY is not set (see .env.example)")
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise RuntimeError("AES_KEY must decode to exactly 32 bytes (AES-256)")
    return key


def _secret() -> bytes:
    s = os.getenv("CAPABILITY_SECRET")
    if not s:
        raise RuntimeError("CAPABILITY_SECRET is not set (see .env.example)")
    return s.encode()


# ---------- AES-256-GCM (confidentiality + tamper detection) ----------
def encrypt(plaintext: str) -> str:
    nonce = os.urandom(12)                      # fresh nonce for every value
    ct = AESGCM(_aes_key()).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt(token: str) -> str:
    blob = base64.b64decode(token)
    return AESGCM(_aes_key()).decrypt(blob[:12], blob[12:], None).decode()


# ---------- Password storage (slow salted hash, not reversible) ----------
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"{salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split("$")
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                            n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# ---------- Dedup fingerprint (keyed hash, so it can't be brute-forced) ----------
def fingerprint(canonical: str) -> str:
    return hmac.new(_aes_key(), canonical.encode(), hashlib.sha256).hexdigest()


# ---------- Capability tokens (SQL-injection layer 2) ----------
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def issue_capability(username: str, scopes: list, ttl: int = 900) -> str:
    payload = {"sub": username, "scp": scopes, "exp": int(time.time()) + ttl}
    body = _b64(json.dumps(payload).encode())
    sig = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_capability(token: Optional[str], required_scope: str) -> Optional[dict]:
    """Returns claims if token is genuine, unexpired and grants the scope."""
    if not token or token.count(".") != 1:
        return None
    body, sig = token.split(".")
    expected = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except Exception:
        return None
    if claims.get("exp", 0) < time.time() or required_scope not in claims.get("scp", []):
        return None
    return claims
