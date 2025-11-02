import base64, hashlib, os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

ALLOW_FIRST_TIME_PUBKEY = os.getenv("ALLOW_FIRST_TIME_PUBKEY", "true").lower() == "true"

def load_public_key_pem(pem: str):
    return serialization.load_pem_public_key(pem.encode("utf-8"))

def verify_signature(public_pem: str, message: bytes, b64sig: str) -> bool:
    pub = load_public_key_pem(public_pem)
    sig = base64.b64decode(b64sig)
    try:
        pub.verify(sig, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

def fingerprint_public_pem(public_pem: str) -> str:
    return hashlib.sha256(public_pem.encode("utf-8")).hexdigest()[:64]
