# app/utils/ed25519_keyfmt.py
import base64
from typing import Union
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat

def pubkey_to_raw32_b64(pub_key_text: Union[str, bytes]) -> str:
    """
    입력: PEM(str/bytes) 또는 base64(raw 32B)
    출력: base64url(무패딩) 문자열. 디코딩하면 32바이트여야 함.
    """
    if isinstance(pub_key_text, str):
        data = pub_key_text.encode()
    else:
        data = pub_key_text

    if data.startswith(b"-----BEGIN"):
        pub = load_pem_public_key(data)
        raw = pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    else:
        raw = base64.b64decode(data)

    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    b64 = base64.b64encode(raw).decode()
    return b64
