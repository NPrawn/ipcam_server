# app/crypto/box.py
from base64 import b64encode, b64decode
from nacl.public import SealedBox

def encrypt_for_server(pub_key, plaintext: bytes) -> str:
    """
    기기 측에서 사용할 함수 개념(서버 공개키만 필요).
    서버 공개키로 암호화 → base64 문자열로 반환해 DB에 저장하기 쉬움.
    """
    sealed = SealedBox(pub_key)
    ct = sealed.encrypt(plaintext)      # random nonce 내부적으로 처리
    return b64encode(ct).decode()

def decrypt_on_server(priv_key, b64_ciphertext: str) -> bytes:
    """
    서버에서 복호화(서버 개인키 필요).
    """
    sealed = SealedBox(priv_key)
    return sealed.decrypt(b64decode(b64_ciphertext))
