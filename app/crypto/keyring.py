# app/crypto/keyring.py
import os
from nacl.public import PublicKey, PrivateKey

def load_keys_from_env():
    # 환경변수로 넣어두세요. (테스트/실제 키 각각 세트)
    pub_hex  = os.environ["REG_KEY_PUBLIC_HEX"]      # 예: 8455da4d...
    priv_hex = os.environ["REG_KEY_PRIVATE_HEX"]     # 예: 9c6c8a3d...

    # hex → raw bytes → Key 객체
    pub  = PublicKey(bytes.fromhex(pub_hex))
    priv = PrivateKey(bytes.fromhex(priv_hex))
    return pub, priv
