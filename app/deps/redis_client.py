# app/deps/redis_client.py
import os, json, secrets, time
from typing import Optional
import redis
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REG_TOKEN_TTL = int(os.getenv("REG_TOKEN_TTL", "600"))     # 등록 토큰 유효기간(초)
SSID_TTL      = int(os.getenv("SSID_TTL", "86400"))        # SSID 캐시 유효기간(초)

r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

def issue_registration_token(device_id: str, ssid: str) -> str:
    token = secrets.token_urlsafe(24)
    payload = {"device_id": device_id, "ssid": ssid, "ts": int(time.time())}
    r.set(f"reg:token:{token}", json.dumps(payload), ex=REG_TOKEN_TTL)
    return token

def consume_registration_token(token: str) -> Optional[dict]:
    key = f"reg:token:{token}"
    pipe = r.pipeline()
    pipe.get(key); pipe.delete(key)
    val, _ = pipe.execute()
    return json.loads(val) if val else None

def save_ssid(device_id: str, ssid: str):
    r.set(f"device:{device_id}:ssid", ssid, ex=SSID_TTL)

def get_ssid(device_id: str) -> Optional[str]:
    return r.get(f"device:{device_id}:ssid")
