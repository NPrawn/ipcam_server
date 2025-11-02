import os, json, secrets, time
from typing import Optional, Dict
import redis
from dotenv import load_dotenv

load_dotenv()

REDIS_URL     = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REG_TOKEN_TTL = int(os.getenv("REG_TOKEN_TTL", "300"))
SSID_TTL      = int(os.getenv("SSID_TTL", "86400"))

r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

def _now() -> int:
    return int(time.time())

# 키 설계:
# reg:token:<token>         -> {"user_id","device_alias","ssid","ssid_psk","ts"} (1회용)
# device:pubkey:<device_id> -> "<PEM>"
# device:bind:<device_id>   -> {"user_id","alias","pubkey_fp","created_at","vpn_ip"}
# device:state:<device_id>  -> {"stage","updated_at","stream_req_id","vpn_ip"}
# device:ssid:<device_id>   -> "<ssid>" (TTL)
# device:serial:<device_id> -> "<mtls_serial>"
# device:byserial:<serial>  -> "<device_id>"

def issue_registration_token(user_id: str, device_alias: str, ssid: str, ssid_psk: str) -> str:
    token = secrets.token_urlsafe(24)
    payload = {"user_id": user_id, "device_alias": device_alias, "ssid": ssid, "ssid_psk": ssid_psk, "ts": _now()}
    r.set(f"reg:token:{token}", json.dumps(payload), ex=REG_TOKEN_TTL)
    return token

def consume_registration_token(token: str) -> Optional[Dict]:
    key = f"reg:token:{token}"
    pipe = r.pipeline()
    pipe.get(key); pipe.delete(key)
    val, _ = pipe.execute()
    return json.loads(val) if val else None

def save_pubkey(device_id: str, pem: str):
    r.set(f"device:pubkey:{device_id}", pem)

def get_pubkey(device_id: str) -> Optional[str]:
    return r.get(f"device:pubkey:{device_id}")

def set_state(device_id: str, state: Dict):
    state["updated_at"] = _now()
    r.set(f"device:state:{device_id}", json.dumps(state))

def get_state(device_id: str) -> Optional[Dict]:
    v = r.get(f"device:state:{device_id}")
    return json.loads(v) if v else None

def set_binding(device_id: str, user_id: str, alias: str, pubkey_fp: str, vpn_ip: str | None):
    payload = {"user_id": user_id, "alias": alias, "pubkey_fp": pubkey_fp, "created_at": _now(), "vpn_ip": vpn_ip}
    r.set(f"device:bind:{device_id}", json.dumps(payload))

def get_binding(device_id: str) -> Optional[Dict]:
    v = r.get(f"device:bind:{device_id}")
    return json.loads(v) if v else None

def save_ssid(device_id: str, ssid: str):
    r.set(f"device:ssid:{device_id}", ssid, ex=SSID_TTL)

def get_ssid(device_id: str) -> Optional[str]:
    return r.get(f"device:ssid:{device_id}")

def bind_mtls_serial(device_id: str, serial: str):
    pipe = r.pipeline()
    pipe.set(f"device:serial:{device_id}", serial)
    pipe.set(f"device:byserial:{serial}", device_id)
    pipe.execute()

def get_device_by_serial(serial: str) -> Optional[str]:
    return r.get(f"device:byserial:{serial}")

def revoke_device(device_id: str):
    serial = r.get(f"device:serial:{device_id}")
    pipe = r.pipeline()
    if serial:
        pipe.delete(f"device:byserial:{serial}")
    for k in [
        f"device:serial:{device_id}",
        f"device:bind:{device_id}",
        f"device:state:{device_id}",
        f"device:ssid:{device_id}",
    ]:
        pipe.delete(k)
    pipe.execute()
