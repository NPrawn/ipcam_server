# app/utils/streaming_be_create.py
import os, time, requests

STREAMING_BASE = os.getenv("STREAMING_BASE", "https://stream.example.com")
STREAMING_BE_CREATE_PATH = "/tunnels/be_create_info"

# mTLS 쓰려면 이 3개 설정(없으면 일반 TLS)
STREAMING_CLIENT_CERT = os.getenv("STREAMING_CLIENT_CERT")  # "/etc/mtls/apiserver.crt"
STREAMING_CLIENT_KEY  = os.getenv("STREAMING_CLIENT_KEY")   # "/etc/mtls/apiserver.key"
STREAMING_CA          = os.getenv("STREAMING_CA")           # "/etc/mtls/ca.crt"

def call_be_create_info(*, device_id: str, device_pubkey_b64u: str, reg_jwt: str, owner_user_id: int, timeout=5):
    url = STREAMING_BASE.rstrip("/") + STREAMING_BE_CREATE_PATH
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {reg_jwt}",  # 스트리밍 서버가 우선적으로 헤더에서 토큰 추출
        "X-User-Id": str(owner_user_id),       # _require_user(x_user_id)
    }
    body = {
        "device_id": device_id,
        "device_pubkey_b64": device_pubkey_b64u,
        # body.registration_token 없이도 동작(Authorization 우선)하지만,
        # 이 라인을 남겨두면 폴백 경로도 커버됨.
        "registration_token": reg_jwt,
    }

    req = dict(url=url, headers=headers, json=body, timeout=timeout)
    if STREAMING_CLIENT_CERT and STREAMING_CLIENT_KEY and STREAMING_CA:
        req["cert"] = (STREAMING_CLIENT_CERT, STREAMING_CLIENT_KEY)
        req["verify"] = STREAMING_CA
    else:
        req["verify"] = True  # 최소 서버 인증

    last_err = None
    for attempt in range(3):
        try:
            resp = requests.post(**req)
            if 200 <= resp.status_code < 300:
                return True, resp.json()
            if resp.status_code in (429, 500, 502, 503, 504):
                time.sleep(1.2 * (attempt + 1))
                continue
            return False, f"streaming_resp_{resp.status_code}: {resp.text[:300]}"
        except Exception as e:
            last_err = e
            time.sleep(1.2 * (attempt + 1))
    return False, f"streaming_req_error: {last_err}"
