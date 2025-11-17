# app/utils/streaming_start.py
import os
import time
import requests
import secrets

STREAMING_BASE = os.getenv("STREAMING_BASE", "https://cowboyhomecam.duckdns.org")
STREAMING_START_PATH = "/streaming/start"  # 스트리밍 서버의 시작 API 경로
STREAMING_END_PATH = "/streaming/end"  # 스트리밍 서버의 종료 API 경로

# mTLS 쓰려면 이 3개 설정(없으면 일반 TLS)
STREAMING_CLIENT_CERT = os.getenv("STREAMING_CLIENT_CERT")  # "/etc/mtls/apiserver.crt"
STREAMING_CLIENT_KEY = os.getenv("STREAMING_CLIENT_KEY")   # "/etc/mtls/apiserver.key"
STREAMING_CA = os.getenv("STREAMING_CA")           # "/etc/mtls/ca.crt"


def call_streaming_start(*, device_id: str, sdp_offer: str, owner_user_id: int, timeout=10):
    """
    스트리밍 서버에 스트리밍 시작 요청을 보냅니다 (mTLS 사용)
    
    Args:
        device_id: 기기 ID
        sdp_offer: 수정된 SDP offer
        owner_user_id: 소유자 사용자 ID
        timeout: 요청 타임아웃 (초)
    
    Returns:
        (success: bool, result: dict or error_message: str)
    """
    url = STREAMING_BASE.rstrip("/") + STREAMING_START_PATH
    headers = {
        "Content-Type": "application/json",
    }
    body = {
        "user_id": owner_user_id,
        "sdp_offer": sdp_offer,
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


def call_streaming_end(*, device_id: str, session_name: str, owner_user_id: int, timeout=10):
    """
    스트리밍 서버에 스트리밍 종료 요청을 보냅니다 (mTLS 사용)
    
    Args:
        device_id: 기기 ID
        session_name: 세션 이름 (mediaMTX 측 스트림 이름)
        owner_user_id: 소유자 사용자 ID
        timeout: 요청 타임아웃 (초)
    
    Returns:
        (success: bool, result: dict or error_message: str)
    """
    url = STREAMING_BASE.rstrip("/") + STREAMING_END_PATH + f"/{device_id}"
    headers = {
        "Content-Type": "application/json",
    }
    body = {
        "device_id": device_id,
        "session_name": session_name,
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
            resp = requests.get(**req)
            if 200 <= resp.status_code < 300:
                return True, resp.json()
            if resp.status_code == 404:
                return False, "device_or_session_not_found"
            if resp.status_code in (429, 500, 502, 503, 504):
                time.sleep(1.2 * (attempt + 1))
                continue
            return False, f"streaming_resp_{resp.status_code}: {resp.text[:300]}"
        except Exception as e:
            last_err = e
            time.sleep(1.2 * (attempt + 1))
    return False, f"streaming_req_error: {last_err}"

