# app/routers/registration.py
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from app.deps.redis_client import (
    issue_registration_token, consume_registration_token,
    save_ssid, get_ssid
)

router = APIRouter(prefix="/register", tags=["Register"])

class StartReq(BaseModel):
    device_id: str
    ssid: str

@router.post("/start")
def start_registration(body: StartReq):
    """
    (앱/웹에서 호출) 등록 토큰 발급. mTLS 불필요.
    """
    token = issue_registration_token(body.device_id, body.ssid)
    return {"reg_token": token, "expires_in": 600}

class ConfirmReq(BaseModel):
    reg_token: str

@router.post("/confirm")
def confirm_registration(req: Request, body: ConfirmReq):
    """
    (디바이스에서 호출) mTLS 필수. 토큰을 소비하며, SSID를 캐시에 저장.
    """
    if req.headers.get("x-ssl-client-verify") != "SUCCESS":
        raise HTTPException(403, "mTLS required")
    data = consume_registration_token(body.reg_token)
    if not data:
        raise HTTPException(400, "invalid_or_expired_token")
    save_ssid(data["device_id"], data["ssid"])
    return {"status": "ok", "device_id": data["device_id"], "ssid": data["ssid"]}

@router.get("/ssid/{device_id}")
def read_ssid(device_id: str):
    """
    최근 등록된 SSID 조회(캐시). 필요시 권한 체크를 추가하세요.
    """
    val = get_ssid(device_id)
    if not val:
        raise HTTPException(404, "ssid_not_found")
    return {"device_id": device_id, "ssid": val}
