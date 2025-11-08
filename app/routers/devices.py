# app/routers/devices.py
import base64
import io
import json
import qrcode
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Query, Response, Header
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database import SessionLocal
from app.models import RegistrationToken, Device
from app.security import get_current_user_id
from app.schemas import RegistrationTokenOut, DeviceRegisterIn, DeviceOut
from app.crypto.keyring import load_keys_from_env
from app.crypto.box import encrypt_for_server, decrypt_on_server

# Ed25519 서명 검즈
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

router = APIRouter(prefix="/devices", tags=["Devices"])

PUB_KEY, PRIV_KEY = load_keys_from_env()

class RegisterReq(BaseModel):
    device_id: str
    token_plain: str            # 기기에서 보내는 평문 토큰(HTTPS 전제) 혹은 이미 암호문을 보낼 수도 있음

# 등록 토큰 TTL(분)
REG_TOKEN_TTL_MIN = 5

# ─────────────────────────────────────────────────────────────
# DB 세션 DI
# ─────────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ─────────────────────────────────────────────────────────────
# 1) 등록 토큰 발급 (로그인 사용자만 / 5분 / 1회용)
# ─────────────────────────────────────────────────────────────
@router.post("/registration-token", response_model=RegistrationTokenOut)
def issue_registration_token(
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id),
):
    token = secrets.token_urlsafe(24)
    expires_at = datetime.utcnow() + timedelta(minutes=REG_TOKEN_TTL_MIN)
    db.add(RegistrationToken(token=token, user_id=user_id, expires_at=expires_at))
    db.commit()
    return RegistrationTokenOut(token=token, expires_in_seconds=REG_TOKEN_TTL_MIN * 60)

# ─────────────────────────────────────────────
# Ed25519 검증 유틸
#   - dev.pub_key 가 PEM이면 PEM 로드
#   - 아니면 base64 raw 32바이트로 간주
# ─────────────────────────────────────────────
def verify_ed25519_signature(pub_key_text: str, message: bytes, sig_b64: str) -> bool:
    try:
        sig = base64.b64decode(sig_b64)
        data = pub_key_text.encode() if isinstance(pub_key_text, str) else pub_key_text
        if data.startswith(b"-----BEGIN"):
            pub = load_pem_public_key(data)
        else:
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_key_text))
        pub.verify(sig, message)
        return True
    except Exception:
        return False

# # ─────────────────────────────────────────────────────────────
# # 2) 등록용 QR PNG (토큰 즉석 발급 + {token, api} → PNG)
# # ─────────────────────────────────────────────────────────────
# @router.get("/registration-qr.png")
# def get_registration_qr_png(
#     db: Session = Depends(get_db),
#     user_id: int = Depends(get_current_user_id),
#     api_base: str = Query(..., description="기기가 호출할 API 베이스 URL (예: https://<IP or Domain>)"),
# ):
#     token = secrets.token_urlsafe(24)
#     expires_at = datetime.utcnow() + timedelta(minutes=REG_TOKEN_TTL_MIN)
#     db.add(RegistrationToken(token=token, user_id=user_id, expires_at=expires_at))
#     db.commit()

#     payload = {"token": token, "api": api_base}
#     data = json.dumps(payload, ensure_ascii=False)

#     img = qrcode.make(data)
#     buf = io.BytesIO()
#     img.save(buf, format="PNG")
#     buf.seek(0)

#     headers = {"X-Registration-Token": token}
#     return StreamingResponse(buf, media_type="image/png", headers=headers)

# ─────────────────────────────────────────────────────────────
# 3) 기기 등록 (IPcam → 서버)  ※ 스트리밍 서버 연동 제거
#    - 입력: DeviceRegisterIn(token, device_id, model?, mac_addr?, serial_no?)
#    - 요구: mTLS(프록시 강제) → 헤더로 확인
#    - 동작:
#       a) 등록 토큰 유효성/1회성 확인(락)
#       b) Device upsert + 소유자/상태 갱신
#       c) 토큰 사용 처리(1회성)
# ─────────────────────────────────────────────────────────────
@router.post("/register", response_model=DeviceOut)
def register_device(
    body: DeviceRegisterIn,
    db: Session = Depends(get_db),
    reg_token_enc: Optional[str] = Header(None, alias="X-Registration-Token-Enc"),
    reg_token_plain: Optional[str] = Header(None, alias="X-Registration-Token"),

):
    # # mTLS 확인
    # if request.headers.get("x-ssl-client-verify") != "SUCCESS":
    #     raise HTTPException(403, "mTLS required")

    # 0) 암호문 우선 복호화 -> 평문 토큰 획득
    if reg_token_enc:
        try:
            reg_token = decrypt_on_server(PRIV_KEY, reg_token_enc).decode()
        except Exception:
            raise HTTPException(400, "invalid_encrypted_token")
    elif reg_token_plain:
        # 구규격 폴백(가능하면 제거 권장)
        reg_token = reg_token_plain
    else:
        raise HTTPException(400, "missing_registration_token")
    
    # 1) 등록 토큰 조회 + 락
    reg = (
        db.query(RegistrationToken)
        .filter(RegistrationToken.token == reg_token)
        .with_for_update(nowait=False)
        .first()
    )
    if not reg:
        raise HTTPException(400, "invalid_token")
    if reg.used:
        raise HTTPException(400, "token_already_used")
    if reg.expires_at < datetime.utcnow():
        raise HTTPException(400, "token_expired")

    # 2) 디바이스 조회 + 락
    # 2) 사전등록 기기 조회(시리얼)
    dev = (
        db.query(Device)
        .filter(Device.serial_no == body.serial_no)
        .with_for_update(nowait=False)
        .first()
    )

    if not dev:
        raise HTTPException(404, "device_not_found")
    if dev.owner_user_id and dev.owner_user_id != reg.user_id:
        raise HTTPException(409, "already_owned_by_other_user")

    # 3) 서명 검증: 기기 공개키로 "토큰 문자열" 검증
    if not dev.pub_key:
        raise HTTPException(400, "device_pubkey_missing")
    if not verify_ed25519_signature(dev.pub_key, reg_token.encode(), body.signature_b64):
        raise HTTPException(401, "invalid_signature")

    # 4) 연결/업데이트
    dev.owner_user_id = reg.user_id
    if body.model:
        dev.model = body.model
    dev.status = "registered"

    # 5) 토큰 1회성 소모
    reg.used = True
    db.commit()
    db.refresh(dev)
    return DeviceOut.from_orm(dev)

    # 4) 토큰 1회성 소모(원자적)
    reg.used = True

    db.commit()
    db.refresh(dev)
    return DeviceOut.from_orm(dev)

# ─────────────────────────────────────────────────────────────
# 4) 단일 기기 상태 조회 (로그인 사용자 본인 소유만)
# ─────────────────────────────────────────────────────────────
@router.get("/{device_id}/status", response_model=DeviceOut)
def get_device_status(
    device_id: str,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id),
):
    dev = db.query(Device).filter(Device.device_id == device_id).first()
    if not dev or dev.owner_user_id != user_id:
        raise HTTPException(404, "not_found")
    return DeviceOut.from_orm(dev)

# ─────────────────────────────────────────────────────────────
# 5) 내 모든 기기 목록/상태
# ─────────────────────────────────────────────────────────────
@router.get("/status", response_model=list[DeviceOut])
def get_my_devices_status(
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id),
):
    devices = db.query(Device).filter(Device.owner_user_id == user_id).all()
    return [DeviceOut.from_orm(d) for d in devices]

# ─────────────────────────────────────────────────────────────
# 6) 기기 삭제 (로그인 사용자 본인 소유만)
# ─────────────────────────────────────────────────────────────
@router.delete("/{device_id}", status_code=204)
def delete_device(
    device_id: str,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id),
):
    dev = db.query(Device).filter(Device.device_id == device_id).first()
    if not dev:
        raise HTTPException(404, "not_found")
    if dev.owner_user_id != user_id:
        raise HTTPException(403, "forbidden")
    
    dev.owner_user_id = None
    dev.status = "inactive"
    db.commit()
    return Response(status_code=204)