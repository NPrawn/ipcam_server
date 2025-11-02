# app/routers/devices.py
import io
import json
import qrcode
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import RegistrationToken, Device
from app.security import get_current_user_id
from app.schemas import RegistrationTokenOut, DeviceRegisterIn, DeviceOut

router = APIRouter(prefix="/devices", tags=["Devices"])

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

# ─────────────────────────────────────────────────────────────
# 2) 등록용 QR PNG (토큰 즉석 발급 + {token, api} → PNG)
# ─────────────────────────────────────────────────────────────
@router.get("/registration-qr.png")
def get_registration_qr_png(
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id),
    api_base: str = Query(..., description="기기가 호출할 API 베이스 URL (예: https://<IP or Domain>)"),
):
    token = secrets.token_urlsafe(24)
    expires_at = datetime.utcnow() + timedelta(minutes=REG_TOKEN_TTL_MIN)
    db.add(RegistrationToken(token=token, user_id=user_id, expires_at=expires_at))
    db.commit()

    payload = {"token": token, "api": api_base}
    data = json.dumps(payload, ensure_ascii=False)

    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    headers = {"X-Registration-Token": token}
    return StreamingResponse(buf, media_type="image/png", headers=headers)

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
    payload: DeviceRegisterIn,
    request: Request,
    db: Session = Depends(get_db),
):
    # mTLS 확인
    if request.headers.get("x-ssl-client-verify") != "SUCCESS":
        raise HTTPException(403, "mTLS required")

    # 1) 등록 토큰 조회 + 락
    reg = (
        db.query(RegistrationToken)
        .filter(RegistrationToken.token == payload.token)
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
    dev = (
        db.query(Device)
        .filter(Device.device_id == payload.device_id)
        .with_for_update(nowait=False)
        .first()
    )

    # 기존 소유자 보호(이미 다른 사용자 소유면 충돌)
    if dev and dev.owner_user_id and dev.owner_user_id != reg.user_id:
        raise HTTPException(409, "already_owned_by_other_user")

    # 3) 디바이스 upsert (스트리밍 연동 삭제: vpn_tunnel_id는 더미/기본)
    vpn_tunnel_id: Optional[str] = None
    if dev:
        dev.owner_user_id = reg.user_id
        dev.model = payload.model or dev.model
        dev.mac_addr = payload.mac_addr or dev.mac_addr
        dev.serial_no = payload.serial_no or dev.serial_no
        if vpn_tunnel_id:
            dev.vpn_tunnel_id = vpn_tunnel_id
        dev.status = "registered"
    else:
        dev = Device(
            device_id=payload.device_id,
            owner_user_id=reg.user_id,
            model=payload.model,
            mac_addr=payload.mac_addr,
            serial_no=payload.serial_no,
            vpn_tunnel_id=vpn_tunnel_id or f"vpn-{payload.device_id}",  # 임시/더미
            status="registered",
        )
        db.add(dev)

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
        raise
