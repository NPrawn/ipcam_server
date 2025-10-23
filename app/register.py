# app/register.py
import secrets, io, json, qrcode
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import RegistrationToken, Device
from .security import get_current_user_id
from .schemas import RegistrationTokenOut, DeviceRegisterIn, DeviceOut

router = APIRouter(prefix="/devices", tags=["Device Registration"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/registration-token", response_model=RegistrationTokenOut)
def issue_registration_token(
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id),
):
    """로그인 사용자만 임시 등록 토큰 발급 (5분 만료, 1회용)"""
    token = secrets.token_urlsafe(24)
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    db.add(RegistrationToken(token=token, user_id=user_id, expires_at=expires_at))
    db.commit()
    return RegistrationTokenOut(token=token, expires_in_seconds=300)

@router.post("/register", response_model=DeviceOut)
def register_device(
    payload: DeviceRegisterIn,
    db: Session = Depends(get_db),
):
    """기기(카메라)에서 토큰 + device_id로 서버에 등록 요청"""
    # 1) 토큰 검증
    reg = db.query(RegistrationToken).filter(RegistrationToken.token == payload.token).first()
    if not reg:
        raise HTTPException(400, "invalid_token")
    if reg.used:
        raise HTTPException(400, "token_already_used")
    if reg.expires_at < datetime.utcnow():
        raise HTTPException(400, "token_expired")

    # 2) 기기 upsert + 소유자/터널 갱신
    dev = db.query(Device).filter(Device.device_id == payload.device_id).first()
    vpn_id = f"vpn-{payload.device_id}-{secrets.token_hex(4)}"  # 실제 VPN 연동 자리에 연결

    if dev:
        dev.owner_user_id = reg.user_id
        dev.model = payload.model or dev.model
        dev.mac_addr = payload.mac_addr or dev.mac_addr
        dev.serial_no = payload.serial_no or dev.serial_no
        dev.vpn_tunnel_id = vpn_id
        dev.status = "registered"
    else:
        dev = Device(
            device_id=payload.device_id,
            owner_user_id=reg.user_id,
            model=payload.model,
            mac_addr=payload.mac_addr,
            serial_no=payload.serial_no,
            vpn_tunnel_id=vpn_id,
            status="registered",
        )
        db.add(dev)

    db.commit()
    db.refresh(dev)

    # 3) 토큰 1회성 소모
    reg.used = True
    db.commit()

    return DeviceOut.from_orm(dev)

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

@router.get("/status", response_model=list[DeviceOut])
def get_my_devices_status(
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id),
):
    """로그인된 사용자의 모든 기기 목록 반환"""
    devices = db.query(Device).filter(Device.owner_user_id==user_id).all()
    return [DeviceOut.from_orm(d) for d in devices]

@router.get("/registration-qr.png")
def get_registration_qr_png(
    db: Session = Depends(get_db),
    user_id: int =Depends(get_current_user_id),
    api_base: str = Query("http://localhost:8000", description="기기가 호출할 API 베이스 URL"),
):
    """
    1. 로그인 토큰을 즉석 발급
    2. {token, api} JSON을 QR로 만들어 PNG로 변환
    """

    # 토큰발급
    token = secrets.token_urlsafe(24)
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    db.add(RegistrationToken(token=token, user_id=user_id, expires_at=expires_at))
    db.commit()

    # QR페이로드 구성
    payload = {"token": token, "api": api_base}
    data = json.dumps(payload, ensure_ascii=False)

    # QR 생성
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    # 이미지로 응답
    headers = {
        "X-Registration-Token": token
    }
    return StreamingResponse(buf, media_type="image/png", headers=headers)

@router.delete("/{device_id}", status_code=240)
def delete_device(
    device_id: str,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id),
):
    """
    🔒 로그인한 사용자 본인 소유 기기만 삭제 가능
    - 존재하지 않으면 404
    - 소유자가 아니면 403
    - 성공 시 204 No Content
    """
    dev = db.query(Device).filter(Device.device_id == device_id).first()
    if not dev:
        raise HTTPException(404, "not_found")
    if dev.owner_user_id != user_id:
        raise HTTPException(403, "forbidden")

    # (선택) 실제 운영에서는 여기서 VPN/터널 해제, 스트림 정리 등 외부 리소스 정리 수행
    # e.g., vpn_client.delete_tunnel(dev.vpn_tunnel_id)

    db.delete(dev)
    db.commit()
    return Response(status_code=204)