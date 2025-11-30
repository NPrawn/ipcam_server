# app/routers/devices.py
import base64
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, Header
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database import SessionLocal
from app.models import RegistrationToken, Device
from app.security.security import get_current_user_id
from app.schemas import RegistrationTokenOut, DeviceRegisterIn, DeviceOut, DeviceRegisterOut
from app.crypto.jwt_utils import issue_reg_jwt, verify_reg_jwt, issue_vpn_jwt, verify_vpn_jwt, VpnJwtError
from app.security.mtls import require_mtls_client
from app.utils.ed25519_keyfmt import pubkey_to_raw32_b64url
from app.utils.streaming_be_create import call_be_create_info

# Ed25519 서명 검즈
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

router = APIRouter(prefix="/devices", tags=["Devices"])

class RegisterReq(BaseModel):
    model: Optional[str] = None
    serial_no: str
    signature_b64: str     # 기기가 'JWT 문자열'에 대해 Ed25519로 서명한 값(Base64)

# 등록 토큰 TTL(분)
REG_TOKEN_TTL_MIN = 60*24*3

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
    jwt_token, jti, exp = issue_reg_jwt(user_id, ttl_minutes=REG_TOKEN_TTL_MIN)
    # DB에는 jti만 저장(1회성 체크용)
    db.add(RegistrationToken(token=jti, user_id=user_id, expires_at=exp))
    db.commit()
    # 응답은 JWT
    return RegistrationTokenOut(token=jwt_token, expires_in_seconds=REG_TOKEN_TTL_MIN * 60)


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
    reg_jwt: str = Header(..., alias="X-Registration-Token")
):
    # # mTLS 확인
    # if request.headers.get("x-ssl-client-verify") != "SUCCESS":
    #     raise HTTPException(403, "mTLS required")

    # 0) JWT 검증
    try:
        claims = verify_reg_jwt(reg_jwt)
    except:
        raise HTTPException(400, "invalid_token")
    
    jti = claims.get("jti")
    user_id_from_claims = int(claims.get("sub"))
    
    # 1) 등록 토큰 조회 + 락
    reg = (
        db.query(RegistrationToken)
        .filter(RegistrationToken.token == jti)
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

    # 3) 서명 검증: 기기 공개키로 JWT 문자열에 대한 검증
    if not dev.pub_key:
        raise HTTPException(400, "device_pubkey_missing")
    if not verify_ed25519_signature(dev.pub_key, reg_jwt.encode(), body.signature_b64):
        print("SERVER RECEIVED JWT HEX:", reg_jwt.encode().hex())
        raise HTTPException(401, "invalid_signature")

    # 4) 상태 전이 + VPN 토큰 발급
    if body.model:
        dev.model = body.model
    dev.owner_user_id = reg.user_id
    dev.status = "auth_pending"
    dev.auth_state = "auth_pending"

    vpn_jwt, vpn_jti, vpn_exp = issue_vpn_jwt(dev.device_id, reg.user_id)
    dev.vpn_auth_token = vpn_jwt
    dev.auth_expires_at = vpn_exp
    dev.last_reg_jti = jti

    # 5) 토큰 1회성 소모
    reg.used = True
    db.commit()
    db.refresh(dev)

    try:
        pub_b64u = pubkey_to_raw32_b64url(dev.pub_key)
    except Exception:
        raise HTTPException(500, "device_pubkey_format_invalid")
    
    ok, detail = call_be_create_info(
        device_id=dev.device_id,
        device_pubkey_b64u=pub_b64u,
        reg_jwt=reg_jwt,
        owner_user_id=reg.user_id,
    )
    print(detail)

    if not ok:
        # 스트리밍 서버 반영 실패 → 운영 재시도 가능 상태로 표시
        dev.auth_state = "stream_pending"
        dev.status = "vpn_ready"   # VPN 토큰 발급은 끝남
        db.commit()
        db.refresh(dev)
    else:
        dev.auth_state = "vpn_ready"
        dev.status = "vpn_ready"
        db.commit()
        db.refresh(dev)


    return DeviceRegisterOut(
        **DeviceOut.from_orm(dev).dict(),
        auth_state=dev.auth_state,
        vpn_auth_token=dev.vpn_auth_token,
        auth_expires_at=dev.auth_expires_at
    )

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

@router.get("/{device_id}/streaming-credentials")
def get_streaming_credentials_mtls(
    device_id: str,
    db: Session = Depends(get_db),
    mtls_ctx: dict = Depends(require_mtls_client),
):
    dev = db.query(Device).filter(Device.device_id == device_id).first()
    if not dev or not dev.vpn_auth_token:
        raise HTTPException(404, "not_ready")
    if dev.auth_expires_at and dev.auth_expires_at < datetime.utcnow():
        raise HTTPException(400, "vpn_token_expired")
    if dev.auth_state not in ("auth_pending", "vpn_ready", "stream_ready"):
        raise HTTPException(400, "invalid_state")
    
    return {
        "device_id": dev.device_id,
        "device_pub_key": dev.pub_key,
        "vpn_auth_token": dev.vpn_auth_token,
        "auth_expires_at": dev.auth_expires_at,
        "owner_user_id": dev.owner_user_id,
        "issued_to": mtls_ctx["client_cn"],     # 누가 가져갔는지 감사용
    }

def _cleanup_previous_links(db: Session, dev: Device):
    """
    기존 저장 상태 있으면 삭제
    추후 구현
    """
    return

def _finalize_registration(db: Session, dev: Device):
    """
    두 콜백(vpn_confirm & stream_donfirm)이 모두 완료되면
    하나의 트랜잭션 안에서 registered로 전이
    """

    if dev.auth_state == "registered" and dev.status == "registered":
        return
    
    if not (dev.vpn_confirmed_at and dev.stream_confirmed_at):
        return
    
    _cleanup_previous_links(db, dev)

    dev.status = "registered"
    dev.auth_state = "registered"
    dev.vpn_auth_token = None
    dev.auth_expires_at = None
    db.commit()
    db.refresh(dev)

@router.post("/{device_id}/vpn-confirm")
def vpn_confirm(
    device_id: str,
    db: Session = Depends(get_db),
    vpn_token: str | None = Header(None, alias="X-VPN-Token"),
):
    # 1) 토큰 존재/검증
    if not vpn_token:
        raise HTTPException(401, "missing_vpn_token")
    try:
        payload = verify_vpn_jwt(vpn_token)
    except VpnJwtError as e:
        raise HTTPException(401, f"invalid_vpn_token: {e}")
    
    # 2) 토큰 대상 기기 일치 확인
    sub = payload.get("sub", "")
    if sub != f"device:{device_id}":
        raise HTTPException(401, "vpn_token_device_mismatch")
    
    # 3) 디바이스 락 + 상태 검증
    dev = (
        db.query(Device)
            .filter(Device.device_id == device_id)
            .with_for_update(nowait=False)
            .first()
    )
    if not dev:
        raise HTTPException(404, "not_found")
    
    if dev.auth_state not in ("auth_pending", "stream_ready", "vpn_ready"):
        if dev.auth_state == "registered":
            return {"ok": True, "state": dev.auth_state}
        raise HTTPException(400, "invalid_state")
    
    # 4) 저장된 VPN 토큰과도 매칭
    if dev.vpn_auth_token is None:
        raise HTTPException(400, "no_vpn_token_issued")
    if dev.vpn_auth_token != vpn_token:
        raise HTTPException(401, "vpn_token_mismatch")
    
    # 5) 만료 확인
    if dev.auth_expires_at and dev.auth_expires_at < datetime.utcnow():
        raise HTTPException(400, "vpn_token_expired")

    # 6) 확인 기록 + 상태 전이
    if not dev.vpn_confirmed_at:
        dev.vpn_confirmed_at = datetime.utcnow()
    dev.status = "vpn_ready"

    if not dev.stream_confirmed_at:
        dev.auth_state = "vpn_ready"
    

    db.commit()
    db.refresh(dev)

    _finalize_registration(db, dev)
    return {"ok": True, "state": dev.auth_state}

@router.post("/{device_id}/stream-confirm")
def stream_confirm(
    device_id: str,
    db: Session = Depends(get_db),
    mtls_ctx: dict = Depends(require_mtls_client),
):
    # 1) 디바이스 락 + 상태 검증
    dev = (
        db.query(Device)
            .filter(Device.device_id == device_id)
            .with_for_update(nowait=False)
            .first()
    )
    if not dev:
        raise HTTPException(404, "not_found")
    
    if dev.auth_state not in ("auth_pending", "vpn_ready", "stream_ready"):
        if dev.auth_state == "registered":
            return {"ok": True, "state": dev.auth_state}
        raise HTTPException(400, "invalid_state")
    
    # 2) 확인 기록 + 상태 전이
    if not dev.stream_confirmed_at:
        dev.stream_confirmed_at = datetime.utcnow()
    dev.status = "stream_ready"
    if not dev.vpn_confirmed_at:
        dev.auth_state = "stream_ready"
    
    db.commint()
    db.refresh(dev)

    # 3) 최종화 시도
    _finalize_registration(db, dev)
    return {"ok": True, "state": dev.auth_state}