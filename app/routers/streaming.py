# app/routers/streaming.py
import secrets
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Device
from app.security.security import get_current_user_id
from app.schemas import StreamingStartIn, StreamingStartOut, StreamingEndIn, StreamingEndOut
from app.utils.streaming_start import call_streaming_start, call_streaming_end

router = APIRouter(prefix="/streaming", tags=["Streaming"])


# ─────────────────────────────────────────────────────────────
# DB 세션 DI
# ─────────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def modify_sdp_offer(sdp_offer: str, device_id: str) -> str:
    """
    SDP offer의 s= 필드를 device_id+timestamp+nonce로 변경합니다.
    
    Args:
        sdp_offer: 원본 SDP offer 문자열
        device_id: 기기 ID
    
    Returns:
        수정된 SDP offer 문자열
    """
    timestamp = str(int(datetime.utcnow().timestamp()))
    nonce = secrets.token_urlsafe(8)
    new_session_name = f"{device_id}+{timestamp}+{nonce}"
    replacement = f's={new_session_name}'
    
    # s= 필드를 찾아서 교체
    lines = sdp_offer.split('\r\n')
    modified_lines = []
    s_replaced = False
    
    for line in lines:
        if line.startswith('s=') and not s_replaced:
            modified_lines.append(replacement)
            s_replaced = True
        else:
            modified_lines.append(line)
    
    # s= 필드가 없으면 추가 (v= 다음에 추가)
    if not s_replaced:
        result_lines = []
        for i, line in enumerate(modified_lines):
            result_lines.append(line)
            # v= 다음에 s= 추가
            if line.startswith('v=') and (i + 1 >= len(modified_lines) or not modified_lines[i + 1].startswith('s=')):
                result_lines.append(replacement)
                s_replaced = True
                break
        if s_replaced:
            modified_lines = result_lines
    
    return '\r\n'.join(modified_lines)


# ─────────────────────────────────────────────────────────────
# 스트리밍 시작 API
# ─────────────────────────────────────────────────────────────
@router.post("/start", response_model=StreamingStartOut)
def start_streaming(
    body: StreamingStartIn,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id),
):
    """
    스트리밍을 시작합니다.
    
    1. device_id가 사용자와 연결되어 있는지 확인
    2. sdp_offer의 s= 필드를 device_id+timestamp+nonce로 수정
    3. 수정된 sdp_offer를 스트리밍 서버에 전달 (mTLS)
    4. 스트리밍 서버로부터 받은 sdp_answer 반환
    """
    # 1) device_id가 실제로 사용자와 연결되어 있는지 확인
    dev = db.query(Device).filter(Device.device_id == body.device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail="device_not_found")
    if dev.owner_user_id != user_id:
        raise HTTPException(status_code=403, detail="device_not_owned_by_user")
    
    # 2) sdp_offer 내 항목의 s=를 device_id+timestamp+nonce로 작성해 채우기
    modified_sdp_offer = modify_sdp_offer(body.sdp_offer, body.device_id)
    
    # 3) 변경된 sdp_offer를 스트리밍 서버에 전달 (스트리밍 시작 요청 API 호출, mtls)
    ok, result = call_streaming_start(
        device_id=body.device_id,
        sdp_offer=modified_sdp_offer,
        owner_user_id=user_id,
    )
    
    if not ok:
        raise HTTPException(
            status_code=502,
            detail=f"streaming_server_error: {result}"
        )
    
    # 4) 스트리밍 서버로부터 받은 sdp_answer 반환
    sdp_answer = result.get("sdp_answer")
    if not sdp_answer:
        raise HTTPException(
            status_code=502,
            detail="streaming_server_response_invalid: missing sdp_answer"
        )
    
    return StreamingStartOut(
        device_id=body.device_id,
        sdp_answer=sdp_answer,
    )


# ─────────────────────────────────────────────────────────────
# 스트리밍 종료 API
# ─────────────────────────────────────────────────────────────
@router.get("/end/{device_id}", response_model=StreamingEndOut)
def end_streaming(
    device_id: str,
    body: StreamingEndIn,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_id),
):
    """
    스트리밍을 종료합니다.
    
    1. device_id가 사용자와 연결되어 있는지 확인
    2. 스트리밍 서버에 종료 요청 전달 (mTLS)
    3. 종료 결과 반환
    """
    # 1) device_id가 실제로 사용자와 연결되어 있는지 확인
    dev = db.query(Device).filter(Device.device_id == device_id).first()
    if not dev:
        raise HTTPException(status_code=404, detail="device_not_found")
    if dev.owner_user_id != user_id:
        raise HTTPException(status_code=403, detail="device_not_owned_by_user")
    
    # 2) body의 device_id와 path parameter의 device_id 일치 확인
    if body.device_id != device_id:
        raise HTTPException(status_code=400, detail="device_id_mismatch")
    
    # 3) 스트리밍 서버에 종료 요청 전달 (mTLS)
    ok, result = call_streaming_end(
        device_id=device_id,
        session_name=body.session_name,
        owner_user_id=user_id,
    )
    
    if not ok:
        if result == "device_or_session_not_found":
            raise HTTPException(
                status_code=404,
                detail="device_or_session_not_found"
            )
        raise HTTPException(
            status_code=502,
            detail=f"streaming_server_error: {result}"
        )
    
    return StreamingEndOut(
        device_id=device_id,
        success=True,
    )

