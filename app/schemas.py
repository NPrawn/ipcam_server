# app/schemas.py
from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime

# 등록 토큰 응답
class RegistrationTokenOut(BaseModel):
    token: str
    expires_in_seconds: int
    class Config:
        from_attributes = True

# 기기 등록 입력
class DeviceRegisterIn(BaseModel):
    model: Optional[str] = None
    serial_no: str
    signature_b64: str

# 기기 응답
class DeviceOut(BaseModel):
    device_id: str
    owner_user_id: Optional[int] = None
    model: Optional[str] = None
    serial_no: Optional[str] = None
    status: Literal["waiting","registered","inactive","revoked","auth_pending","vpn_ready","stream_ready"]
    created_at: datetime
    class Config:
        from_attributes = True

class DeviceRegisterOut(DeviceOut):
    auth_state: str
    vpn_auth_token: Optional[str] = None
    auth_expires_at: Optional[datetime] = None

# 스트리밍 시작 요청
class StreamingStartIn(BaseModel):
    device_id: str
    sdp_offer: str

# 스트리밍 시작 응답
class StreamingStartOut(BaseModel):
    device_id: str
    sdp_answer: str

# 스트리밍 종료 요청
class StreamingEndIn(BaseModel):
    device_id: str
    session_name: str

# 스트리밍 종료 응답
class StreamingEndOut(BaseModel):
    device_id: str
    success: bool