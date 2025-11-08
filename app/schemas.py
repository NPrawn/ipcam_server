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
    status: Literal["waiting","registered","inactive","revoked"]
    created_at: datetime
    class Config:
        from_attributes = True

