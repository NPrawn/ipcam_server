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
    token: str
    device_id: str
    pub_key: Optional[str] = None   # 장치 공개키(PEM). 지금 단계에서 수집한다면 필수로 바꿔도 됨
    model: Optional[str] = None
    serial_no: Optional[str] = None

# 기기 응답
class DeviceOut(BaseModel):
    device_id: str
    owner_user_id: Optional[int] = None
    pub_key: Optional[str] = None
    model: Optional[str] = None
    serial_no: Optional[str] = None
    status: Literal["waiting","registered","inactive","revoked"]
    created_at: datetime

    class Config:
        from_attributes = True

