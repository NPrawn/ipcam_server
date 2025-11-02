# app/schemas.py
from pydantic import BaseModel
from typing import Optional

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
    model: Optional[str] = None
    mac_addr: Optional[str] = None
    serial_no: Optional[str] = None

# 기기 응답
class DeviceOut(BaseModel):
    device_id: str
    owner_user_id: Optional[int] = None
    model: Optional[str] = None
    mac_addr: Optional[str] = None
    serial_no: Optional[str] = None
    vpn_tunnel_id: Optional[str] = None
    status: str

    class Config:
        from_attributes = True 

