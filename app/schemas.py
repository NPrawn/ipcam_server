# app/schemas.py
from pydantic import BaseModel, Field
from typing import Optional

class RegistrationTokenOut(BaseModel):
    token: str
    expires_in_seconds: int = 300

class DeviceRegisterIn(BaseModel):
    token: str = Field(..., description="임시 등록 토큰")
    device_id: str = Field(..., description="카메라 고유 ID")
    model: Optional[str] = None
    mac_addr: Optional[str] = None
    serial_no: Optional[str] = None

class DeviceOut(BaseModel):
    device_id: str
    owner_user_id: Optional[int]
    model: Optional[str]
    vpn_tunnel_id: Optional[str]
    status: str
    class Config:
        from_attributes = True