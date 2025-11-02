from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, ForeignKey, UniqueConstraint, func
)
from sqlalchemy.orm import relationship
from datetime import datetime

from datetime import datetime
from .database import Base

# ───────────────────────────────────────────────
# 👤 사용자 테이블
# ───────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String, nullable=False)  # 예: 'naver'
    social_id = Column(String, unique=True, index=True)
    name = Column(String)
    email = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ───────────────────────────────────────────────
# 🔁 리프레시 토큰 테이블
# ───────────────────────────────────────────────
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = Column(String(255), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


# ───────────────────────────────────────────────
# 🕒 임시 로그인 세션 (state 기반)
# ───────────────────────────────────────────────
class TempLoginSession(Base):
    __tablename__ = "temp_login_sessions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    state = Column(String(100), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    used = Column(Boolean, default=False)

class RegistrationToken(Base):
    __tablename__ = "registration_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(255), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", backref="registration_tokens")

class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        UniqueConstraint("device_id", name="uq_devices_device_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(255), nullable=False)  # 실제 기기 고유 ID
    owner_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    model = Column(String(255), nullable=True)
    mac_addr = Column(String(64), nullable=True)
    serial_no = Column(String(255), nullable=True)

    vpn_tunnel_id = Column(String(255), nullable=True)  # 현재는 더미/후에 스트리밍 연동 시 갱신
    status = Column(String(64), nullable=False, default="registered")

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    owner = relationship("User", backref="devices")