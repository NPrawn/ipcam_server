from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, ForeignKey, UniqueConstraint, func, CheckConstraint, Text
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
        UniqueConstraint("pub_key",  name="uq_devices_pub_key"),  # NULL 은 중복 허용(DB별), 값이 있으면 고유
        CheckConstraint(
            "status IN ('waiting','registered','inactive','revoked')",
            name="ck_devices_status"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)

    # 설계상 필수/고유
    device_id   = Column(String(255), nullable=False)

    # 설계상 nullable
    owner_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # 설계상 pub_key(고유) — 장치의 공개키(PEM 텍스트). 초기 이행을 위해 nullable=True 로 두고 점진 수집 권장
    pub_key     = Column(Text, nullable=True)  # 최초 마이그레이션 단계에선 NULL 허용 권장

    # 선택값
    model       = Column(String(255), nullable=True)
    serial_no   = Column(String(255), nullable=True)

    # ↓ 설계에 없지만 기존 코드 사용 중이면 유지(나중에 제거 가능)
    mac_addr        = Column(String(64),  nullable=True)
    vpn_tunnel_id   = Column(String(255), nullable=True)

    # 상태: 기본값 waiting → 등록 완료 시 registered 로 갱신
    status      = Column(String(32), nullable=False, default="waiting")

    created_at  = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    owner = relationship("User", backref="devices")