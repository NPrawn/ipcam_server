from sqlalchemy import (
    Column, Integer, String, DateTime, Boolean, ForeignKey, UniqueConstraint, func
)
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