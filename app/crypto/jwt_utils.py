import os, secrets
from datetime import datetime, timedelta, timezone
import jwt

JWT_SECRET = os.getenv("REG_JWT_SECRET")
JWT_ISSUER = os.getenv("REG_JWT_ISSUER", "ipcam")

def issue_reg_jwt(user_id: int, ttl_minutes: int = 5) -> tuple[str, str, datetime]:
    """
    등록 토큰용 JWT 발급.
    반환: (jwt_token, jti, expires_at_utc)
    """
    if not JWT_SECRET:
        raise RuntimeError("REG_JWT_SECRET is not set")

    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ttl_minutes)
    jti = secrets.token_hex(16)  # 32 hex chars

    payload = {
        "iss": JWT_ISSUER,
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
        "typ": "registration",
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token, jti, exp.replace(tzinfo=None)  # DB는 naive UTC로 저장하는 현재 스키마에 맞춤

def verify_reg_jwt(jwt_token: str) -> dict:
    """
    등록 토큰용 JWT 검증 및 디코딩. 유효하면 클레임(dict) 리턴, 실패시 예외 발생.
    """
    if not JWT_SECRET:
        raise RuntimeError("REG_JWT_SECRET is not set")
    claims = jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"], options={"require": ["exp", "iat", "jti", "sub"]})
    if claims.get("iss") != JWT_ISSUER:
        raise jwt.InvalidIssuerError("invalid issuer")
    if claims.get("typ") != "registration":
        raise jwt.InvalidTokenError("invalid typ")
    return claims
