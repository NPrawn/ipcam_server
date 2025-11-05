# app/security.py
import os
from fastapi import Header, HTTPException
from jose import jwt, JWTError
from dotenv import load_dotenv

load_dotenv()  # ⬅️ 추가: .env 로드

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

def get_current_user_id(Authorization: str = Header(...)) -> int:
    # 리스트로 들어오는 케이스 방어
    if isinstance(Authorization, list):
        Authorization = Authorization[0]

    # 대소문자 무시하고 'bearer <token>' 형태 허용
    parts = Authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header")

    token = parts[1]

    # 키가 비어있으면 500이 아니라 500 원인 노출을 막고 500 대신 명확한 구성오류 메시지
    if not JWT_SECRET_KEY or not isinstance(JWT_SECRET_KEY, (str, bytes)):
        # 운영에선 로깅만 하고 500 반환 권장
        raise HTTPException(status_code=500, detail="Server misconfigured: JWT secret missing")

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        sub = payload.get("sub")
        if not sub:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return int(sub)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")