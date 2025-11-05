# app/security.py
import os
from fastapi import Header, HTTPException
from jose import jwt, JWTError
from dotenv import load_dotenv, find_dotenv

# ⬇️ .env를 어떤 작업 디렉토리에서도 확실히 찾도록
load_dotenv(find_dotenv())

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

def get_current_user_id(Authorization: str = Header(...)) -> int:
    # 헤더가 리스트로 들어오는 변종 방어
    if isinstance(Authorization, list):
        Authorization = Authorization[0]

    # 대소문자 혼용 허용: 'Bearer ' 접두만 확인
    parts = Authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header")

    token = parts[1]

    # 🔒 서버 설정 미스 방지: 키가 없으면 500 대신 명확한 에러로
    if not isinstance(JWT_SECRET_KEY, (str, bytes)) or not JWT_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Server misconfigured: JWT secret missing")

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        sub = payload.get("sub")
        if not sub:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return int(sub)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")