# app/security.py
import os
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

bearer = HTTPBearer(auto_error=True)

def get_current_user_id(token: HTTPAuthorizationCredentials = Depends(bearer)) -> int:
    """Authorization: Bearer <JWT> 에서 user_id(sub) 추출"""
    try:
        payload = jwt.decode(token.credentials, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        sub = payload.get("sub")
        if not sub:
            raise HTTPException(401, "invalid token (no sub)")
        return int(sub)
    except JWTError:
        raise HTTPException(401, "invalid or expired token")