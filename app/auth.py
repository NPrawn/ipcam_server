import os, json, secrets, requests, re
from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import APIRouter, HTTPException, Header
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from pydantic import BaseModel

from .database import SessionLocal
from .models import User, RefreshToken, TempLoginSession  # ✅ models.py의 클래스 import

load_dotenv()
router = APIRouter(prefix="/auth", tags=["Auth"])

NAVER_CLIENT_ID = os.getenv("NAVER_CLIENT_ID")
NAVER_CLIENT_SECRET = os.getenv("NAVER_CLIENT_SECRET")
NAVER_REDIRECT_URI = os.getenv("NAVER_REDIRECT_URI")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# ───────────────────────────────────────────────
# 유틸
# ───────────────────────────────────────────────
KOREAN_RE = re.compile(r"[가-힣]")
def _has_korean(s: str) -> bool:
    return bool(KOREAN_RE.search(s))
def _fix_name(raw: str) -> str:
    try:
        fixed = raw.encode("latin1").decode("utf-8")
        if _has_korean(fixed): return fixed
    except Exception:
        pass
    try:
        fixed = raw.encode("utf-8").decode("latin1")
        if _has_korean(fixed): return fixed
    except Exception:
        pass
    return raw

def create_jwt(user_id: int):
    payload = {"sub": str(user_id), "exp": datetime.utcnow() + timedelta(hours=2)}
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_jwt(token: str):
    """
    JWT를 복호화하여 유효성 검사 및 user_id 반환
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return int(user_id)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# ───────────────────────────────────────────────
# Request / Response 모델
# ───────────────────────────────────────────────
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    user: dict

class NaverTokenRequest(BaseModel):
    state: str

# ───────────────────────────────────────────────
# 로그인 URL 생성
# ───────────────────────────────────────────────
def build_auth_url(state_mode: str) -> str:
    nonce = secrets.token_urlsafe(8) # 8바이트 랜덤 토큰
    state = f"{state_mode}:{nonce}"
    return (
        f"https://nid.naver.com/oauth2.0/authorize"
        f"?response_type=code&client_id={NAVER_CLIENT_ID}"
        f"&redirect_uri={NAVER_REDIRECT_URI}&state={state}"
    )

@router.get("/naver/login")
def naver_login():
    return {"auth_url": build_auth_url("login")}

@router.get("/naver/signup")
def naver_signup():
    return {"auth_url": build_auth_url("signup")}

# ───────────────────────────────────────────────
# CALLBACK: 네이버 code 처리, 사용자 검증, state 저장
# ───────────────────────────────────────────────
@router.get("/naver/callback")
def naver_callback(code: str, state: str):
    """네이버 인증 콜백"""
    if ":" in state:
        mode, nonce = state.split(":", 1)
    else:
        mode = state
    # 1) Access Token 요청
    token_res = requests.post(
        "https://nid.naver.com/oauth2.0/token",
        params={
            "grant_type": "authorization_code",
            "client_id": NAVER_CLIENT_ID,
            "client_secret": NAVER_CLIENT_SECRET,
            "code": code,
            "state": mode,
        },
    )
    if token_res.status_code != 200:
        raise HTTPException(500, "토큰 발급 실패")

    access_token = token_res.json().get("access_token")

    # 2) 사용자 정보 요청
    headers = {"Authorization": f"Bearer {access_token}", "Accept-Charset": "utf-8"}
    user_res = requests.get("https://openapi.naver.com/v1/nid/me", headers=headers)
    user_res.encoding = "utf-8"
    data = user_res.json()
    profile = data["response"]

    social_id = profile["id"]
    raw_name = profile.get("name")
    name = raw_name if raw_name is None else (
        raw_name if _has_korean(raw_name) else _fix_name(raw_name)
    )
    email = profile.get("email")

    # 3) DB 사용자 조회 또는 생성
    db: Session = SessionLocal()
    user = db.query(User).filter(User.social_id == social_id).first()

    if mode == "login":
        if not user:
            raise HTTPException(403, "user_not_registered")
    elif mode == "signup":
        if user:
            raise HTTPException(409, "already_registered")
        user = User(provider="naver", social_id=social_id, name=name, email=email)
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        raise HTTPException(400, "invalid_state")

    # 4) state 기반 임시 세션 저장
    temp = TempLoginSession(state=state, user_id=user.id)
    db.add(temp)
    db.commit()

    return {
        "message": "login_ready",
        "state": state,
        "user_id": user.id,
        "info": "앱이 /auth/naver/token 호출 시 JWT 발급됩니다."
    }

# ───────────────────────────────────────────────
# TOKEN 발급 (앱이 state로 요청)
# ───────────────────────────────────────────────
@router.post("/naver/token", response_model=TokenResponse)
def issue_token(body: NaverTokenRequest):
    db: Session = SessionLocal()
    temp = db.query(TempLoginSession).filter(TempLoginSession.state == body.state).first()

    if not temp:
        raise HTTPException(404, "invalid_state_or_expired")
    if temp.used:
        raise HTTPException(400, "token_already_issued")

    user = db.query(User).filter(User.id == temp.user_id).first()
    if not user:
        raise HTTPException(404, "user_not_found")

    # JWT / Refresh 발급
    access_token = create_jwt(user.id)
    refresh_token = secrets.token_urlsafe(48)
    expires_at = datetime.utcnow() + timedelta(days=30)

    new_refresh = RefreshToken(
        user_id=user.id,
        token=refresh_token,
        expires_at=expires_at,
        revoked=False,
    )
    db.add(new_refresh)
    temp.used = True
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {"id": user.id, "name": user.name, "email": user.email},
    }

# ───────────────────────────────────────────────
# Access Token 재발급
# ───────────────────────────────────────────────
@router.post("/refresh")
def refresh_access_token(data: dict):
    """
    Refresh Token을 이용해 새 Access Token 발급
    """
    token = data.get("refresh_token")
    if not token:
        raise HTTPException(status_code=400, detail="refresh_token_required")

    db: Session = SessionLocal()
    rt = db.query(RefreshToken).filter(RefreshToken.token == token).first()

    if not rt or rt.revoked:
        raise HTTPException(status_code=401, detail="invalid_or_revoked_refresh_token")

    if rt.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="refresh_token_expired")

    new_access_token = create_jwt(rt.user_id)
    return {"access_token": new_access_token}

# ───────────────────────────────────────────────
# 로그아웃 (Refresh Token 폐기)
# ───────────────────────────────────────────────
@router.post("/logout")
def logout(data: dict):
    """
    Refresh Token을 만료시켜 로그아웃 처리
    """
    token = data.get("refresh_token")
    if not token:
        raise HTTPException(status_code=400, detail="refresh_token_required")

    db: Session = SessionLocal()
    rt = db.query(RefreshToken).filter(RefreshToken.token == token).first()

    if not rt:
        raise HTTPException(status_code=404, detail="refresh_token_not_found")

    rt.revoked = True
    db.commit()
    return {"message": "logout_success"}



# ───────────────────────────────────────────────
#  사용자 정보 조회
# ───────────────────────────────────────────────
@router.get("/me")
def get_current_user(Authorization: str = Header(...)):
    """
    로그인된 사용자 정보 조회
    """
    # 1️⃣ 리스트 형태일 경우 첫 번째 값만 사용
    if isinstance(Authorization, list):
        Authorization = Authorization[0]

    # 2️⃣ 헤더 형식 검사
    if not Authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")

    # 3️⃣ 토큰 추출
    token = Authorization.split(" ")[1]

    # 4️⃣ JWT 검증
    try:
        user_id = verify_jwt(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

    # 5️⃣ 유저 조회
    db: Session = SessionLocal()
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "provider": user.provider,
        "created_at": user.created_at,
    }