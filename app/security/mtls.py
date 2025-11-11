import os
from fastapi import Header, HTTPException

def _parse_csv(env: str | None) -> set[str]:
    if not env:
        return set()
    return {x.strip() for x in env.split(",") if x.strip()}

ALLOWED_CNS = _parse_csv(os.getenv("MTLS_ALLOWED_CNS"))
ALLOWED_FPS = _parse_csv(os.getenv("MTLS_ALLOWED_FPS"))  # 프록시가 넘기는 지문 형식과 일치해야 함

def require_mtls_client(
    x_ssl_client_verify: str = Header(None, alias="X-SSL-Client-Verify"),
    x_ssl_client_cn: str = Header(None, alias="X-SSL-Client-CN"),
    x_ssl_client_fp: str = Header(None, alias="X-SSL-Client-FP"),
):
    # 1) 프록시가 mTLS 검증 성공했는지 확인
    if x_ssl_client_verify != "SUCCESS":
        raise HTTPException(status_code=403, detail="mTLS verification failed")

    # 2) 인증서 식별 화이트리스트 검사 (CN/FP 둘 중 하나라도 통과)
    cn_ok = (len(ALLOWED_CNS) == 0) or (x_ssl_client_cn in ALLOWED_CNS)
    fp_ok = (len(ALLOWED_FPS) == 0) or (x_ssl_client_fp in ALLOWED_FPS)

    if not (cn_ok or fp_ok):
        raise HTTPException(status_code=403, detail="mTLS client not allowed")

    # 통과 → 호출측에서 필요시 CN/FP를 추가 활용할 수 있도록 리턴
    return {
        "client_cn": x_ssl_client_cn,
        "client_fp": x_ssl_client_fp,
    }
