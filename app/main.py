from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from app.routers.registration import router as reg_router
import json

from .database import Base, engine
from . import auth, models

class UTF8JSONResponse(Response):
    media_type = "application/json; charset=utf-8"
    def render(self, content) -> bytes:
        return json.dumps(jsonable_encoder(content), ensure_ascii=False).encode("utf-8")

Base.metadata.create_all(bind=engine)

app = FastAPI(title="IPCam API", default_response_class=UTF8JSONResponse)
# mTLS 헤더 디버그용
@app.get("/_debug/mtls")
def dbg(request: __import__("fastapi").Request):
    h = request.headers
    return {
        "verify": h.get("x-ssl-client-verify"),
        "serial": h.get("x-ssl-client-serial"),
        "subject": h.get("x-ssl-client-s-dn"),
        "issuer": h.get("x-ssl-client-i-dn"),
    }
app.include_router(auth.router)
app.include_router(reg_router)


@app.get("/")
def ping():
    return {"ok": True}

from fastapi.openapi.models import APIKey, APIKeyIn, SecuritySchemeType
from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    openapi_schema["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi