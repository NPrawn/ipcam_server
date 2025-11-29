# scripts/test_call_be_create_info.py
from app.utils.streaming_be_create import call_be_create_info

REG_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpcGNhbSIsInN1YiI6IjIiLCJpYXQiOjE3NjQzOTY4MTksImV4cCI6MTc2NTAwMTYxOSwianRpIjoiNGIyYzQwYTVmOWZiMDg4ZDk2MjVmZDIwNzhiYWYxMGYiLCJ0eXAiOiJyZWdpc3RyYXRpb24ifQ.zu6OZ3iDD-FFQLbynBPRfkc0e5cUoIQ61VdRX6_l3O8"
if __name__ == "__main__":
    ok, data = call_be_create_info(
        device_id="test-7201aff50e7f495693b50fb90a6e3a6b",
        device_pubkey_b64u="hFXaTQIyLikhNIlJl6WyVJfKc/wAkdbBnUuMilOzcPQ=",
        reg_jwt=REG_JWT,
        owner_user_id=2,
        timeout=5,
    )
    print("OK:", ok)
    print("DATA:", data)
