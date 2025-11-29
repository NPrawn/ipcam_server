# scripts/test_call_be_create_info.py
from app.utils.streaming_be_create import call_be_create_info

if __name__ == "__main__":
    ok, data = call_be_create_info(
        device_id="dev-1234",
        device_pubkey_b64u="qweqwe",
        reg_jwt="jwtjwt",
        owner_user_id=1,
        timeout=5,
    )
    print("OK:", ok)
    print("DATA:", data)
