# scripts/test_call_be_create_info.py
from app.utils.streaming_be_create import call_be_create_info

if __name__ == "__main__":
    ok, data = call_be_create_info(
        device_id="dev-1234",
        device_pubkey_b64u="여기에실제기기공개키(Base64URL)",
        reg_jwt="여기에실제-등록JWT",
        owner_user_id=1,
        timeout=5,
    )
    print("OK:", ok)
    print("DATA:", data)
