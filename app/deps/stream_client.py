import os, requests
STREAM_SERVER_URL = os.getenv("STREAM_SERVER_URL", "http://127.0.0.1:9000")
STREAM_SERVER_TOKEN = os.getenv("STREAM_SERVER_TOKEN", "changeme")

def _headers():
    return {"Authorization": f"Bearer {STREAM_SERVER_TOKEN}", "Content-Type": "application/json"}

def request_vpn_tunnel(device_id: str, auth_token_signed_by_ipcam: str, ipcam_pubkey_pem: str, vpn_pubkey_pem: str) -> dict:
    # 실제 계약에 맞게 수정 가능
    url = f"{STREAM_SERVER_URL}/api/v1/vpn/tunnels"
    resp = requests.post(url, json={
        "device_id": device_id,
        "auth_sig": auth_token_signed_by_ipcam,
        "ipcam_pubkey_pem": ipcam_pubkey_pem,
        "vpn_pubkey_pem": vpn_pubkey_pem,
    }, headers=_headers(), timeout=10)
    resp.raise_for_status()
    return resp.json()

def confirm_stream_done(device_id: str, stream_request_id: str) -> dict:
    url = f"{STREAM_SERVER_URL}/api/v1/vpn/tunnels/{stream_request_id}/status"
    resp = requests.get(url, headers=_headers(), timeout=10, params={"device_id": device_id})
    resp.raise_for_status()
    return resp.json()
