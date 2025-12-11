import os
import json
import base64
import traceback
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import uvicorn

# Crypto
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

app = FastAPI()

# ============================
# CORS
# ============================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================
# ENV VARIABLES
# ============================
ASL_API_KEY = os.getenv("ASL_API_KEY")
BUSINESS_PLACE_ID = os.getenv("BUSINESS_PLACE_ID")
AUTHORIZED_MACS_URL = os.getenv("AUTHORIZED_MACS_URL")
AUTHORIZED_MACS = os.getenv("AUTHORIZED_MACS", "")
ASL_URL = "https://xtrace.aslbelgisi.uz/public/api/v1/doc/aggregation"

BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID = os.getenv("ADMIN_ID")

AUTHORIZED_FILE = "authorized_hwids.json"
PENDING_FILE = "pending_hwids.json"

# ============================
# Utility JSON functions
# ============================
def load_json(path: str, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            traceback.print_exc()
    return default

def save_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# ============================
# Telegram
# ============================
def send_telegram(message: str, buttons=None):
    if not BOT_TOKEN or not ADMIN_ID:
        print("[TG] BOT_TOKEN or ADMIN_ID is missing")
        return

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    payload = {
        "chat_id": ADMIN_ID,
        "text": message,
        "parse_mode": "HTML"
    }

    if buttons:
        payload["reply_markup"] = {"inline_keyboard": buttons}

    try:
        requests.post(url, json=payload, timeout=5)
    except:
        traceback.print_exc()

# ============================
# Models
# ============================
class AggregationRequest(BaseModel):
    documentBody: str

class AggregationResponse(BaseModel):
    status_code: int
    body: dict

class ActivationRequest(BaseModel):
    hwid: str

class AuthCheckResponse(BaseModel):
    authorized: bool
    message: str

# ============================
# Old MAC check (unchanged)
# ============================
def check_mac_authorization(mac: str) -> bool:
    try:
        print(f"[CHECK MAC] Checking {mac}")

        if AUTHORIZED_MACS:
            authorized = {m.strip().upper() for m in AUTHORIZED_MACS.split(",")}
            return mac.upper() in authorized

        if AUTHORIZED_MACS_URL:
            response = requests.get(AUTHORIZED_MACS_URL, timeout=5)
            if response.status_code == 200:
                authorized = {line.strip().upper() for line in response.text.splitlines()}
                return mac.upper() in authorized

        return False
    except:
        traceback.print_exc()
        return False

# ============================
# /aggregation (unchanged)
# ============================
@app.post("/aggregation", response_model=AggregationResponse)
async def aggregation(request: AggregationRequest, x_client_mac: str = Header(...)):
    if not check_mac_authorization(x_client_mac):
        raise HTTPException(status_code=403, detail="MAC address not authorized")

    if not ASL_API_KEY or not BUSINESS_PLACE_ID:
        raise HTTPException(status_code=500, detail="Server is not configured")

    try:
        raw_json = base64.b64decode(request.documentBody.encode()).decode()
        body_json = json.loads(raw_json)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid documentBody")

    body_json["businessPlaceId"] = int(BUSINESS_PLACE_ID)

    new_body = json.dumps(body_json, ensure_ascii=False, separators=(",", ":"))
    new_document_body = base64.b64encode(new_body.encode()).decode()

    headers = {
        "Authorization": f"Bearer {ASL_API_KEY}",
        "X-Business-Place-Id": BUSINESS_PLACE_ID,
        "Content-Type": "application/json"
    }

    response = requests.post(
        ASL_URL,
        json={"documentBody": new_document_body},
        headers=headers,
        timeout=30
    )

    try:
        body = response.json()
    except:
        body = {"raw_response": response.text}

    return AggregationResponse(status_code=response.status_code, body=body)

# ============================
# /check-auth (unchanged)
# ============================
@app.get("/check-auth")
async def check_auth(x_client_mac: str = Header(...)):
    authorized = check_mac_authorization(x_client_mac)
    return AuthCheckResponse(
        authorized=authorized,
        message="Authorized" if authorized else "Not authorized"
    )

# ============================
# RSA /activate
# ============================
@app.post("/activate")
async def activate(request: ActivationRequest):
    hwid = request.hwid.strip().upper()
    print(f"[ACTIVATE] Request for HWID: {hwid}")

    authorized = load_json(AUTHORIZED_FILE, [])
    pending = load_json(PENDING_FILE, [])

    # ---------------------------------------------------
    # HWID NOT AUTHORIZED → add to pending and notify admin
    # ---------------------------------------------------
    if hwid not in authorized:

        if hwid not in pending:
            pending.append(hwid)
            save_json(PENDING_FILE, pending)

        # Telegram alert
        buttons = [
            [{"text": "Разрешить", "callback_data": f"approve:{hwid}"}],
            [{"text": "Блокировать", "callback_data": f"deny:{hwid}"}]
        ]

        send_telegram(
            f"🔐 <b>Новый HWID запросил доступ:</b>\n<code>{hwid}</code>",
            buttons
        )

        return {"authorized": False, "message": "HWID not approved"}

    # ---------------------------------------------------
    # HWID AUTHORIZED → issue license
    # ---------------------------------------------------
    private_key_pem = os.getenv("RSA_PRIVATE_KEY")
    if not private_key_pem:
        raise HTTPException(status_code=500, detail="RSA_PRIVATE_KEY missing")

    try:
        private_key = RSA.import_key(private_key_pem)
    except:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Invalid RSA key")

    payload = {
        "hwid": hwid,
        "valid": True,
        "exp": "2030-01-01"
    }

    payload_str = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.b64encode(payload_str.encode()).decode()

    h = SHA256.new(payload_str.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    signature_b64 = base64.b64encode(signature).decode()

    return {
        "authorized": True,
        "payload": payload_b64,
        "signature": signature_b64
    }

# ============================
# Telegram Webhook
# ============================
@app.post("/bot/{token}")
async def telegram_webhook(token: str, request: Request):
    if token != BOT_TOKEN:
        return {"ok": False}

    data = await request.json()

    if "callback_query" not in data:
        return {"ok": True}

    callback = data["callback_query"]
    cmd = callback.get("data", "")
    chat_id = str(callback["from"]["id"])

    # Only admin can approve
    if chat_id != str(ADMIN_ID):
        return {"ok": True}

    if ":" not in cmd:
        return {"ok": True}

    action, hwid = cmd.split(":", 1)
    hwid = hwid.strip().upper()

    authorized = load_json(AUTHORIZED_FILE, [])
    pending = load_json(PENDING_FILE, [])

    if action == "approve":
        if hwid not in authorized:
            authorized.append(hwid)
            save_json(AUTHORIZED_FILE, authorized)

        if hwid in pending:
            pending.remove(hwid)
            save_json(PENDING_FILE, pending)

        send_telegram(f"✅ HWID разрешён:\n<code>{hwid}</code>")

    elif action == "deny":
        if hwid in pending:
            pending.remove(hwid)
            save_json(PENDING_FILE, pending)

        send_telegram(f"⛔ HWID заблокирован:\n<code>{hwid}</code>")

    return {"ok": True}

# ============================
# Health
# ============================
@app.get("/health")
async def health():
    return {"status": "ok"}

# ============================
# Run
# ============================
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
