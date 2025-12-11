import os
import json
import base64
import traceback
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import uvicorn

# Crypto
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------
APP_PORT = int(os.getenv("PORT", 8000))

ASL_API_KEY = os.getenv("ASL_API_KEY")
BUSINESS_PLACE_ID = os.getenv("BUSINESS_PLACE_ID")
AUTHORIZED_MACS_URL = os.getenv("AUTHORIZED_MACS_URL")
AUTHORIZED_MACS = os.getenv("AUTHORIZED_MACS", "")
ASL_URL = "https://xtrace.aslbelgisi.uz/public/api/v1/doc/aggregation"

BOT_TOKEN = os.getenv("BOT_TOKEN")  # Telegram bot token
ADMIN_ID = os.getenv("ADMIN_ID")    # Telegram admin chat id (as string or number)

# Files for HWID lists
AUTHORIZED_FILE = os.getenv("AUTHORIZED_FILE", "authorized_hwids.json")
PENDING_FILE = os.getenv("PENDING_FILE", "pending_hwids.json")

# ------------------------------------------------------------------
# FastAPI init
# ------------------------------------------------------------------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------
# Utilities: JSON file load/save (robust)
# ------------------------------------------------------------------
def ensure_file_exists(path: str, default):
    if not os.path.exists(path):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(default, f, indent=2, ensure_ascii=False)
        except Exception:
            traceback.print_exc()

def load_json(path: str, default):
    ensure_file_exists(path, default)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        traceback.print_exc()
        return default

def save_json(path: str, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        traceback.print_exc()

# ensure files exist on startup
ensure_file_exists(AUTHORIZED_FILE, [])
ensure_file_exists(PENDING_FILE, [])

# ------------------------------------------------------------------
# Helper: short HWID for Telegram buttons (first 12 chars)
# ------------------------------------------------------------------
def short_hwid(hwid: str) -> str:
    """Returns first 12 characters of HWID for display/buttons"""
    return hwid[:12].upper()

def find_hwid_by_short(short: str, hwid_list: List[str]) -> str:
    """Finds full HWID from list by matching first 12 chars"""
    short_upper = short.upper()
    for hwid in hwid_list:
        if hwid.upper().startswith(short_upper):
            return hwid.upper()
    return ""

# ------------------------------------------------------------------
# Telegram helper (fixed for short HWID)
# ------------------------------------------------------------------
def send_telegram(message: str, buttons: List[List[Dict]] = None):
    """Send message to admin. buttons: inline_keyboard format"""
    if not BOT_TOKEN or not ADMIN_ID:
        print("[TG] BOT_TOKEN or ADMIN_ID not configured - skipping send")
        return

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": str(ADMIN_ID),
        "text": message,
        "parse_mode": "HTML",
        "disable_notification": False
    }
    if buttons:
        payload["reply_markup"] = {"inline_keyboard": buttons}
    try:
        r = requests.post(url, json=payload, timeout=6)
        if r.status_code != 200:
            print("[TG] send failed:", r.status_code, r.text)
    except Exception:
        traceback.print_exc()

# small helper to answer callback queries
def answer_callback_query(callback_query_id: str, text: str = ""):
    if not BOT_TOKEN:
        return
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/answerCallbackQuery"
        requests.post(url, json={"callback_query_id": callback_query_id, "text": text}, timeout=5)
    except Exception:
        traceback.print_exc()

# ------------------------------------------------------------------
# New Telegram admin helpers (for text commands)
# ------------------------------------------------------------------
def send_message_to_chat(chat_id: str, text: str):
    if not BOT_TOKEN:
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": str(chat_id),
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception:
        traceback.print_exc()

async def handle_admin_command(chat_id: str, text: str):
    """Processes admin text commands such as /list, /remove ..."""

    text = (text or "").strip()
    parts = text.split()
    if not parts:
        return

    cmd = parts[0].lower()

    # /help
    if cmd == "/help":
        send_message_to_chat(chat_id,
            "<b>Admin Commands:</b>\n"
            "/list – show authorized HWIDs\n"
            "/pending – show pending HWIDs\n"
            "/remove &lt;HWID_short&gt; – remove HWID from authorized\n"
            "/clear_pending – clear pending list\n"
        )
        return

    # /list
    if cmd == "/list":
        authorized = load_json(AUTHORIZED_FILE, [])
        if not authorized:
            send_message_to_chat(chat_id, "<b>Authorized list is empty.</b>")
        else:
            msg = "<b>Authorized HWIDs:</b>\n"
            msg += "\n".join(f"- <code>{short_hwid(a)}</code>... ({a})" for a in authorized)
            send_message_to_chat(chat_id, msg)
        return

    # /pending
    if cmd == "/pending":
        pending = load_json(PENDING_FILE, [])
        if not pending:
            send_message_to_chat(chat_id, "<b>Pending list is empty.</b>")
        else:
            msg = "<b>Pending HWIDs:</b>\n"
            msg += "\n".join(f"- <code>{short_hwid(p)}</code>... ({p})" for p in pending)
            send_message_to_chat(chat_id, msg)
        return

    # /clear_pending
    if cmd == "/clear_pending":
        save_json(PENDING_FILE, [])
        send_message_to_chat(chat_id, "<b>Pending list cleared.</b>")
        return

    # /remove <HWID_short>
    if cmd == "/remove":
        if len(parts) < 2:
            send_message_to_chat(chat_id, "Usage: /remove &lt;HWID_short&gt;")
            return
        hwid_short = parts[1].upper()

        authorized = load_json(AUTHORIZED_FILE, [])
        full_hwid = find_hwid_by_short(hwid_short, authorized)
        
        if full_hwid:
            authorized.remove(full_hwid)
            save_json(AUTHORIZED_FILE, authorized)
            send_message_to_chat(chat_id, f"⛔ Removed: <code>{short_hwid(full_hwid)}</code>...")
        else:
            send_message_to_chat(chat_id, f"<b>HWID not found:</b> <code>{hwid_short}</code>")
        return

    send_message_to_chat(chat_id, "Unknown command. Use /help.")

# ------------------------------------------------------------------
# Models
# ------------------------------------------------------------------
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

# ------------------------------------------------------------------
# MAC check logic (kept for backwards compatibility)
# ------------------------------------------------------------------
def check_mac_authorization(mac: str) -> bool:
    try:
        print(f"[CHECK MAC] {mac}")
        if AUTHORIZED_MACS:
            authorized = {m.strip().upper() for m in AUTHORIZED_MACS.split(",") if m.strip()}
            return mac.upper() in authorized
        if AUTHORIZED_MACS_URL:
            r = requests.get(AUTHORIZED_MACS_URL, timeout=5)
            if r.status_code == 200:
                authorized = {line.strip().upper() for line in r.text.splitlines() if line.strip()}
                return mac.upper() in authorized
        return False
    except Exception:
        traceback.print_exc()
        return False

# ------------------------------------------------------------------
# /aggregation endpoint (unchanged)
# ------------------------------------------------------------------
@app.post("/aggregation", response_model=AggregationResponse)
async def aggregation(request: AggregationRequest, x_client_mac: str = Header(...)):
    if not check_mac_authorization(x_client_mac):
        raise HTTPException(status_code=403, detail="MAC address not authorized")
    if not ASL_API_KEY or not BUSINESS_PLACE_ID:
        raise HTTPException(status_code=500, detail="ASL config missing")
    try:
        raw_json = base64.b64decode(request.documentBody.encode()).decode()
        body_json = json.loads(raw_json)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid documentBody")
    body_json["businessPlaceId"] = int(BUSINESS_PLACE_ID)
    new_body = json.dumps(body_json, ensure_ascii=False, separators=(",", ":"))
    new_document_body = base64.b64encode(new_body.encode()).decode()
    headers = {
        "Authorization": f"Bearer {ASL_API_KEY}",
        "X-Business-Place-Id": BUSINESS_PLACE_ID,
        "Content-Type": "application/json"
    }
    try:
        r = requests.post(ASL_URL, json={"documentBody": new_document_body}, headers=headers, timeout=30)
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"ASL request failed: {e}")
    try:
        body = r.json()
    except Exception:
        body = {"raw_response": r.text}
    return AggregationResponse(status_code=r.status_code, body=body)

# ------------------------------------------------------------------
# /check-auth (unchanged)
# ------------------------------------------------------------------
@app.get("/check-auth")
async def check_auth(x_client_mac: str = Header(...)):
    authorized = check_mac_authorization(x_client_mac)
    return AuthCheckResponse(authorized=authorized, message="Authorized" if authorized else "Not authorized")

# ------------------------------------------------------------------
# /activate - issue signed license if HWID authorized, otherwise pending
# ------------------------------------------------------------------
@app.post("/activate")
async def activate(request: ActivationRequest):
    hwid = request.hwid.strip().upper()
    print(f"[ACTIVATE] request for HWID: {hwid}")

    authorized = load_json(AUTHORIZED_FILE, [])
    pending = load_json(PENDING_FILE, [])

    # not authorized -> add to pending and notify admin
    if hwid not in authorized:
        if hwid not in pending:
            pending.append(hwid)
            save_json(PENDING_FILE, pending)

        # USE SHORT HWID IN BUTTONS (Telegram limit: 64 bytes)
        short = short_hwid(hwid)
        buttons = [
            [{"text": "✅ Разрешить", "callback_data": f"approve:{short}"}],
            [{"text": "⛔ Блокировать", "callback_data": f"deny:{short}"}]
        ]
        send_telegram(
            f"🔐 <b>Новый HWID запросил доступ:</b>\n"
            f"<code>{short}</code>...\n\n"
            f"<i>Полный HWID: {hwid}</i>",
            buttons
        )
        return {"authorized": False, "message": "HWID not approved"}

    # authorized -> issue RSA-signed payload
    private_key_pem = os.getenv("RSA_PRIVATE_KEY")
    if not private_key_pem:
        raise HTTPException(status_code=500, detail="RSA_PRIVATE_KEY not configured")

    try:
        private_key = RSA.import_key(private_key_pem)
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Invalid RSA private key")

    payload = {"hwid": hwid, "valid": True, "exp": "2030-01-01"}
    payload_str = json.dumps(payload, separators=(",", ":"))
    payload_b64 = base64.b64encode(payload_str.encode()).decode()

    try:
        h = SHA256.new(payload_str.encode())
        signature = pkcs1_15.new(private_key).sign(h)
        signature_b64 = base64.b64encode(signature).decode()
    except Exception:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Signing failed")

    return {"authorized": True, "payload": payload_b64, "signature": signature_b64}

# ------------------------------------------------------------------
# /validate - strict validate + add to pending + notify
# ------------------------------------------------------------------
class ValidateRequest(BaseModel):
    hwid: str

@app.post("/validate")
async def validate(request: ValidateRequest):
    """
    Жёсткая проверка + автоподача заявки в Telegram если HWID не найден.
    """
    hwid = request.hwid.strip().upper()
    print(f"[VALIDATE] Проверка HWID: {hwid}")

    authorized = load_json(AUTHORIZED_FILE, [])
    pending = load_json(PENDING_FILE, [])

    # --- HWID РАЗРЕШЁН ---
    if hwid in authorized:
        return {"authorized": True}

    # --- HWID НЕ РАЗРЕШЁН → создать pending и отправить TG-запрос ---
    if hwid not in pending:
        pending.append(hwid)
        save_json(PENDING_FILE, pending)

        # Telegram уведомление с SHORT HWID
        short = short_hwid(hwid)
        buttons = [
            [{"text": "✅ Разрешить", "callback_data": f"approve:{short}"}],
            [{"text": "⛔ Блокировать", "callback_data": f"deny:{short}"}]
        ]
        send_telegram(
            f"🛑 <b>Клиент потерял авторизацию или запрашивает доступ снова:</b>\n"
            f"<code>{short}</code>...\n\n"
            f"<i>Полный HWID: {hwid}</i>",
            buttons
        )

    return {"authorized": False}

# ------------------------------------------------------------------
# Admin endpoints: view pending/authorized and approve via HTTP
# ------------------------------------------------------------------
@app.get("/pending-hwids")
async def get_pending_hwids():
    pending = load_json(PENDING_FILE, [])
    return {"pending": pending}

@app.get("/authorized-hwids")
async def get_authorized_hwids():
    auth = load_json(AUTHORIZED_FILE, [])
    return {"authorized": auth}

@app.post("/approve/{hwid_or_short}")
async def approve_hwid(hwid_or_short: str):
    """Approve by full HWID or short (first 12 chars)"""
    hw_input = hwid_or_short.strip().upper()
    
    auth = load_json(AUTHORIZED_FILE, [])
    pending = load_json(PENDING_FILE, [])
    
    # Check if it's a short HWID - find full version
    if len(hw_input) <= 12:
        # Search in pending first
        full_hwid = find_hwid_by_short(hw_input, pending)
        if not full_hwid:
            # Search in authorized
            full_hwid = find_hwid_by_short(hw_input, auth)
        if not full_hwid:
            raise HTTPException(status_code=404, detail="HWID not found")
        hw = full_hwid
    else:
        hw = hw_input
    
    if hw not in auth:
        auth.append(hw)
        save_json(AUTHORIZED_FILE, auth)
    
    if hw in pending:
        pending.remove(hw)
        save_json(PENDING_FILE, pending)
    
    send_telegram(f"✅ HWID разрешён:\n<code>{short_hwid(hw)}</code>...")
    return {"status": "ok", "approved": hw}

# ------------------------------------------------------------------
# Telegram webhook endpoint (GET to satisfy setWebhook test, POST to handle callbacks + commands)
# ------------------------------------------------------------------
@app.get("/bot/{token}")
async def bot_get(token: str):
    # Simple test endpoint - returns OK so setWebhook doesn't get 404
    return {"ok": True, "token": token}

@app.post("/bot/{token}")
async def bot_webhook(token: str, request: Request):
    # first: quick token check
    if not BOT_TOKEN:
        return {"ok": False, "error": "bot token not configured"}

    if token != BOT_TOKEN:
        # token mismatch - ignore
        return {"ok": False, "error": "token mismatch"}

    # parse incoming update
    try:
        data = await request.json()
    except Exception:
        return {"ok": False, "error": "invalid json"}

    # HANDLE TEXT MESSAGES (admin commands)
    if "message" in data:
        msg = data["message"]
        chat_id = str(msg["chat"]["id"])
        from_id = str(msg["from"]["id"])
        text = msg.get("text", "")

        # only admin can use commands
        if str(ADMIN_ID) == from_id:
            await handle_admin_command(chat_id, text)
        else:
            send_message_to_chat(chat_id, "You are not allowed to use admin commands.")

        return {"ok": True}

    # HANDLE CALLBACK BUTTONS approve/deny (with SHORT HWID)
    if "callback_query" in data:
        cq = data["callback_query"]
        cmd = cq.get("data", "")
        cq_id = cq.get("id")
        from_id = str(cq["from"]["id"])

        # only admin
        if str(ADMIN_ID) != from_id:
            answer_callback_query(cq_id, "Not authorized")
            return {"ok": True}

        if ":" not in cmd:
            answer_callback_query(cq_id, "Unknown cmd")
            return {"ok": True}

        action, hwid_short = cmd.split(":", 1)
        
        authorized = load_json(AUTHORIZED_FILE, [])
        pending = load_json(PENDING_FILE, [])
        
        # Find full HWID from short
        full_hwid = find_hwid_by_short(hwid_short, pending)
        if not full_hwid:
            full_hwid = find_hwid_by_short(hwid_short, authorized)
        
        if not full_hwid:
            answer_callback_query(cq_id, "HWID not found")
            return {"ok": True}
        
        hw = full_hwid.upper()

        if action == "approve":
            if hw not in authorized:
                authorized.append(hw)
                save_json(AUTHORIZED_FILE, authorized)

            if hw in pending:
                pending.remove(hw)
                save_json(PENDING_FILE, pending)

            answer_callback_query(cq_id, "Approved")
            send_telegram(f"✅ Approved:\n<code>{short_hwid(hw)}</code>...")

        elif action == "deny":
            if hw in pending:
                pending.remove(hw)
                save_json(PENDING_FILE, pending)

            answer_callback_query(cq_id, "Denied")
            send_telegram(f"⛔ Denied:\n<code>{short_hwid(hw)}</code>...")

        return {"ok": True}

    return {"ok": True}

# ------------------------------------------------------------------
# Health
# ------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}

# ------------------------------------------------------------------
# Run
# ------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=APP_PORT)
