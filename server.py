import os
import json
import base64
import traceback
import uuid
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

# PostgreSQL
import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------
APP_PORT = int(os.getenv("PORT", 8000))

ASL_API_KEY = os.getenv("ASL_API_KEY")
BUSINESS_PLACE_ID = os.getenv("BUSINESS_PLACE_ID")
AUTHORIZED_MACS_URL = os.getenv("AUTHORIZED_MACS_URL")
AUTHORIZED_MACS = os.getenv("AUTHORIZED_MACS", "")
ASL_URL = "https://xtrace.aslbelgisi.uz/public/api/v1/doc/aggregation"

BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID = os.getenv("ADMIN_ID")

# PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL")

# ------------------------------------------------------------------
# PostgreSQL Connection Pool
# ------------------------------------------------------------------
db_pool = None

def init_db_pool():
    """Initialize PostgreSQL connection pool"""
    global db_pool
    if not DATABASE_URL:
        print("[DB] WARNING: DATABASE_URL not set!")
        return
    
    try:
        db_pool = ConnectionPool(
            conninfo=DATABASE_URL,
            min_size=1,
            max_size=10
        )
        print("[DB] Connection pool created")
        init_tables()
    except Exception as e:
        print(f"[DB] Failed to create pool: {e}")
        traceback.print_exc()

def get_db_connection():
    """Get connection from pool"""
    if not db_pool:
        raise Exception("Database pool not initialized")
    return db_pool.getconn()

def return_db_connection(conn):
    """Return connection to pool"""
    if db_pool:
        db_pool.putconn(conn)

def init_tables():
    """Create tables if they don't exist"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Table: authorized_hwids
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS authorized_hwids (
                hwid VARCHAR(255) PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_validated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table: pending_hwids
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pending_hwids (
                hwid VARCHAR(255) PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table: hwid_mapping (short_id -> full_hwid)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hwid_mapping (
                short_id VARCHAR(8) PRIMARY KEY,
                full_hwid VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        print("[DB] Tables initialized")
        
    except Exception as e:
        print(f"[DB] Failed to init tables: {e}")
        traceback.print_exc()
    finally:
        if conn:
            return_db_connection(conn)

# ------------------------------------------------------------------
# Database operations
# ------------------------------------------------------------------

def db_get_authorized() -> List[str]:
    """Get all authorized HWIDs"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT hwid FROM authorized_hwids")
        rows = cursor.fetchall()
        return [row[0] for row in rows]
    except Exception as e:
        print(f"[DB] Error getting authorized: {e}")
        return []
    finally:
        if conn:
            return_db_connection(conn)

def db_get_pending() -> List[str]:
    """Get all pending HWIDs"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT hwid FROM pending_hwids")
        rows = cursor.fetchall()
        return [row[0] for row in rows]
    except Exception as e:
        print(f"[DB] Error getting pending: {e}")
        return []
    finally:
        if conn:
            return_db_connection(conn)

def db_add_authorized(hwid: str):
    """Add HWID to authorized list"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO authorized_hwids (hwid) VALUES (%s) ON CONFLICT (hwid) DO NOTHING",
            (hwid,)
        )
        conn.commit()
    except Exception as e:
        print(f"[DB] Error adding authorized: {e}")
        traceback.print_exc()
    finally:
        if conn:
            return_db_connection(conn)

def db_remove_authorized(hwid: str):
    """Remove HWID from authorized list"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM authorized_hwids WHERE hwid = %s", (hwid,))
        conn.commit()
    except Exception as e:
        print(f"[DB] Error removing authorized: {e}")
    finally:
        if conn:
            return_db_connection(conn)

def db_add_pending(hwid: str):
    """Add HWID to pending list"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO pending_hwids (hwid) VALUES (%s) ON CONFLICT (hwid) DO NOTHING",
            (hwid,)
        )
        conn.commit()
    except Exception as e:
        print(f"[DB] Error adding pending: {e}")
    finally:
        if conn:
            return_db_connection(conn)

def db_remove_pending(hwid: str):
    """Remove HWID from pending list"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM pending_hwids WHERE hwid = %s", (hwid,))
        conn.commit()
    except Exception as e:
        print(f"[DB] Error removing pending: {e}")
    finally:
        if conn:
            return_db_connection(conn)

def db_clear_pending():
    """Clear all pending HWIDs"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM pending_hwids")
        conn.commit()
    except Exception as e:
        print(f"[DB] Error clearing pending: {e}")
    finally:
        if conn:
            return_db_connection(conn)

def db_update_last_validated(hwid: str):
    """Update last_validated timestamp"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE authorized_hwids SET last_validated = CURRENT_TIMESTAMP WHERE hwid = %s",
            (hwid,)
        )
        conn.commit()
    except Exception as e:
        print(f"[DB] Error updating last_validated: {e}")
    finally:
        if conn:
            return_db_connection(conn)

# ------------------------------------------------------------------
# HWID Mapping: short_id <-> full_hwid (SECURE)
# ------------------------------------------------------------------
def generate_short_id() -> str:
    """Generates unique 8-character ID for Telegram buttons"""
    return str(uuid.uuid4())[:8].upper()

def get_or_create_short_id(hwid: str) -> str:
    """Gets existing short_id or creates new one for HWID"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if mapping exists
        cursor.execute("SELECT short_id FROM hwid_mapping WHERE full_hwid = %s", (hwid,))
        row = cursor.fetchone()
        
        if row:
            return row[0]
        
        # Create new short_id
        short_id = generate_short_id()
        
        # Ensure uniqueness
        while True:
            cursor.execute("SELECT 1 FROM hwid_mapping WHERE short_id = %s", (short_id,))
            if not cursor.fetchone():
                break
            short_id = generate_short_id()
        
        # Insert mapping
        cursor.execute(
            "INSERT INTO hwid_mapping (short_id, full_hwid) VALUES (%s, %s)",
            (short_id, hwid)
        )
        conn.commit()
        
        return short_id
        
    except Exception as e:
        print(f"[DB] Error in get_or_create_short_id: {e}")
        traceback.print_exc()
        return generate_short_id()
    finally:
        if conn:
            return_db_connection(conn)

def get_hwid_from_short_id(short_id: str) -> str:
    """Gets full HWID from short_id"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT full_hwid FROM hwid_mapping WHERE short_id = %s", (short_id,))
        row = cursor.fetchone()
        return row[0] if row else ""
    except Exception as e:
        print(f"[DB] Error getting hwid from short_id: {e}")
        return ""
    finally:
        if conn:
            return_db_connection(conn)

def short_hwid_display(hwid: str) -> str:
    """Returns first 12 characters for display only"""
    return hwid[:12].upper()

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

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    init_db_pool()

# ------------------------------------------------------------------
# Telegram helper
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
        else:
            print("[TG] sent successfully")
    except Exception:
        traceback.print_exc()

def answer_callback_query(callback_query_id: str, text: str = ""):
    if not BOT_TOKEN:
        return
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/answerCallbackQuery"
        requests.post(url, json={"callback_query_id": callback_query_id, "text": text}, timeout=5)
    except Exception:
        traceback.print_exc()

# ------------------------------------------------------------------
# Telegram admin helpers
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
    """Processes admin text commands"""
    text = (text or "").strip()
    parts = text.split()
    if not parts:
        return

    cmd = parts[0].lower()

    if cmd == "/help":
        send_message_to_chat(chat_id,
            "<b>Admin Commands:</b>\n"
            "/list – show authorized HWIDs\n"
            "/pending – show pending HWIDs\n"
            "/view &lt;HWID_short&gt; – view HWID details\n"
            "/stats – database statistics\n"
            "/remove &lt;HWID_short&gt; – remove HWID\n"
            "/clear_pending – clear pending list\n"
        )
        return

    if cmd == "/list":
        authorized = db_get_authorized()
        if not authorized:
            send_message_to_chat(chat_id, "<b>Authorized list is empty.</b>")
        else:
            msg = "<b>Authorized HWIDs:</b>\n"
            for a in authorized:
                short_display = short_hwid_display(a)
                msg += f"- <code>{short_display}</code>...\n"
            send_message_to_chat(chat_id, msg)
        return

    if cmd == "/pending":
        pending = db_get_pending()
        if not pending:
            send_message_to_chat(chat_id, "<b>Pending list is empty.</b>")
        else:
            msg = "<b>Pending HWIDs:</b>\n"
            for p in pending:
                short_display = short_hwid_display(p)
                msg += f"- <code>{short_display}</code>...\n"
            send_message_to_chat(chat_id, msg)
        return

    if cmd == "/clear_pending":
        db_clear_pending()
        send_message_to_chat(chat_id, "<b>Pending list cleared.</b>")
        return

    if cmd == "/stats":
        authorized = db_get_authorized()
        pending = db_get_pending()
        
        # Get mapping count
        conn = None
        mapping_count = 0
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM hwid_mapping")
            mapping_count = cursor.fetchone()[0]
        except:
            pass
        finally:
            if conn:
                return_db_connection(conn)
        
        msg = (
            f"📊 <b>Database Statistics:</b>\n\n"
            f"✅ Authorized: {len(authorized)}\n"
            f"⏳ Pending: {len(pending)}\n"
            f"🔗 Mappings: {mapping_count}\n"
        )
        send_message_to_chat(chat_id, msg)
        return

    if cmd == "/view":
        if len(parts) < 2:
            send_message_to_chat(chat_id, "Usage: /view &lt;HWID_prefix or short_id&gt;")
            return
        
        input_val = parts[1].upper()
        
        # Try as short_id first
        if len(input_val) == 8:
            hwid = get_hwid_from_short_id(input_val)
        else:
            # Try prefix search
            hwid = None
            auth = db_get_authorized()
            pending = db_get_pending()
            for h in auth + pending:
                if h.upper().startswith(input_val):
                    hwid = h
                    break
        
        if not hwid:
            send_message_to_chat(chat_id, f"<b>HWID not found:</b> <code>{input_val}</code>")
            return
        
        # Get details from database
        conn = None
        details = {}
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Check authorized
            cursor.execute(
                "SELECT created_at, last_validated FROM authorized_hwids WHERE hwid = %s",
                (hwid,)
            )
            row = cursor.fetchone()
            if row:
                details['status'] = '✅ Authorized'
                details['created_at'] = row[0].strftime('%Y-%m-%d %H:%M:%S')
                details['last_validated'] = row[1].strftime('%Y-%m-%d %H:%M:%S')
            else:
                # Check pending
                cursor.execute(
                    "SELECT created_at FROM pending_hwids WHERE hwid = %s",
                    (hwid,)
                )
                row = cursor.fetchone()
                if row:
                    details['status'] = '⏳ Pending'
                    details['created_at'] = row[0].strftime('%Y-%m-%d %H:%M:%S')
                else:
                    details['status'] = '❓ Unknown'
            
            # Get short_id
            cursor.execute(
                "SELECT short_id FROM hwid_mapping WHERE full_hwid = %s",
                (hwid,)
            )
            row = cursor.fetchone()
            if row:
                details['short_id'] = row[0]
        except Exception as e:
            print(f"[DB] Error in /view: {e}")
        finally:
            if conn:
                return_db_connection(conn)
        
        short_display = short_hwid_display(hwid)
        msg = (
            f"🔍 <b>HWID Details:</b>\n\n"
            f"<b>Short:</b> <code>{short_display}</code>...\n"
            f"<b>Full:</b> <code>{hwid}</code>\n\n"
            f"<b>Status:</b> {details.get('status', 'Unknown')}\n"
        )
        
        if 'short_id' in details:
            msg += f"<b>ID:</b> <code>{details['short_id']}</code>\n"
        if 'created_at' in details:
            msg += f"<b>Created:</b> {details['created_at']}\n"
        if 'last_validated' in details:
            msg += f"<b>Last Check:</b> {details['last_validated']}\n"
        
        send_message_to_chat(chat_id, msg)
        return

    if cmd == "/remove":
        if len(parts) < 2:
            send_message_to_chat(chat_id, "Usage: /remove &lt;HWID_prefix&gt;")
            return
        prefix = parts[1].upper()
        
        authorized = db_get_authorized()
        found = None
        for hwid in authorized:
            if hwid.upper().startswith(prefix):
                found = hwid
                break
        
        if found:
            db_remove_authorized(found)
            short_display = short_hwid_display(found)
            send_message_to_chat(chat_id, f"⛔ Removed: <code>{short_display}</code>...")
        else:
            send_message_to_chat(chat_id, f"<b>HWID not found with prefix:</b> <code>{prefix}</code>")
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
# MAC check logic
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
# /aggregation endpoint
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
# /check-auth
# ------------------------------------------------------------------
@app.get("/check-auth")
async def check_auth(x_client_mac: str = Header(...)):
    authorized = check_mac_authorization(x_client_mac)
    return AuthCheckResponse(authorized=authorized, message="Authorized" if authorized else "Not authorized")

# ------------------------------------------------------------------
# /activate - SECURE VERSION with unique short IDs
# ------------------------------------------------------------------
@app.post("/activate")
async def activate(request: ActivationRequest):
    hwid = request.hwid.strip().upper()
    print(f"[ACTIVATE] request for HWID: {hwid}")

    authorized = db_get_authorized()
    pending = db_get_pending()

    # not authorized -> add to pending and notify admin
    if hwid not in authorized:
        if hwid not in pending:
            db_add_pending(hwid)

        # Generate SECURE short ID (8 characters, unique)
        short_id = get_or_create_short_id(hwid)
        short_display = short_hwid_display(hwid)
        
        # callback_data is now just 8 characters + "approve:" = 16 bytes total
        buttons = [
            [{"text": "✅ Разрешить", "callback_data": f"approve:{short_id}"}],
            [{"text": "⛔ Блокировать", "callback_data": f"deny:{short_id}"}]
        ]
        
        send_telegram(
            f"🔐 <b>Новый HWID запросил доступ:</b>\n"
            f"<code>{short_display}</code>...\n\n"
            f"<b>ID:</b> <code>{short_id}</code>\n"
            f"<i>Полный HWID: {hwid}</i>",
            buttons
        )
        return {"authorized": False, "message": "HWID not approved"}

    # Update last validated timestamp
    db_update_last_validated(hwid)

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
# /validate
# ------------------------------------------------------------------
class ValidateRequest(BaseModel):
    hwid: str

@app.post("/validate")
async def validate(request: ValidateRequest):
    hwid = request.hwid.strip().upper()
    print(f"[VALIDATE] Проверка HWID: {hwid}")

    authorized = db_get_authorized()
    pending = db_get_pending()

    if hwid in authorized:
        # Update last validated timestamp
        db_update_last_validated(hwid)
        return {"authorized": True}

    if hwid not in pending:
        db_add_pending(hwid)

        short_id = get_or_create_short_id(hwid)
        short_display = short_hwid_display(hwid)
        
        buttons = [
            [{"text": "✅ Разрешить", "callback_data": f"approve:{short_id}"}],
            [{"text": "⛔ Блокировать", "callback_data": f"deny:{short_id}"}]
        ]
        
        send_telegram(
            f"🛑 <b>Клиент потерял авторизацию:</b>\n"
            f"<code>{short_display}</code>...\n\n"
            f"<b>ID:</b> <code>{short_id}</code>\n"
            f"<i>Полный HWID: {hwid}</i>",
            buttons
        )

    return {"authorized": False}

# ------------------------------------------------------------------
# Admin endpoints
# ------------------------------------------------------------------
@app.get("/pending-hwids")
async def get_pending_hwids():
    pending = db_get_pending()
    return {"pending": pending}

@app.get("/authorized-hwids")
async def get_authorized_hwids():
    auth = db_get_authorized()
    return {"authorized": auth}

@app.post("/approve/{hwid_or_short}")
async def approve_hwid(hwid_or_short: str):
    """Approve by full HWID, short display (12 chars), or short_id (8 chars)"""
    input_val = hwid_or_short.strip().upper()
    
    auth = db_get_authorized()
    pending = db_get_pending()
    
    # Try as short_id first (8 chars from mapping)
    if len(input_val) == 8:
        full_hwid = get_hwid_from_short_id(input_val)
        if full_hwid:
            hw = full_hwid
        else:
            raise HTTPException(status_code=404, detail="Short ID not found")
    # Try as prefix match
    elif len(input_val) < 64:
        found = None
        for hwid in pending + auth:
            if hwid.upper().startswith(input_val):
                found = hwid
                break
        if not found:
            raise HTTPException(status_code=404, detail="HWID not found")
        hw = found
    else:
        hw = input_val
    
    if hw not in auth:
        db_add_authorized(hw)
    
    if hw in pending:
        db_remove_pending(hw)
    
    short_display = short_hwid_display(hw)
    send_telegram(f"✅ HWID разрешён:\n<code>{short_display}</code>...")
    return {"status": "ok", "approved": hw}

# ------------------------------------------------------------------
# Telegram webhook
# ------------------------------------------------------------------
@app.get("/bot/{token}")
async def bot_get(token: str):
    return {"ok": True, "token": token}

@app.post("/bot/{token}")
async def bot_webhook(token: str, request: Request):
    if not BOT_TOKEN or token != BOT_TOKEN:
        return {"ok": False, "error": "token mismatch"}

    try:
        data = await request.json()
    except Exception:
        return {"ok": False, "error": "invalid json"}

    # HANDLE TEXT MESSAGES
    if "message" in data:
        msg = data["message"]
        chat_id = str(msg["chat"]["id"])
        from_id = str(msg["from"]["id"])
        text = msg.get("text", "")

        if str(ADMIN_ID) == from_id:
            await handle_admin_command(chat_id, text)
        else:
            send_message_to_chat(chat_id, "You are not allowed to use admin commands.")

        return {"ok": True}

    # HANDLE CALLBACK BUTTONS - using secure short_id mapping
    if "callback_query" in data:
        cq = data["callback_query"]
        cmd = cq.get("data", "")
        cq_id = cq.get("id")
        from_id = str(cq["from"]["id"])

        if str(ADMIN_ID) != from_id:
            answer_callback_query(cq_id, "Not authorized")
            return {"ok": True}

        if ":" not in cmd:
            answer_callback_query(cq_id, "Unknown cmd")
            return {"ok": True}

        action, short_id = cmd.split(":", 1)
        
        # Get full HWID from secure mapping
        hwid = get_hwid_from_short_id(short_id)
        
        if not hwid:
            answer_callback_query(cq_id, "ID not found")
            return {"ok": True}
        
        authorized = db_get_authorized()
        pending = db_get_pending()
        
        hw = hwid.upper()

        if action == "approve":
            if hw not in authorized:
                db_add_authorized(hw)

            if hw in pending:
                db_remove_pending(hw)

            answer_callback_query(cq_id, "Approved")
            short_display = short_hwid_display(hw)
            send_telegram(f"✅ Approved:\n<code>{short_display}</code>...")

        elif action == "deny":
            # Remove from BOTH pending AND authorized (if exists)
            if hw in pending:
                db_remove_pending(hw)
            if hw in authorized:
                db_remove_authorized(hw)

            answer_callback_query(cq_id, "Denied")
            short_display = short_hwid_display(hw)
            send_telegram(f"⛔ Denied:\n<code>{short_display}</code>...")

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
