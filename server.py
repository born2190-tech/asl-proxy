"""
ПОЛНЫЙ прокси-сервер для ASL BELGISI API
С поддержкой: лицензирования, агрегации, нанесения, поиска кодов
"""

import os
import json
import traceback
import uuid
from typing import Any, Dict, List
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import uvicorn

# PostgreSQL
import psycopg2
from psycopg2.pool import SimpleConnectionPool
from psycopg2.extras import RealDictCursor

# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------
APP_PORT = int(os.getenv("PORT", 8000))

ASL_API_KEY = os.getenv("ASL_API_KEY")
BUSINESS_PLACE_ID = os.getenv("BUSINESS_PLACE_ID")
ASL_API_URL = "https://xtrace.aslbelgisi.uz"

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
        db_pool = SimpleConnectionPool(
            minconn=1,
            maxconn=10,
            dsn=DATABASE_URL
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
    if db_pool and conn:
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
# Database functions
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
# HWID Mapping: short_id <-> full_hwid
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
    except Exception as e:
        print(f"[TG] send exception: {e}")

# ------------------------------------------------------------------
# FastAPI init
# ------------------------------------------------------------------
app = FastAPI(title="ASL BELGISI Proxy Server")
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
# Models
# ------------------------------------------------------------------
class ValidateRequest(BaseModel):
    hwid: str

class AggregationRequest(BaseModel):
    documentBody: str  # Base64 encoded JSON

class UtilisationRequest(BaseModel):
    sntins: list
    releaseType: str
    manufacturerCountry: str
    productGroup: str
    productionOrderId: Optional[str] = None
    productionDate: Optional[str] = None
    expirationDate: Optional[str] = None
    seriesNumber: Optional[str] = None

class SearchCodeRequest(BaseModel):
    code: str

# ------------------------------------------------------------------
# Endpoints
# ------------------------------------------------------------------

@app.get("/")
async def root():
    """Главная страница"""
    return {
        "service": "ASL BELGISI Proxy Server",
        "version": "1.4.0",
        "endpoints": {
            "validate": "POST /validate",
            "aggregation": "POST /aggregation",
            "utilisation": "POST /utilisation",
            "search_code": "POST /search-code"
        }
    }

@app.get("/health")
async def health():
    """Health check для protection.dll"""
    return {"status": "ok"}

@app.post("/validate")
async def validate(request: ValidateRequest):
    """Проверка лицензии по HWID"""
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

@app.post("/aggregation")
async def aggregation(request: AggregationRequest):
    """Отправка отчёта об агрегации"""
    
    # Формируем запрос к ASL API
    asl_request = {
        "documentBody": request.documentBody  # Передаём base64 как есть
    }
    
    headers = {
        "Authorization": f"Bearer {ASL_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            f"{ASL_API_URL}/public/api/v1/doc/aggregation",  # ✅ Правильный из документации
            json=asl_request,
            headers=headers,
            timeout=60
        )
        
        return {
            "status_code": response.status_code,
            "body": response.json() if response.status_code == 200 else response.text
        }
    
    except requests.Timeout:
        raise HTTPException(status_code=504, detail="Timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/utilisation")
async def utilisation(request: UtilisationRequest):
    """Отправка отчёта о нанесении"""
    
    # Формируем запрос к ASL API
    asl_request = {
        "sntins": request.sntins,
        "businessPlaceId": int(BUSINESS_PLACE_ID),  # ✅ Берём с сервера!
        "releaseType": request.releaseType,
        "manufacturerCountry": request.manufacturerCountry
    }
    
    # Опциональные поля
    if request.productionOrderId:
        asl_request["productionOrderId"] = request.productionOrderId
    if request.productionDate:
        asl_request["productionDate"] = request.productionDate
    if request.expirationDate:
        asl_request["expirationDate"] = request.expirationDate
    if request.seriesNumber:
        asl_request["seriesNumber"] = request.seriesNumber
    
    headers = {
        "Authorization": f"Bearer {ASL_API_KEY}",
        "Content-Type": "application/json"
    }
    
    # productGroup передаём в query параметре (согласно документации!)
    params = {
        "productGroup": request.productGroup
    }
    
    try:
        response = requests.post(
            f"{ASL_API_URL}/api/utilisation",
            json=asl_request,
            headers=headers,
            params=params,  # ✅ Query параметр
            timeout=60
        )
        
        return {
            "status_code": response.status_code,
            "body": response.json() if response.status_code == 200 else response.text
        }
    
    except requests.Timeout:
        raise HTTPException(status_code=504, detail="Timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/search-code")
async def search_code(request: SearchCodeRequest):
    """
    Поиск информации о коде маркировки или SSCC
    Возвращает детальную информацию включая:
    - parentCode (родительский SSCC)
    - children[] (дочерние коды)
    - все параметры товара
    """
    
    # Вызываем ASL API для получения детальной информации
    asl_url = f"{ASL_API_URL}/public/api/cod/private/codes"
    
    headers = {
        "Authorization": f"Bearer {ASL_API_KEY}",
        "Content-Type": "application/json"
    }
    
    asl_request = {
        "codes": [request.code]
    }
    
    try:
        response = requests.post(
            asl_url,
            json=asl_request,
            headers=headers,
            timeout=30
        )
        
        return {
            "status_code": response.status_code,
            "body": response.json() if response.status_code == 200 else response.text
        }
    
    except requests.Timeout:
        raise HTTPException(status_code=504, detail="Timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Admin endpoints (for Telegram bot)
@app.post("/approve/{hwid_or_short}")
async def approve(hwid_or_short: str):
    """Approve HWID (via Telegram bot)"""
    hwid = get_hwid_from_short_id(hwid_or_short) or hwid_or_short
    if not hwid:
        raise HTTPException(status_code=404, detail="HWID not found")
    
    db_add_authorized(hwid)
    db_remove_pending(hwid)
    
    send_telegram(f"✅ <b>Устройство авторизовано:</b>\n<code>{short_hwid_display(hwid)}</code>")
    
    return {"status": "approved"}

@app.post("/deny/{hwid_or_short}")
async def deny(hwid_or_short: str):
    """Deny HWID (via Telegram bot)"""
    hwid = get_hwid_from_short_id(hwid_or_short) or hwid_or_short
    if not hwid:
        raise HTTPException(status_code=404, detail="HWID not found")
    
    db_remove_pending(hwid)
    db_remove_authorized(hwid)
    
    send_telegram(f"⛔ <b>Устройство заблокировано:</b>\n<code>{short_hwid_display(hwid)}</code>")
    
    return {"status": "denied"}

@app.post("/bot/{token}")
async def bot_webhook(token: str, request: Request):
    """Telegram bot webhook"""
    if token != BOT_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    try:
        data = await request.json()
        
        if "callback_query" in data:
            callback = data["callback_query"]
            callback_data = callback.get("data", "")
            
            if callback_data.startswith("approve:"):
                short_id = callback_data.split(":")[1]
                hwid = get_hwid_from_short_id(short_id)
                
                if hwid:
                    db_add_authorized(hwid)
                    db_remove_pending(hwid)
                    
                    url = f"https://api.telegram.org/bot{BOT_TOKEN}/answerCallbackQuery"
                    requests.post(url, json={
                        "callback_query_id": callback["id"],
                        "text": f"✅ Устройство {short_hwid_display(hwid)} авторизовано!"
                    })
                    
                    send_telegram(f"✅ <b>Устройство авторизовано:</b>\n<code>{short_hwid_display(hwid)}</code>")
            
            elif callback_data.startswith("deny:"):
                short_id = callback_data.split(":")[1]
                hwid = get_hwid_from_short_id(short_id)
                
                if hwid:
                    db_remove_pending(hwid)
                    db_remove_authorized(hwid)
                    
                    url = f"https://api.telegram.org/bot{BOT_TOKEN}/answerCallbackQuery"
                    requests.post(url, json={
                        "callback_query_id": callback["id"],
                        "text": f"⛔ Устройство {short_hwid_display(hwid)} заблокировано!"
                    })
                    
                    send_telegram(f"⛔ <b>Устройство заблокировано:</b>\n<code>{short_hwid_display(hwid)}</code>")
        
        return {"ok": True}
    
    except Exception as e:
        print(f"[BOT] Error: {e}")
        traceback.print_exc()
        return {"ok": False}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=APP_PORT)
