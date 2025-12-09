import os
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import uvicorn

app = FastAPI()

# CORS для доступа с клиента
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Получаем секреты из переменных окружения
ASL_API_KEY = os.getenv("ASL_API_KEY")
BUSINESS_PLACE_ID = os.getenv("BUSINESS_PLACE_ID")
AUTHORIZED_MACS_URL = os.getenv("AUTHORIZED_MACS_URL")  # опционально
AUTHORIZED_MACS = os.getenv("AUTHORIZED_MACS", "")  # список через запятую
ASL_URL = "https://xtrace.aslbelgisi.uz/public/api/v1/doc/aggregation"


class AggregationRequest(BaseModel):
    documentBody: str


class AggregationResponse(BaseModel):
    status_code: int
    body: dict


class AuthCheckResponse(BaseModel):
    authorized: bool
    message: str


def check_mac_authorization(mac: str) -> bool:
    """Проверяет MAC адрес в списке авторизованных"""
    try:
        print(f"[CHECK] Проверка MAC: {mac}")
        
        # СПОСОБ 1: Из переменной окружения AUTHORIZED_MACS (список через запятую)
        if AUTHORIZED_MACS:
            print(f"[CHECK] Используем AUTHORIZED_MACS из переменной окружения")
            authorized_macs = {m.strip().upper() for m in AUTHORIZED_MACS.split(",") if m.strip()}
            print(f"[CHECK] Список MAC: {authorized_macs}")
            result = mac.upper() in authorized_macs
            print(f"[CHECK] MAC {mac} → {'✅ АВТОРИЗОВАН' if result else '❌ ЗАБЛОКИРОВАН'}")
            return result
        
        # СПОСОБ 2: Из URL (если указан)
        if AUTHORIZED_MACS_URL:
            print(f"[CHECK] Загружаем MAC из GitHub: {AUTHORIZED_MACS_URL}")
            response = requests.get(AUTHORIZED_MACS_URL, timeout=5)
            print(f"[CHECK] GitHub ответ: {response.status_code}")
            
            if response.status_code == 200:
                authorized_macs = {line.strip().upper() for line in response.text.splitlines() if line.strip()}
                print(f"[CHECK] Загружено {len(authorized_macs)} MAC адресов")
                result = mac.upper() in authorized_macs
                print(f"[CHECK] MAC {mac} → {'✅ АВТОРИЗОВАН' if result else '❌ ЗАБЛОКИРОВАН'}")
                return result
        
        print(f"[CHECK] ❌ Нет источника MAC адресов!")
        return False
    except Exception as e:
        print(f"[CHECK] ❌ Ошибка проверки: {e}")
        return False


@app.post("/aggregation", response_model=AggregationResponse)
async def aggregation(request: AggregationRequest, x_client_mac: str = Header(...)):
    """Отправляет агрегацию в ASL (с проверкой MAC)"""
    
    print(f"\n[AGGREGATION] Запрос от MAC: {x_client_mac}")
    
    # Проверка MAC адреса
    if not check_mac_authorization(x_client_mac):
        print(f"[AGGREGATION] ❌ Отклонено - MAC не авторизован")
        raise HTTPException(status_code=403, detail="MAC address not authorized")
    
    print(f"[AGGREGATION] ✅ MAC авторизован, отправляем в ASL API")
    
    # Проверка конфигурации
    if not ASL_API_KEY:
        raise HTTPException(status_code=500, detail="ASL_API_KEY not configured")
    if not BUSINESS_PLACE_ID:
        raise HTTPException(status_code=500, detail="BUSINESS_PLACE_ID not configured")
    
    # --- РАСКОДИРУЕМ documentBody ---
    try:
        raw_json = base64.b64decode(request.documentBody.encode("utf-8")).decode("utf-8")
        body_json = json.loads(raw_json)
        print("[AGGREGATION] documentBody успешно раскодирован")
    except Exception as e:
        print(f"[AGGREGATION] ❌ Ошибка декодирования documentBody: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid documentBody: {e}")
    
    # --- ДОБАВЛЯЕМ businessPlaceId ВНУТРЬ JSON ---
    body_json["businessPlaceId"] = BUSINESS_PLACE_ID
    print(f"[AGGREGATION] Добавлен businessPlaceId={BUSINESS_PLACE_ID} в documentBody")
    
    # --- ПЕРЕкОДИРУЕМ ОБНОВЛЁННЫЙ JSON В BASE64 ---
    new_raw_json = json.dumps(body_json, ensure_ascii=False, separators=(",", ":"))
    new_document_body = base64.b64encode(new_raw_json.encode("utf-8")).decode("utf-8")
    
    headers = {
        "Authorization": f"Bearer {ASL_API_KEY}",
        "X-Business-Place-Id": BUSINESS_PLACE_ID,
        "Content-Type": "application/json"
    }
    
    payload = {
        "documentBody": new_document_body
    }
    
    try:
        response = requests.post(ASL_URL, json=payload, headers=headers, timeout=30)
        print(f"[AGGREGATION] ASL API ответ: {response.status_code}")
        
        try:
            response_body = response.json()
        except:
            response_body = {"raw_response": response.text}
        
        return AggregationResponse(
            status_code=response.status_code,
            body=response_body
        )
    
    except requests.RequestException as e:
        print(f"[AGGREGATION] ❌ Ошибка ASL API: {e}")
        raise HTTPException(status_code=500, detail=f"ASL API request failed: {str(e)}")


@app.get("/check-auth")
async def check_auth(x_client_mac: str = Header(...)):
    """Проверяет авторизацию MAC адреса"""
    print(f"\n[CHECK-AUTH] Проверка MAC: {x_client_mac}")
    
    authorized = check_mac_authorization(x_client_mac)
    
    print(f"[CHECK-AUTH] Результат: {'✅ Авторизован' if authorized else '❌ Не авторизован'}")
    
    return AuthCheckResponse(
        authorized=authorized,
        message="Authorized" if authorized else "Not authorized"
    )


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))

