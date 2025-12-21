"""
Прокси-сервер для ASL BELGISI API
С поддержкой агрегации, нанесения и ПОИСКА КОДОВ
"""

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import requests
from typing import Optional
import os

app = FastAPI(title="ASL BELGISI Proxy Server")

# ASL BELGISI API ключ
ASL_API_KEY = os.environ.get("ASL_API_KEY", "your-api-key-here")
ASL_API_URL = "https://xtrace.aslbelgisi.uz"

# Авторизованные MAC адреса
AUTHORIZED_MACS = os.environ.get("AUTHORIZED_MACS", "").split(",")

def check_mac_authorization(mac: str) -> bool:
    """Проверка авторизации по MAC адресу"""
    if not AUTHORIZED_MACS or AUTHORIZED_MACS == [""]:
        return True  # Если список пуст - разрешаем всем
    return mac.lower() in [m.lower().strip() for m in AUTHORIZED_MACS]

# === МОДЕЛИ ДАННЫХ ===

class AggregationRequest(BaseModel):
    sscc: str
    codes: list

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

# === ENDPOINTS ===

@app.get("/")
async def root():
    """Главная страница"""
    return {
        "service": "ASL BELGISI Proxy Server",
        "version": "1.3.0",
        "endpoints": {
            "aggregation": "POST /aggregation",
            "utilisation": "POST /utilisation",
            "search_code": "POST /search-code"
        }
    }

@app.post("/aggregation")
async def aggregation(
    request: AggregationRequest,
    x_client_mac: str = Header(...)
):
    """Отправка отчёта об агрегации"""
    
    # Проверка MAC
    if not check_mac_authorization(x_client_mac):
        raise HTTPException(
            status_code=403,
            detail="MAC адрес не авторизован"
        )
    
    # Формируем запрос к ASL API
    asl_request = {
        "aggregationUnit": request.sscc,
        "aggregatedItemList": request.codes
    }
    
    headers = {
        "Authorization": f"Bearer {ASL_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            f"{ASL_API_URL}/doc/aggregation",
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
async def utilisation(
    request: UtilisationRequest,
    x_client_mac: str = Header(...)
):
    """Отправка отчёта о нанесении"""
    
    # Проверка MAC
    if not check_mac_authorization(x_client_mac):
        raise HTTPException(
            status_code=403,
            detail="MAC адрес не авторизован"
        )
    
    # Формируем запрос к ASL API
    asl_request = {
        "sntins": request.sntins,
        "releaseType": request.releaseType,
        "manufacturerCountry": request.manufacturerCountry,
        "productGroup": request.productGroup
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
    
    try:
        response = requests.post(
            f"{ASL_API_URL}/utilisation",
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

@app.post("/search-code")
async def search_code(
    request: SearchCodeRequest,
    x_client_mac: str = Header(...)
):
    """
    Поиск информации о коде маркировки или SSCC
    Возвращает детальную информацию включая:
    - parentCode (родительский SSCC)
    - children[] (дочерние коды)
    - все параметры товара
    """
    
    # Проверка MAC
    if not check_mac_authorization(x_client_mac):
        raise HTTPException(
            status_code=403,
            detail="MAC адрес не авторизован"
        )
    
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
