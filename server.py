pythonimport os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import uvicorn

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ASL_API_KEY = os.getenv("ASL_API_KEY")
BUSINESS_PLACE_ID = os.getenv("BUSINESS_PLACE_ID")
ASL_URL = "https://xtrace.aslbelgisi.uz/public/api/v1/doc/aggregation"


class AggregationRequest(BaseModel):
    documentBody: str


class AggregationResponse(BaseModel):
    status_code: int
    body: dict


@app.post("/aggregation", response_model=AggregationResponse)
async def aggregation(request: AggregationRequest):
    if not ASL_API_KEY:
        raise HTTPException(status_code=500, detail="ASL_API_KEY not configured")
    if not BUSINESS_PLACE_ID:
        raise HTTPException(status_code=500, detail="BUSINESS_PLACE_ID not configured")
    
    headers = {
        "Authorization": f"Bearer {ASL_API_KEY}",
        "X-Business-Place-Id": BUSINESS_PLACE_ID,
        "Content-Type": "application/json"
    }
    
    payload = {
        "documentBody": request.documentBody
    }
    
    try:
        response = requests.post(ASL_URL, json=payload, headers=headers, timeout=30)
        
        try:
            response_body = response.json()
        except:
            response_body = {"raw_response": response.text}
        
        return AggregationResponse(
            status_code=response.status_code,
            body=response_body
        )
    
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"ASL API request failed: {str(e)}")


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
