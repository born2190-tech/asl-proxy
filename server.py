import os
import json
import base64
import traceback
from typing import List, Any, Dict

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

# CORS для доступа с клиента
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------
# 环境ные переменные
# -----------------------
ASL_API_KEY = os.getenv("ASL_API_KEY")
BUSINESS_PLACE_ID = os.getenv("BUSINESS_PLACE_ID")
AUTHORIZED_MACS_URL = os.getenv("AUTHORIZED_MACS_URL")  # опционально
AUTHORIZED_MACS = os.getenv("AUTHORIZED_MACS", "")  # список через запятую
ASL_URL = "https://xtrace.aslbelgisi.uz/public/api/v1/doc/aggregation"

# Telegram
BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID = os.getenv("ADMIN_ID
