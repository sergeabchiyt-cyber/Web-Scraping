import re
import os
import secrets
import asyncio
import socket
import concurrent.futures
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any, Union
from collections import Counter
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl
from bs4 import BeautifulSoup

# ── Dependencies ──────────────────────────────────────────────────────────────
try:
    from scrapling.fetchers import Fetcher, StealthyFetcher
    _STEALTH_AVAILABLE = True
except ImportError:
    _STEALTH_AVAILABLE = False

try:
    from telegram import Bot
    from telegram.ext import ApplicationBuilder, CommandHandler
    _TELEGRAM_AVAILABLE = True
except ImportError:
    _TELEGRAM_AVAILABLE = False

# ═══════════════════════════════════════════════════════════
# GLOBAL EXECUTOR & LIMITS
# ═══════════════════════════════════════════════════════════
cpu_executor = concurrent.futures.ProcessPoolExecutor(max_workers=min(32, (os.cpu_count() or 1) + 4))
MAX_PAYLOAD_SIZE = 10_485_760 

# ═══════════════════════════════════════════════════════════
# SECURITY & PARSER UTILITIES (Isolated)
# ═══════════════════════════════════════════════════════════

def _is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'): return False
        hostname = parsed.hostname
        if not hostname: return False
        ip = socket.gethostbyname(hostname)
        ip_int = int.from_bytes(socket.inet_aton(ip), 'big')
        private_blocks = [
            (0x0A000000, 0xFF000000), (0xAC100000, 0xFFF00000),
            (0xC0A80000, 0xFFFF0000), (0x7F000000, 0xFF000000),
            (0xA9FE0000, 0xFFFF0000), (0x00000000, 0xFF000000)
        ]
        return not any((ip_int & mask) == (net & mask) for net, mask in private_blocks)
    except: return False

def _sanitize_key(text: str) -> str:
    clean = re.sub(r'[^a-zA-Z0-9]', '_', text.strip())
    return re.sub(r'_+', '_', clean).strip('_').lower()[:64]

def _clean_value(text: str) -> Union[str, Dict[str, Any]]:
    if not text: return None
    t = text.strip()
    fin = re.match(r'^([\+\-]?)([\$€£¥])\s?([\d,]+\.?\d*)\s?([KMBT]?)$', t)
    if fin:
        sign, curr, val, suffix = fin.groups()
        mult = {'K': 1e3, 'M': 1e6, 'B': 1e9, 'T': 1e12, '': 1}
        return {
            "numeric": float(val.replace(',', '')) * mult.get(suffix, 1) * (-1 if sign == '-' else 1),
            "currency": curr, "type": "financial"
        }
    return t[:1000]

def _extract_worker(content: bytes) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(content, 'html.parser')
    for tag in soup(['script', 'style', 'nav', 'footer', 'aside', 'svg']): tag.decompose()
    results = []
    
    for table in soup.find_all('table'):
        rows = table.find_all('tr')
        if not rows: continue
        headers = [_sanitize_key(th.get_text(strip=True)) or f"col_{i}" for i, th in enumerate(rows[0].find_all(['th', 'td']))]
        for row in rows[1:]:
            cells = row.find_all(['td', 'th'])
            if len(cells) != len(headers): continue
            results.append({headers[i]: _clean_value(c.get_text(strip=True)) for i, c in enumerate(cells)})
    return results

# ═══════════════════════════════════════════════════════════
# TELEGRAM INTEGRATION (Asynchronous)
# ═══════════════════════════════════════════════════════════

async def start_telegram_bot():
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token or not _TELEGRAM_AVAILABLE:
        print("[AUDITOR] Telegram disabled: Missing token or library.")
        return
    
    app = ApplicationBuilder().token(token).build()
    app.add_handler(CommandHandler("status", lambda u, c: u.message.reply_text("AUDITOR System Online.")))
    
    await app.initialize()
    await app.start()
    await app.updater.start_polling()
    print("[AUDITOR] Telegram Bot active.")
    return app

# ═══════════════════════════════════════════════════════════
# API ORCHESTRATION
# ═══════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Telegram Bot
    tg_app = await start_telegram_bot()
    yield
    # Shutdown: Clean up Process Pool and Telegram
    cpu_executor.shutdown(wait=True)
    if tg_app:
        await tg_app.updater.stop()
        await tg_app.stop()
        await tg_app.shutdown()

app = FastAPI(title="AUDITOR CORE", version="7.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=False,
    allow_methods=["POST"], allow_headers=["X-Api-Key", "Content-Type"],
)

_ENV_KEY = os.environ.get("AUDITOR_API_KEY", "").strip()
API_KEY = _ENV_KEY if _ENV_KEY else secrets.token_hex(32)
if not _ENV_KEY: print(f"[BOOT] API KEY: {API_KEY}")

def validate_auth(x_api_key: str = Header(..., alias="X-Api-Key")):
    if not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="UNAUTHORIZED")

class ScrapeRequest(BaseModel):
    url: HttpUrl
    js: bool = False

@app.post("/api/v1/extract", dependencies=[Depends(validate_auth)])
async def extract(payload: ScrapeRequest):
    target = str(payload.url)
    if not _is_safe_url(target):
        raise HTTPException(status_code=403, detail="RESTRICTED_URL")

    loop = asyncio.get_event_loop()
    
    try:
        if payload.js:
            if not _STEALTH_AVAILABLE: raise ValueError("Stealth engine missing")
            # Offload synchronous fetcher to thread pool
            response = await loop.run_in_executor(None, lambda: StealthyFetcher.fetch(target, headless=True, network_idle=True, wait=10))
        else:
            response = await loop.run_in_executor(None, lambda: Fetcher().get(target))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"FETCH_FAILURE: {str(e)}")

    if not response or not hasattr(response, 'content'):
        raise HTTPException(status_code=502, detail="EMPTY_RESPONSE")

    if len(response.content) > MAX_PAYLOAD_SIZE:
        raise HTTPException(status_code=413, detail="CONTENT_TOO_LARGE")

    # Offload CPU-bound parser to process pool
    extracted_data = await loop.run_in_executor(cpu_executor, _extract_worker, response.content)

    return {
        "status": "SUCCESS",
        "data": extracted_data,
        "metrics": {"nodes": len(extracted_data), "size": len(response.content)}
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
