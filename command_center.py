import os
import re
import secrets
import asyncio
import socket
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any, Union

import uvicorn
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel, HttpUrl
from bs4 import BeautifulSoup

# ── Dependencies ──────────────────────────────────────────────────────────────
try:
    from scrapling.fetchers import Fetcher, StealthyFetcher
    _STEALTH_AVAILABLE = True
except ImportError:
    from scrapling import Fetcher
    StealthyFetcher = None
    _STEALTH_AVAILABLE = False

# ═══════════════════════════════════════════════════════════
# GLOBAL EXECUTOR & CONFIG
# ═══════════════════════════════════════════════════════════
cpu_executor = concurrent.futures.ProcessPoolExecutor(max_workers=4)
MAX_PAYLOAD_SIZE = 10_485_760 

# Mock Token Status for Telegram Dashboard
def get_token_status():
    return {
        "limit_per_key": 100000,
        "keys": [
            {"key_index": 1, "tokens_used": 15400, "tokens_remaining": 84600, "active": True}
        ]
    }

# ═══════════════════════════════════════════════════════════
# SECURITY & PARSER UTILITIES
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

def _extract_worker(content: bytes) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(content, 'html.parser')
    for tag in soup(['script', 'style', 'nav', 'footer', 'aside']): tag.decompose()
    results = []
    for table in soup.find_all('table'):
        rows = table.find_all('tr')
        if not rows: continue
        headers = [_sanitize_key(th.get_text(strip=True)) or f"col_{i}" for i, th in enumerate(rows[0].find_all(['th', 'td']))]
        for row in rows[1:]:
            cells = row.find_all(['td', 'th'])
            if len(cells) != len(headers): continue
            results.append({headers[i]: c.get_text(strip=True) for i, c in enumerate(cells)})
    return results

# ═══════════════════════════════════════════════════════════
# API ORCHESTRATION
# ═══════════════════════════════════════════════════════════

app = FastAPI(title="AUDITOR CORE", version="7.5.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

_ENV_KEY = os.environ.get("AUDITOR_API_KEY", "").strip()
API_KEY = _ENV_KEY if _ENV_KEY else secrets.token_hex(32)
if not _ENV_KEY: print(f"[BOOT] AUTH KEY: {API_KEY}")

@app.get("/")
async def serve_frontend():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(base_dir, "index.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    return HTMLResponse(content=f"<h2>404: index.html missing at {html_path}</h2>", status_code=404)

async def scrape_url(url: str, adaptive: bool = True, js: bool = False):
    if not _is_safe_url(url):
        raise ValueError("FORBIDDEN_DOMAIN")
    
    loop = asyncio.get_event_loop()
    if js:
        if not _STEALTH_AVAILABLE: raise ImportError("StealthFetcher missing")
        response = await loop.run_in_executor(None, lambda: StealthyFetcher.fetch(url, headless=True))
    else:
        response = await loop.run_in_executor(None, lambda: Fetcher().get(url))
    
    if not response or not hasattr(response, 'content'):
        return {"events": []}, 0

    raw_count = len(response.content)
    data = await loop.run_in_executor(cpu_executor, _extract_worker, response.content)
    return {"events": data}, raw_count

@app.on_event("startup")
async def startup():
    from telegram_bot import start_bot
    start_bot()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
