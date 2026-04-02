import re
import os
import secrets
import asyncio
import socket
import concurrent.futures
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any, Union
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel, HttpUrl
from bs4 import BeautifulSoup

# ── Dependencies ──────────────────────────────────────────────────────────────
try:
    from scrapling.fetchers import Fetcher, StealthyFetcher
    _STEALTH_AVAILABLE = True
except ImportError:
    _STEALTH_AVAILABLE = False

# ── Telegram Hook (Assumes telegram_bot.py exists) ───────────────────────────
_TELEGRAM_AVAILABLE = False
try:
    # Attempt to import your specific bot module
    from telegram_bot import start_bot_thread
    _TELEGRAM_AVAILABLE = True
except ImportError:
    print("[AUDITOR] telegram_bot.py not found. Telegram interface disabled.")

# ═══════════════════════════════════════════════════════════
# GLOBAL EXECUTORS
# ═══════════════════════════════════════════════════════════
# Offload CPU-bound BeautifulSoup parsing to separate processes
cpu_executor = concurrent.futures.ProcessPoolExecutor(max_workers=4)
MAX_PAYLOAD_SIZE = 10_485_760 

# ═══════════════════════════════════════════════════════════
# HARDENED LOGIC ENGINE (PROCESS-ISOLATED)
# ═══════════════════════════════════════════════════════════

def _is_safe_url(url: str) -> bool:
    """SSRF Protection: Block internal/private network access."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'): return False
        hostname = parsed.hostname
        if not hostname: return False
        ip = socket.gethostbyname(hostname)
        ip_int = int.from_bytes(socket.inet_aton(ip), 'big')
        # Private IP Ranges
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
    """Context-aware data cleaning."""
    if not text: return None
    t = text.strip()
    # Financial Regex
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
    """CPU-bound parsing executed in ProcessPoolExecutor."""
    soup = BeautifulSoup(content, 'html.parser')
    for tag in soup(['script', 'style', 'nav', 'footer', 'aside']): tag.decompose()
    
    results = []
    # Table extraction
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
# LIFECYCLE & API
# ═══════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    if _TELEGRAM_AVAILABLE:
        try:
            start_bot_thread()
            print("[AUDITOR] Telegram thread spawned.")
        except Exception as e:
            print(f"[AUDITOR] Telegram Bot fail: {e}")
    yield
    # Shutdown
    cpu_executor.shutdown(wait=True)

app = FastAPI(title="AUDITOR CORE", version="7.2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# Auth Config
_ENV_KEY = os.environ.get("AUDITOR_API_KEY", "").strip()
API_KEY = _ENV_KEY if _ENV_KEY else secrets.token_hex(32)
if not _ENV_KEY: print(f"[BOOT] AUTH KEY: {API_KEY}")

def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="INVALID_API_KEY")

class ScrapePayload(BaseModel):
    url: HttpUrl
    js: bool = False

# ═══════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════

@app.get("/", tags=["Frontend"])
async def serve_frontend():
    """Corrected frontend resolution logic."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(base_dir, "index.html")
    
    if os.path.exists(html_path):
        return FileResponse(html_path)
    
    return HTMLResponse(
        content=f"<h2>404: Frontend Missing</h2><p>Expected index.html at: {html_path}</p>", 
        status_code=404
    )

@app.post("/api/scrape", dependencies=[Depends(require_api_key)])
async def api_scrape(payload: ScrapePayload):
    target = str(payload.url)
    if not _is_safe_url(target):
        raise HTTPException(status_code=403, detail="FORBIDDEN_DOMAIN")

    loop = asyncio.get_event_loop()
    
    # 1. Threaded Fetch (I/O Bound)
    try:
        if payload.js:
            if not _STEALTH_AVAILABLE: raise ValueError("Stealth engine unavailable")
            response = await loop.run_in_executor(None, lambda: StealthyFetcher.fetch(target, headless=True, network_idle=True))
        else:
            response = await loop.run_in_executor(None, lambda: Fetcher().get(target))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"FETCH_ERROR: {str(e)}")

    if not response or not hasattr(response, 'content'):
        raise HTTPException(status_code=502, detail="EMPTY_RESPONSE")

    if len(response.content) > MAX_PAYLOAD_SIZE:
        raise HTTPException(status_code=413, detail="PAYLOAD_TOO_LARGE")

    # 2. Process-Isolated Parse (CPU Bound)
    data = await loop.run_in_executor(cpu_executor, _extract_worker, response.content)

    return {
        "status": "COMPLETED",
        "url": target,
        "clean_count": len(data),
        "data": data
    }

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
