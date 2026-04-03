import os
import re
import secrets
import asyncio
import socket
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel
from bs4 import BeautifulSoup

# ── Dependencies ──────────────────────────────────────────────────────────────
try:
    from scrapling.fetchers import Fetcher, StealthyFetcher
    _STEALTH_AVAILABLE = True
except ImportError:
    try:
        from scrapling import Fetcher
    except ImportError:
        Fetcher = None
    StealthyFetcher = None
    _STEALTH_AVAILABLE = False

# ═══════════════════════════════════════════════════════════
# GLOBAL EXECUTOR & CONFIG
# ═══════════════════════════════════════════════════════════
cpu_executor = concurrent.futures.ProcessPoolExecutor(max_workers=4)
MAX_PAYLOAD_SIZE = 10_485_760  # 10 MB

# ═══════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════
_ENV_KEY = os.environ.get("AUDITOR_API_KEY", "").strip()
API_KEY  = _ENV_KEY if _ENV_KEY else secrets.token_hex(32)
if not _ENV_KEY:
    print(f"[BOOT] No AUDITOR_API_KEY set — generated key: {API_KEY}")

def verify_key(x_api_key: str = Header(..., alias="X-Api-Key")) -> str:
    """FastAPI dependency — validates X-Api-Key header on every protected route."""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return x_api_key

# ═══════════════════════════════════════════════════════════
# REQUEST / RESPONSE MODELS
# ═══════════════════════════════════════════════════════════
class ScrapeRequest(BaseModel):
    url:      str
    adaptive: bool = True
    js:       bool = False

class ScrapeResponse(BaseModel):
    events:    List[Dict[str, Any]]
    raw_bytes: int
    elapsed:   float

# ═══════════════════════════════════════════════════════════
# SECURITY UTILITIES
# ═══════════════════════════════════════════════════════════
def _is_safe_url(url: str) -> bool:
    """Blocks private/loopback IPs (SSRF protection)."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        ip = socket.gethostbyname(hostname)
        ip_int = int.from_bytes(socket.inet_aton(ip), 'big')
        private_blocks = [
            (0x0A000000, 0xFF000000),  # 10.0.0.0/8
            (0xAC100000, 0xFFF00000),  # 172.16.0.0/12
            (0xC0A80000, 0xFFFF0000),  # 192.168.0.0/16
            (0x7F000000, 0xFF000000),  # 127.0.0.0/8
            (0xA9FE0000, 0xFFFF0000),  # 169.254.0.0/16
            (0x00000000, 0xFF000000),  # 0.0.0.0/8
        ]
        return not any((ip_int & mask) == (net & mask) for net, mask in private_blocks)
    except Exception:
        return False

def _sanitize_key(text: str) -> str:
    clean = re.sub(r'[^a-zA-Z0-9]', '_', text.strip())
    return re.sub(r'_+', '_', clean).strip('_').lower()[:64]

# ═══════════════════════════════════════════════════════════
# EXTRACTION WORKER (runs in ProcessPoolExecutor)
# ═══════════════════════════════════════════════════════════
def _extract_worker(content: bytes) -> List[Dict[str, Any]]:
    """
    Pure-function HTML table extractor — safe to run in a subprocess.
    Returns a flat list of row dicts, one dict per table row.
    """
    soup = BeautifulSoup(content, 'html.parser')
    for tag in soup(['script', 'style', 'nav', 'footer', 'aside']):
        tag.decompose()

    results = []
    for table in soup.find_all('table'):
        rows = table.find_all('tr')
        if not rows:
            continue
        headers = [
            _sanitize_key(th.get_text(strip=True)) or f"col_{i}"
            for i, th in enumerate(rows[0].find_all(['th', 'td']))
        ]
        if not headers:
            continue
        for row in rows[1:]:
            cells = row.find_all(['td', 'th'])
            if len(cells) != len(headers):
                continue
            results.append({headers[i]: c.get_text(strip=True) for i, c in enumerate(cells)})
    return results

# ═══════════════════════════════════════════════════════════
# CORE SCRAPE LOGIC
# ═══════════════════════════════════════════════════════════
async def _scrape_url(url: str, js: bool = False) -> tuple[List[Dict[str, Any]], int]:
    """
    Fetches `url` with Scrapling (static or headless) and extracts tables.
    Returns (rows, raw_byte_count).
    """
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="FORBIDDEN_DOMAIN — private/loopback addresses are not allowed.")

    loop = asyncio.get_running_loop()  # FIX: get_event_loop() deprecated in 3.10+

    if js:
        if not _STEALTH_AVAILABLE:
            raise HTTPException(status_code=501, detail="StealthyFetcher unavailable — run: pip install scrapling[all] && scrapling install")
        response = await loop.run_in_executor(
            None, lambda: StealthyFetcher.fetch(url, headless=True)
        )
    else:
        if Fetcher is None:
            raise HTTPException(status_code=501, detail="Scrapling is not installed.")
        response = await loop.run_in_executor(
            None, lambda: Fetcher().get(url)
        )

    if not response or not hasattr(response, 'content'):
        return [], 0

    raw_bytes = len(response.content)
    if raw_bytes > MAX_PAYLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"Payload too large ({raw_bytes} bytes > {MAX_PAYLOAD_SIZE}).")

    rows = await loop.run_in_executor(cpu_executor, _extract_worker, response.content)
    return rows, raw_bytes

# ═══════════════════════════════════════════════════════════
# APP
# ═══════════════════════════════════════════════════════════
app = FastAPI(title="AUDITOR CORE", version="7.5.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Frontend ──────────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def serve_frontend():
    base_dir  = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(base_dir, "index.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    return HTMLResponse(
        content=f"<h2>404: index.html not found at {html_path}</h2>",
        status_code=404,
    )

# ── Auth info (used by frontend on load) ─────────────────────────────────────
@app.get("/api/key")
async def get_api_key():
    """
    Returns the active API key so the frontend can auto-populate its key field.
    Only expose this endpoint on trusted networks / behind auth proxy in production.
    """
    return JSONResponse({"api_key": API_KEY})

# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {
        "status":            "ok",
        "version":           "7.5.0",
        "stealth_available": _STEALTH_AVAILABLE,
        "scrapling_available": Fetcher is not None,
        "utc":               datetime.now(timezone.utc).isoformat(),
    }

# ── Main extraction endpoint ──────────────────────────────────────────────────
@app.post("/api/scrape", response_model=ScrapeResponse)
async def scrape(
    body:    ScrapeRequest,
    _key:    str = Depends(verify_key),   # enforces X-Api-Key header
):
    """
    Scrapes `body.url` and returns extracted table rows as `events`.

    - `js: false`  → Scrapling Fetcher (fast, static pages)
    - `js: true`   → StealthyFetcher / Playwright (JS-rendered pages)
    """
    t0 = asyncio.get_event_loop().time()

    rows, raw_bytes = await _scrape_url(body.url, js=body.js)

    elapsed = asyncio.get_event_loop().time() - t0

    return ScrapeResponse(
        events=rows,
        raw_bytes=raw_bytes,
        elapsed=round(elapsed, 3),
    )

# ── Token status (Telegram dashboard helper) ──────────────────────────────────
@app.get("/api/token-status")
async def token_status(_key: str = Depends(verify_key)):
    return {
        "limit_per_key": 100_000,
        "keys": [
            {"key_index": 1, "tokens_used": 15_400, "tokens_remaining": 84_600, "active": True}
        ],
    }

# ═══════════════════════════════════════════════════════════
# STARTUP — Telegram bot (optional, won't crash server if absent)
# ═══════════════════════════════════════════════════════════
@app.on_event("startup")
async def startup():
    try:
        from telegram_bot import start_bot
        start_bot()
        print("[BOOT] Telegram bot started.")
    except ImportError:
        print("[BOOT] telegram_bot.py not found — skipping bot startup.")
    except Exception as e:
        print(f"[BOOT] Telegram bot failed to start: {e}")

# ═══════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
    )
