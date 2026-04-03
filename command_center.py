import os
import re
import time
import secrets
import asyncio
import socket
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List, Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel
from bs4 import BeautifulSoup

# ── Scrapling import ──────────────────────────────────────────────────────────
try:
    from scrapling.fetchers import Fetcher, StealthyFetcher
    _STEALTH_AVAILABLE = True
    _FETCHER_AVAILABLE = True
except ImportError:
    try:
        from scrapling import Fetcher
        _FETCHER_AVAILABLE = True
    except ImportError:
        Fetcher = None
        _FETCHER_AVAILABLE = False
    StealthyFetcher = None
    _STEALTH_AVAILABLE = False

print(f"[BOOT] Fetcher available: {_FETCHER_AVAILABLE}, Stealth available: {_STEALTH_AVAILABLE}")

# ═══════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════
cpu_executor     = concurrent.futures.ProcessPoolExecutor(max_workers=4)
MAX_PAYLOAD_SIZE = 10_485_760  # 10 MB

# ═══════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════
_ENV_KEY = os.environ.get("AUDITOR_API_KEY", "").strip()
API_KEY  = _ENV_KEY if _ENV_KEY else secrets.token_hex(32)
if not _ENV_KEY:
    print(f"[BOOT] No AUDITOR_API_KEY env var — generated key: {API_KEY}")

def verify_key(x_api_key: str = Header(..., alias="X-Api-Key")) -> str:
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
# SECURITY
# ═══════════════════════════════════════════════════════════
def _is_safe_url(url: str) -> bool:
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
            (0x0A000000, 0xFF000000),
            (0xAC100000, 0xFFF00000),
            (0xC0A80000, 0xFFFF0000),
            (0x7F000000, 0xFF000000),
            (0xA9FE0000, 0xFFFF0000),
            (0x00000000, 0xFF000000),
        ]
        return not any((ip_int & mask) == (net & mask) for net, mask in private_blocks)
    except Exception:
        return False

def _sanitize_key(text: str) -> str:
    clean = re.sub(r'[^a-zA-Z0-9]', '_', text.strip())
    return re.sub(r'_+', '_', clean).strip('_').lower()[:64]

# ═══════════════════════════════════════════════════════════
# RAW CONTENT EXTRACTION FROM SCRAPLING RESPONSE
# ═══════════════════════════════════════════════════════════
def _get_raw_bytes(response) -> bytes:
    """
    Extract raw HTML bytes from a Scrapling Adaptor object.
    Tries attributes in priority order — raises ValueError if nothing usable is found.
    """
    # 1. .html — primary Scrapling attribute (str)
    html = getattr(response, 'html', None)
    if html and isinstance(html, str) and len(html.strip()) > 0:
        return html.encode('utf-8', errors='replace')

    # 2. .text — alias used in some Scrapling versions
    text = getattr(response, 'text', None)
    if text and isinstance(text, str) and len(text.strip()) > 0:
        return text.encode('utf-8', errors='replace')

    # 3. .content — raw bytes (may be populated in some fetcher modes)
    content = getattr(response, 'content', None)
    if content and isinstance(content, bytes) and len(content) > 0:
        return content

    # 4. .body — fallback used by some Scrapling versions
    body = getattr(response, 'body', None)
    if body:
        if isinstance(body, bytes) and len(body) > 0:
            return body
        if isinstance(body, str) and len(body.strip()) > 0:
            return body.encode('utf-8', errors='replace')

    raise ValueError(
        f"Scrapling response returned no usable content. "
        f"Available attrs: {[a for a in dir(response) if not a.startswith('_')]}"
    )

# ═══════════════════════════════════════════════════════════
# EXTRACTION WORKER (top-level for ProcessPoolExecutor pickling)
# ═══════════════════════════════════════════════════════════

def _cell_label(cell, index: int) -> str:
    """
    Universal header label extractor for a single <th> or <td> cell.
    Tries text content → aria-label → title → data-* values → positional fallback.
    Works on any site regardless of whether headers use icons, spans, or plain text.
    """
    # 1. Visible text (strips all child tags)
    text = cell.get_text(separator=' ', strip=True)
    key  = _sanitize_key(text)
    if key:
        return key

    # 2. aria-label (common in icon-heavy tables like CoinGlass)
    aria = cell.get('aria-label', '').strip()
    key  = _sanitize_key(aria)
    if key:
        return key

    # 3. title attribute
    title = cell.get('title', '').strip()
    key   = _sanitize_key(title)
    if key:
        return key

    # 4. Any data-* attribute value (e.g. data-column, data-key, data-field)
    for attr, val in cell.attrs.items():
        if attr.startswith('data-') and isinstance(val, str):
            key = _sanitize_key(val)
            if key:
                return key

    # 5. Check nested elements for any non-empty text (catches icon + hidden span patterns)
    for child in cell.descendants:
        if hasattr(child, 'get_text'):
            nested = _sanitize_key(child.get_text(strip=True))
            if nested:
                return nested

    # 6. Positional fallback
    return f"col_{index}"


def _find_headers(table) -> tuple[list, list]:
    """
    Robustly locate header row and data rows for any table structure.
    Returns (headers: list[str], data_rows: list[Tag]).
    """
    all_rows = table.find_all('tr')
    if not all_rows:
        return [], []

    def score_row(row):
        """Higher score = better header candidate (more named, fewer positional cols)."""
        cells = row.find_all(['th', 'td'])
        if not cells:
            return -1, cells
        labels   = [_cell_label(c, i) for i, c in enumerate(cells)]
        named    = sum(1 for l in labels if not l.startswith('col_'))
        return named, cells

    # --- Try <thead> first ---
    thead = table.find('thead')
    if thead:
        thead_rows = thead.find_all('tr')
        if thead_rows:
            best_score, best_cells = -1, None
            for row in thead_rows:
                score, cells = score_row(row)
                if score > best_score and cells:
                    best_score, best_cells = score, cells
            if best_cells is not None:
                headers   = [_cell_label(c, i) for i, c in enumerate(best_cells)]
                tbody = table.find('tbody')
                data_rows = tbody.find_all('tr') if tbody else [
                    r for r in all_rows if r not in thead_rows
                ]
                return headers, data_rows

    # --- No thead: scan all rows for the best header candidate ---
    th_rows     = [r for r in all_rows if r.find('th')]
    candidates  = th_rows if th_rows else all_rows

    best_score, best_idx, best_cells = -1, 0, None
    for idx, row in enumerate(candidates):
        score, cells = score_row(row)
        if score > best_score and cells:
            best_score, best_idx, best_cells = score, idx, cells

    if best_cells is None:
        return [], []

    headers   = [_cell_label(c, i) for i, c in enumerate(best_cells)]
    actual_idx = all_rows.index(candidates[best_idx])
    data_rows  = all_rows[actual_idx + 1:]
    return headers, data_rows


def _extract_worker(content: bytes) -> List[Dict[str, Any]]:
    """
    Parses HTML bytes and extracts all <table> rows as dicts with semantic column names.
    Pure function — safe to run in a subprocess.
    """
    soup = BeautifulSoup(content, 'html.parser')
    for tag in soup(['script', 'style', 'nav', 'footer', 'aside']):
        tag.decompose()

    results = []
    for table in soup.find_all('table'):
        headers, data_rows = _find_headers(table)
        if not headers:
            continue

        for row in data_rows:
            cells = row.find_all(['td', 'th'])
            if not cells:
                continue
            if len(cells) > len(headers):
                continue
            record = {
                headers[i]: c.get_text(separator=' ', strip=True)
                for i, c in enumerate(cells)
            }
            if any(v for v in record.values()):
                results.append(record)

    return results

# ═══════════════════════════════════════════════════════════
# FETCH WRAPPERS
# ═══════════════════════════════════════════════════════════
def _fetch_static(url: str):
    if Fetcher is None:
        raise RuntimeError("Scrapling Fetcher is not installed.")
    try:
        response = Fetcher().get(url)
    except Exception as e:
        raise RuntimeError(f"Fetcher.get() failed: {e}") from e
    if response is None:
        raise RuntimeError("Fetcher.get() returned None — URL may be unreachable or blocked.")
    return response

def _fetch_js(url: str):
    if not _STEALTH_AVAILABLE or StealthyFetcher is None:
        raise RuntimeError(
            "StealthyFetcher unavailable — run: "
            "pip install scrapling[all] --break-system-packages && scrapling install"
        )
    try:
        response = StealthyFetcher.fetch(url, headless=True)
    except Exception as e:
        raise RuntimeError(f"StealthyFetcher.fetch() failed: {e}") from e
    if response is None:
        raise RuntimeError("StealthyFetcher.fetch() returned None — URL may be unreachable or blocked.")
    return response

# ═══════════════════════════════════════════════════════════
# CORE SCRAPE LOGIC
# ═══════════════════════════════════════════════════════════
async def _scrape_url(url: str, js: bool = False) -> tuple[List[Dict[str, Any]], int]:
    if not _is_safe_url(url):
        raise HTTPException(
            status_code=403,
            detail="FORBIDDEN_DOMAIN — private/loopback addresses are blocked."
        )

    loop = asyncio.get_running_loop()

    # ── Fetch ──────────────────────────────────────────────
    try:
        if js:
            response = await loop.run_in_executor(None, _fetch_js, url)
        else:
            response = await loop.run_in_executor(None, _fetch_static, url)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))

    # ── Extract raw bytes from Scrapling response ──────────
    try:
        raw = _get_raw_bytes(response)
    except ValueError as e:
        raise HTTPException(status_code=502, detail=str(e))

    raw_bytes = len(raw)
    print(f"[SCRAPE] {url} → {raw_bytes} bytes fetched (js={js})")

    if raw_bytes == 0:
        raise HTTPException(status_code=502, detail="Fetcher returned empty body — page may require JS rendering (enable JS context) or is blocking scrapers.")

    if raw_bytes > MAX_PAYLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Payload too large ({raw_bytes / 1_048_576:.1f} MB > 10 MB limit)."
        )

    # ── Parse tables ───────────────────────────────────────
    try:
        rows = await loop.run_in_executor(cpu_executor, _extract_worker, raw)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Table extraction failed: {e}")

    print(f"[SCRAPE] {url} → {len(rows)} rows extracted")
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

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    errors = "; ".join(
        f"{' → '.join(str(l) for l in e['loc'])}: {e['msg']}"
        for e in exc.errors()
    )
    return JSONResponse(status_code=422, content={"detail": f"Validation error — {errors}"})

# ── Frontend ──────────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def serve_frontend():
    base_dir  = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(base_dir, "index.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    return HTMLResponse(
        content=f"<h2>404 — index.html not found at {html_path}</h2>",
        status_code=404,
    )

# ── Key ───────────────────────────────────────────────────────────────────────
@app.get("/api/key")
async def get_api_key():
    return JSONResponse({"api_key": API_KEY})

# ── Health ─────────────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {
        "status":              "ok",
        "version":             "7.5.0",
        "fetcher_available":   _FETCHER_AVAILABLE,
        "stealth_available":   _STEALTH_AVAILABLE,
        "utc":                 datetime.now(timezone.utc).isoformat(),
    }

# ── Debug endpoint — test fetcher directly, returns content preview ───────────
@app.get("/api/debug-fetch")
async def debug_fetch(url: str, _key: str = Depends(verify_key)):
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="FORBIDDEN_DOMAIN")
    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(None, _fetch_static, url)
        raw = _get_raw_bytes(response)
        return {
            "url":        url,
            "raw_bytes":  len(raw),
            "preview":    raw[:500].decode('utf-8', errors='replace'),
            "attrs_found": [a for a in dir(response) if not a.startswith('_') and not callable(getattr(response, a, None))],
        }
    except Exception as e:
        return {"url": url, "error": str(e)}

# ── Scrape ─────────────────────────────────────────────────────────────────────
@app.post("/api/scrape", response_model=ScrapeResponse)
async def scrape(
    body: ScrapeRequest,
    _key: str = Depends(verify_key),
):
    t0 = time.perf_counter()
    rows, raw_bytes = await _scrape_url(body.url, js=body.js)
    elapsed = round(time.perf_counter() - t0, 3)
    return ScrapeResponse(events=rows, raw_bytes=raw_bytes, elapsed=elapsed)

# ── Token status ───────────────────────────────────────────────────────────────
@app.get("/api/token-status")
async def token_status(_key: str = Depends(verify_key)):
    return {
        "limit_per_key": 100_000,
        "keys": [
            {"key_index": 1, "tokens_used": 15_400, "tokens_remaining": 84_600, "active": True}
        ],
    }

# ═══════════════════════════════════════════════════════════
# TELEGRAM BOT LIFESPAN (replaces old @app.on_event)
# ═══════════════════════════════════════════════════════════
from telegram_bot import telegram_lifespan  # must be the corrected version
app.router.lifespan_context = telegram_lifespan

# ═══════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
    )
