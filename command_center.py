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
from bs4 import BeautifulSoup, Tag

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

def _clean_header(text: str) -> str:
    """Clean raw header text to a readable key."""
    if not text:
        return None
    # Remove special characters, collapse spaces
    cleaned = re.sub(r'[^\w\s]', ' ', text)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    # Capitalise each word
    cleaned = ' '.join(word.capitalize() for word in cleaned.split())
    # Truncate
    return cleaned[:50] if cleaned else None

# ═══════════════════════════════════════════════════════════
# RAW CONTENT EXTRACTION FROM SCRAPLING RESPONSE
# ═══════════════════════════════════════════════════════════
def _get_raw_bytes(response) -> bytes:
    html = getattr(response, 'html', None)
    if html and isinstance(html, str) and len(html.strip()) > 0:
        return html.encode('utf-8', errors='replace')
    text = getattr(response, 'text', None)
    if text and isinstance(text, str) and len(text.strip()) > 0:
        return text.encode('utf-8', errors='replace')
    content = getattr(response, 'content', None)
    if content and isinstance(content, bytes) and len(content) > 0:
        return content
    body = getattr(response, 'body', None)
    if body:
        if isinstance(body, bytes) and len(body) > 0:
            return body
        if isinstance(body, str) and len(body.strip()) > 0:
            return body.encode('utf-8', errors='replace')
    raise ValueError("No usable content found in Scrapling response")

# ═══════════════════════════════════════════════════════════
# UNIVERSAL TABLE EXTRACTION (FINAL)
# ═══════════════════════════════════════════════════════════

def _get_cell_text(cell: Tag) -> str:
    """Extract visible text, ignoring scripts/styles."""
    for unwanted in cell(['script', 'style']):
        unwanted.decompose()
    return cell.get_text(separator=' ', strip=True)

def _extract_header_from_cell(cell: Tag, index: int) -> str:
    """Try to get a meaningful header name from any cell."""
    # 1. aria-label (common on CoinGlass)
    aria = cell.get('aria-label', '').strip()
    if aria:
        cleaned = _clean_header(aria)
        if cleaned:
            return cleaned
    # 2. title attribute
    title = cell.get('title', '').strip()
    if title:
        cleaned = _clean_header(title)
        if cleaned:
            return cleaned
    # 3. visible text
    text = _get_cell_text(cell)
    if text:
        cleaned = _clean_header(text)
        if cleaned:
            return cleaned
    # 4. any data-* attribute
    for attr, val in cell.attrs.items():
        if attr.startswith('data-') and isinstance(val, str) and val.strip():
            cleaned = _clean_header(val)
            if cleaned:
                return cleaned
    # 5. fallback: None (will be filled later)
    return None

def _is_likely_header_row(row: Tag) -> bool:
    """Heuristic: a row is likely a header if it contains <th> or its text has common header words."""
    if row.find('th'):
        return True
    cells = row.find_all(['td', 'th'])
    if not cells:
        return False
    text = ' '.join(_get_cell_text(c) for c in cells[:4]).lower()
    header_keywords = ['exchange', 'open interest', 'btc', 'usd', 'dominance', 'change', 'funding',
                       'date', 'time', 'event', 'actual', 'previous', 'forecast', 'country', 'currency']
    return any(kw in text for kw in header_keywords)

def _expand_rowspan_headers(rows: List[Tag]) -> List[List[str]]:
    """
    Expand a list of header rows (each row is a list of cell texts) into a flat list of column headers,
    respecting rowspan and colspan.
    Returns a 2D matrix of header texts (rows x columns), which can then be merged.
    """
    if not rows:
        return []
    # Determine max columns by scanning all rows with colspan expansion
    max_cols = 0
    row_span_tracker = []  # list of dicts per row? Actually easier: process sequentially
    # We'll build a matrix row by row
    matrix = []
    active_spans = []  # list of (col_index, remaining_rows, header_text)
    for row in rows:
        cells = row.find_all(['th', 'td'])
        row_cells = []
        col_idx = 0
        for cell in cells:
            # Skip columns already occupied by a rowspan from previous rows
            while active_spans and active_spans[0][0] == col_idx:
                span_col, remaining, text = active_spans.pop(0)
                row_cells.append(text)
                if remaining > 1:
                    active_spans.append((span_col, remaining - 1, text))
                col_idx += 1
            # Get header text for this cell
            header_text = _extract_header_from_cell(cell, col_idx)
            if not header_text:
                header_text = f"Column_{col_idx+1}"
            colspan = int(cell.get('colspan', 1))
            rowspan = int(cell.get('rowspan', 1))
            for _ in range(colspan):
                row_cells.append(header_text)
                if rowspan > 1:
                    # Insert at correct position (maintain order)
                    active_spans.append((col_idx, rowspan - 1, header_text))
                col_idx += 1
        # After row, fill any remaining active spans that started before this row
        while active_spans:
            span_col, remaining, text = active_spans.pop(0)
            row_cells.append(text)
            if remaining > 1:
                active_spans.append((span_col, remaining - 1, text))
            # Note: this may misalign if spans are interleaved; but for most tables it's fine.
        matrix.append(row_cells)
        max_cols = max(max_cols, len(row_cells))
    # Pad all rows to same length
    for i in range(len(matrix)):
        if len(matrix[i]) < max_cols:
            matrix[i].extend([''] * (max_cols - len(matrix[i])))
    return matrix

def _merge_header_rows(header_matrix: List[List[str]]) -> List[str]:
    """
    Merge a 2D header matrix (rows x columns) into a single list of column headers.
    Takes the first non-empty cell in each column, preferring lower rows if higher rows are empty.
    """
    if not header_matrix:
        return []
    num_cols = len(header_matrix[0])
    final_headers = []
    for col in range(num_cols):
        header = ''
        # Go from bottom row to top (prefer most specific)
        for row in reversed(header_matrix):
            if row[col] and row[col] != 'Column_?':
                header = row[col]
                break
        if not header:
            # Fallback to generic
            header = f"Column_{col+1}"
        final_headers.append(header)
    return final_headers

def _get_table_headers(table: Tag) -> List[str]:
    """
    Extract column headers from any table, handling thead, th, and heuristic detection.
    """
    # 1. Try to use <thead>
    thead = table.find('thead')
    if thead:
        header_rows = thead.find_all('tr')
        if header_rows:
            matrix = _expand_rowspan_headers(header_rows)
            headers = _merge_header_rows(matrix)
            if headers:
                return headers

    # 2. Try to find a row that contains <th> or looks like a header
    all_rows = table.find_all('tr')
    candidate_rows = []
    for row in all_rows:
        if _is_likely_header_row(row):
            candidate_rows.append(row)
    if candidate_rows:
        matrix = _expand_rowspan_headers(candidate_rows)
        headers = _merge_header_rows(matrix)
        if headers:
            return headers

    # 3. Last resort: use the first row as header (but try to clean it)
    if all_rows:
        first_row = all_rows[0]
        cells = first_row.find_all(['td', 'th'])
        headers = []
        for i, cell in enumerate(cells):
            text = _get_cell_text(cell)
            cleaned = _clean_header(text)
            if cleaned:
                headers.append(cleaned)
            else:
                headers.append(f"Column_{i+1}")
        return headers

    return []

def _extract_worker(content: bytes) -> List[Dict[str, Any]]:
    """
    Parse HTML and extract all tables as list of dicts.
    """
    soup = BeautifulSoup(content, 'html.parser')
    # Remove noise
    for tag in soup(['script', 'style', 'nav', 'footer', 'aside', 'header']):
        tag.decompose()

    results = []
    for table in soup.find_all('table'):
        headers = _get_table_headers(table)
        if not headers:
            continue

        # Identify data rows: skip rows used as headers
        # We'll take all rows after the last header row we used
        all_rows = table.find_all('tr')
        # Find the index of the last row that was part of header detection
        # Simple approach: skip rows that contain <th> or are marked as header
        data_rows = []
        for row in all_rows:
            if _is_likely_header_row(row):
                continue  # skip header rows
            # Also skip rows that have very few cells (sometimes decorative)
            cells = row.find_all(['td', 'th'])
            if len(cells) < len(headers) // 2:
                continue
            data_rows.append(row)

        for row in data_rows:
            cells = row.find_all(['td', 'th'])
            if not cells:
                continue
            record = {}
            for i, cell in enumerate(cells):
                if i >= len(headers):
                    break
                text = _get_cell_text(cell)
                if text:
                    record[headers[i]] = text
            if record:
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
# CORE SCRAPE LOGIC (exposed for telegram bot)
# ═══════════════════════════════════════════════════════════
async def _scrape_url(url: str, js: bool = False) -> tuple[List[Dict[str, Any]], int]:
    if not _is_safe_url(url):
        raise HTTPException(
            status_code=403,
            detail="FORBIDDEN_DOMAIN — private/loopback addresses are blocked."
        )
    loop = asyncio.get_running_loop()
    try:
        if js:
            response = await loop.run_in_executor(None, _fetch_js, url)
        else:
            response = await loop.run_in_executor(None, _fetch_static, url)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
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
    base_dir = os.path.dirname(os.path.abspath(__file__))
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
        "status": "ok",
        "version": "7.5.0",
        "fetcher_available": _FETCHER_AVAILABLE,
        "stealth_available": _STEALTH_AVAILABLE,
        "utc": datetime.now(timezone.utc).isoformat(),
    }

# ── Debug endpoint ───────────────────────────────────────────────────────────
@app.get("/api/debug-fetch")
async def debug_fetch(url: str, _key: str = Depends(verify_key)):
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="FORBIDDEN_DOMAIN")
    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(None, _fetch_static, url)
        raw = _get_raw_bytes(response)
        return {
            "url": url,
            "raw_bytes": len(raw),
            "preview": raw[:500].decode('utf-8', errors='replace'),
            "attrs_found": [a for a in dir(response) if not a.startswith('_') and not callable(getattr(response, a, None))],
        }
    except Exception as e:
        return {"url": url, "error": str(e)}

# ── Scrape endpoint ──────────────────────────────────────────────────────────
@app.post("/api/scrape", response_model=ScrapeResponse)
async def scrape(
    body: ScrapeRequest,
    _key: str = Depends(verify_key),
):
    t0 = time.perf_counter()
    rows, raw_bytes = await _scrape_url(body.url, js=body.js)
    elapsed = round(time.perf_counter() - t0, 3)
    return ScrapeResponse(events=rows, raw_bytes=raw_bytes, elapsed=elapsed)

# ── Token status (mock) ──────────────────────────────────────────────────────
@app.get("/api/token-status")
async def token_status(_key: str = Depends(verify_key)):
    return {
        "limit_per_key": 100_000,
        "keys": [
            {"key_index": 1, "tokens_used": 15_400, "tokens_remaining": 84_600, "active": True}
        ],
    }

# ═══════════════════════════════════════════════════════════
# TELEGRAM BOT STARTUP & SHUTDOWN (thread‑based)
# ═══════════════════════════════════════════════════════════
@app.on_event("startup")
async def startup_telegram():
    try:
        from telegram_bot import start_bot
        start_bot()
        print("[BOOT] Telegram bot started.")
    except ImportError:
        print("[BOOT] telegram_bot.py not found — skipping.")
    except Exception as e:
        print(f"[BOOT] Telegram bot failed: {e}")

@app.on_event("shutdown")
async def shutdown_telegram():
    try:
        from telegram_bot import stop_bot
        stop_bot()
    except ImportError:
        pass

# ═══════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
    )
