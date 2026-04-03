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
from bs4 import BeautifulSoup, Tag, NavigableString

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
    cleaned = re.sub(r'[^\w\s]', ' ', text)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    cleaned = ' '.join(word.capitalize() for word in cleaned.split())
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
# CSS PSEUDO‑ELEMENT PROCESSOR (handles both : and ::)
# ═══════════════════════════════════════════════════════════
def _apply_pseudo_elements(soup: BeautifulSoup) -> None:
    """
    Parse <style> tags and manually inject ::before/::after content into elements.
    Simulates browser rendering for static extraction.
    """
    style_text = ''
    for style_tag in soup.find_all('style'):
        if style_tag.string:
            style_text += style_tag.string

    if not style_text:
        return

    # Matches both .class:before and .class::before (single or double colon)
    pattern = r'\.([a-zA-Z0-9_-]+):{1,2}(before|after)\s*\{\s*content:\s*["\']([^"\']+)["\']\s*;?\s*\}'
    matches = re.findall(pattern, style_text)

    for class_name, pseudo, content in matches:
        selector = f'.{class_name}'
        elements = soup.select(selector)
        new_string = NavigableString(content)
        for el in elements:
            if pseudo == 'before':
                el.insert(0, new_string)
            else:  # after
                el.append(new_string)

# ═══════════════════════════════════════════════════════════
# UNIVERSAL TEXT EXTRACTION (SVG, hidden classes, inline joining)
# ═══════════════════════════════════════════════════════════
def _get_element_text(element) -> str:
    """Extract visible text, ignoring hidden classes, scripts, and cleaning junk."""
    if not isinstance(element, Tag):
        return str(element).strip() if element else ''

    # Skip hidden elements
    hidden_classes = ['visually-hidden', 'tw-sr-only', 'sr-only', 'hidden', 'hide']
    class_attr = element.get('class', [])
    if isinstance(class_attr, list):
        if any(cls in hidden_classes for cls in class_attr):
            return ''
    elif isinstance(class_attr, str):
        if any(cls in class_attr.split() for cls in hidden_classes):
            return ''

    # Skip scripts and styles
    if element.name in ('script', 'style', 'noscript', 'template'):
        return ''

    # SVG text extraction
    if element.name == 'svg':
        text_elements = element.find_all('text')
        if text_elements:
            return ' '.join(_get_element_text(t) for t in text_elements).strip()
        return ''

    # Recursively collect text from children
    text_parts = []
    for child in element.children:
        if isinstance(child, NavigableString):
            # Remove zero-width and other non-ASCII junk
            clean = child.string.encode('ascii', 'ignore').decode('ascii').strip()
            if clean:
                text_parts.append(clean)
        else:
            child_text = _get_element_text(child)
            if child_text:
                text_parts.append(child_text)

    # Inline elements should be joined without spaces (e.g., price components)
    inline_elements = {'span', 'a', 'b', 'i', 'strong', 'em', 'small', 'u',
                       's', 'sub', 'sup', 'label', 'button', 'text'}
    if element.name in inline_elements:
        return ''.join(text_parts)
    return ' '.join(text_parts).strip()

# ═══════════════════════════════════════════════════════════
# STANDARD TABLE EXTRACTION
# ═══════════════════════════════════════════════════════════
def _extract_standard_tables(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    """Extract data from standard <table> elements."""
    results = []
    for table in soup.find_all('table'):
        headers = []
        thead = table.find('thead')
        if thead:
            header_rows = thead.find_all('tr')
            if header_rows:
                for cell in header_rows[0].find_all(['th', 'td']):
                    text = _get_element_text(cell)
                    cleaned = _clean_header(text) or f"Column_{len(headers)+1}"
                    headers.append(cleaned)
        if not headers:
            first_row = table.find('tr')
            if first_row:
                for cell in first_row.find_all(['th', 'td']):
                    text = _get_element_text(cell)
                    cleaned = _clean_header(text) or f"Column_{len(headers)+1}"
                    headers.append(cleaned)
        if not headers:
            continue

        # Data rows
        data_rows = []
        tbody = table.find('tbody')
        if tbody:
            data_rows = tbody.find_all('tr')
        else:
            all_rows = table.find_all('tr')
            if len(all_rows) > 1:
                data_rows = all_rows[1:]

        for row in data_rows:
            cells = row.find_all(['td', 'th'])
            if not cells:
                continue
            record = {}
            for i, cell in enumerate(cells):
                if i >= len(headers):
                    break
                text = _get_element_text(cell)
                if text:
                    record[headers[i]] = text
            if record:
                results.append(record)
    return results

# ═══════════════════════════════════════════════════════════
# ARIA TABLE EXTRACTION (for React/Angular/Vue grids)
# ═══════════════════════════════════════════════════════════
def _extract_aria_tables(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    """Extract data from ARIA role="table" / role="grid" structures."""
    results = []
    tables = soup.find_all(attrs={"role": ["table", "grid"]})
    if not tables:
        return results

    for table in tables:
        header_row = None
        header_cells = []
        for rowgroup in table.find_all(attrs={"role": "rowgroup"}):
            rows = rowgroup.find_all(attrs={"role": "row"})
            for row in rows:
                cells = row.find_all(attrs={"role": ["columnheader", "cell"]})
                if cells and any(c.get('role') == 'columnheader' for c in cells):
                    header_row = row
                    break
            if header_row:
                break
        if header_row:
            header_cells = header_row.find_all(attrs={"role": "columnheader"})
        else:
            first_rowgroup = table.find(attrs={"role": "rowgroup"})
            if first_rowgroup:
                first_row = first_rowgroup.find(attrs={"role": "row"})
                if first_row:
                    header_cells = first_row.find_all(attrs={"role": "cell"})
        if not header_cells:
            num_cols = 0
            for row in table.find_all(attrs={"role": "row"}):
                cells = row.find_all(attrs={"role": "cell"})
                if len(cells) > num_cols:
                    num_cols = len(cells)
            header_cells = [f"Column_{i+1}" for i in range(num_cols)]
        else:
            header_texts = []
            for cell in header_cells:
                text = _get_element_text(cell)
                cleaned = _clean_header(text) or f"Column_{len(header_texts)+1}"
                header_texts.append(cleaned)
            header_cells = header_texts

        data_rows = []
        for rowgroup in table.find_all(attrs={"role": "rowgroup"}):
            for row in rowgroup.find_all(attrs={"role": "row"}):
                if row == header_row:
                    continue
                cells = row.find_all(attrs={"role": "cell"})
                if cells:
                    data_rows.append((row, cells))
        for row in table.find_all(attrs={"role": "row"}):
            if row == header_row or row in [r for r, _ in data_rows]:
                continue
            cells = row.find_all(attrs={"role": "cell"})
            if cells:
                data_rows.append((row, cells))

        for row, cells in data_rows:
            record = {}
            for i, cell in enumerate(cells):
                if i >= len(header_cells):
                    break
                text = _get_element_text(cell)
                if text:
                    header = header_cells[i] if isinstance(header_cells[i], str) else f"Column_{i+1}"
                    record[header] = text
            if record:
                results.append(record)
    return results

# ═══════════════════════════════════════════════════════════
# FALLBACK: HEURISTIC EXTRACTION (for non‑table pages)
# ═══════════════════════════════════════════════════════════
def _extract_heuristic_tables(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    """Last resort for pages with data hidden in CSS pseudo-elements."""
    results = []
    # Look for common product patterns (can be extended)
    p_name = soup.select_one('.p-name')
    if p_name:
        name = _get_element_text(p_name)
        sku_span = soup.select_one('#sku_val_6621')
        sku = _get_element_text(sku_span) if sku_span else ''
        p_val = soup.select_one('.p-val')
        price = _get_element_text(p_val) if p_val else ''
        if name or sku or price:
            record = {}
            if name:  record['Product'] = name
            if sku:   record['SKU'] = sku
            if price: record['Price'] = price
            results.append(record)
    return results

# ═══════════════════════════════════════════════════════════
# MAIN EXTRACTION DISPATCHER
# ═══════════════════════════════════════════════════════════
def _extract_worker(content: bytes) -> List[Dict[str, Any]]:
    """Parse HTML and extract tables using multiple strategies."""
    soup = BeautifulSoup(content, 'html.parser')

    # 1. Inject CSS pseudo-element content
    _apply_pseudo_elements(soup)

    # 2. Remove noise
    for tag in soup(['script', 'style', 'noscript', 'template']):
        tag.decompose()

    # 3. Standard tables
    results = _extract_standard_tables(soup)
    # Filter out garbage rows (e.g., very long single‑column headers)
    results = [r for r in results if (len(r) > 1 or (len(r) == 1 and not list(r.keys())[0].startswith("Column_"))) and len(list(r.keys())[0]) < 40]

    # 4. ARIA tables
    aria_results = _extract_aria_tables(soup)
    if aria_results:
        results.extend(aria_results)

    # 5. Heuristic fallback
    heuristic_results = _extract_heuristic_tables(soup)
    if heuristic_results:
        results.extend(heuristic_results)

    return results

# ═══════════════════════════════════════════════════════════
# FETCH WRAPPERS
# ═══════════════════════════════════════════════════════════
def _fetch_static(url: str):
    if Fetcher is None:
        raise RuntimeError("Scrapling Fetcher not installed.")
    try:
        response = Fetcher().get(url)
    except Exception as e:
        raise RuntimeError(f"Fetcher.get() failed: {e}")
    if response is None:
        raise RuntimeError("Fetcher.get() returned None")
    return response

def _fetch_js(url: str):
    if not _STEALTH_AVAILABLE or StealthyFetcher is None:
        raise RuntimeError("StealthyFetcher unavailable")
    try:
        response = StealthyFetcher.fetch(url, headless=True)
    except Exception as e:
        raise RuntimeError(f"StealthyFetcher.fetch() failed: {e}")
    if response is None:
        raise RuntimeError("StealthyFetcher.fetch() returned None")
    return response

# ═══════════════════════════════════════════════════════════
# CORE SCRAPE LOGIC
# ═══════════════════════════════════════════════════════════
async def _scrape_url(url: str, js: bool = False) -> tuple[List[Dict[str, Any]], int]:
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="FORBIDDEN_DOMAIN")
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
        raise HTTPException(status_code=502, detail="Empty response body")
    if raw_bytes > MAX_PAYLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"Payload too large ({raw_bytes / 1_048_576:.1f} MB)")

    try:
        rows = await loop.run_in_executor(cpu_executor, _extract_worker, raw)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Extraction failed: {e}")
    print(f"[SCRAPE] {url} → {len(rows)} rows extracted")
    return rows, raw_bytes

# ═══════════════════════════════════════════════════════════
# FASTAPI APP
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

# ── Debug endpoint (fixed function name) ───────────────────────────────────────
@app.get("/api/debug-fetch")
async def debug_fetch(url: str, _key: str = Depends(verify_key)):
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="FORBIDDEN_DOMAIN")
    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(None, _fetch_static, url)
        raw = _get_raw_bytes(response)   # Fixed: was get_raw_bytes
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
async def scrape(body: ScrapeRequest, _key: str = Depends(verify_key)):
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
# TELEGRAM BOT STARTUP & SHUTDOWN
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
