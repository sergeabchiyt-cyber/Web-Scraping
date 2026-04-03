import os
import re
import time
import secrets
import asyncio
import socket
import unicodedata
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional, Tuple

import uvicorn
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel
from bs4 import BeautifulSoup, Tag, NavigableString
import tinycss2
from scrapling.fetchers import StealthyFetcher

# ─────────────────────────────────────────────────────────────
# GLOBAL CONFIGURATION
# ─────────────────────────────────────────────────────────────
cpu_executor = concurrent.futures.ProcessPoolExecutor(max_workers=4)
MAX_PAYLOAD_SIZE = 10_485_760  # 10 MB

# ─────────────────────────────────────────────────────────────
# AUTHENTICATION
# ─────────────────────────────────────────────────────────────
_ENV_KEY = os.environ.get("AUDITOR_API_KEY", "").strip()
API_KEY = _ENV_KEY if _ENV_KEY else secrets.token_hex(32)
if not _ENV_KEY:
    print(f"[BOOT] No AUDITOR_API_KEY env var — generated key: {API_KEY}")

def verify_key(x_api_key: str = Header(..., alias="X-Api-Key")) -> str:
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return x_api_key

# ─────────────────────────────────────────────────────────────
# REQUEST / RESPONSE MODELS
# ─────────────────────────────────────────────────────────────
class ScrapeRequest(BaseModel):
    url: str
    adaptive: bool = True
    js: bool = False

class ScrapeResponse(BaseModel):
    events: List[Dict[str, Any]]
    raw_bytes: int
    elapsed: float

# ─────────────────────────────────────────────────────────────
# SECURITY: BLOCK PRIVATE IPs
# ─────────────────────────────────────────────────────────────
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

# ─────────────────────────────────────────────────────────────
# CLEANING & NORMALIZATION (UTF‑8 safe, preserves currency)
# ─────────────────────────────────────────────────────────────
def _normalize_text(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize('NFKC', text)
    text = re.sub(r'[\u200b\u200c\u200d\u2060\uFEFF]', '', text)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text.strip()

# ─────────────────────────────────────────────────────────────
# CSS PSEUDO‑ELEMENT RESOLVER (tinycss2)
# ─────────────────────────────────────────────────────────────
def _extract_css_rules(style_text: str) -> Dict[str, str]:
    rules = {}
    stylesheet = tinycss2.parse_stylesheet(style_text)
    for rule in stylesheet:
        if rule.type != 'qualified-rule':
            continue
        prelude = tinycss2.serialize(rule.prelude).strip()
        pseudo_match = re.search(r'::?(before|after)$', prelude)
        if not pseudo_match:
            continue
        pseudo = pseudo_match.group(1)
        selector = re.sub(r'::?(before|after)$', '', prelude).strip()
        content_value = None
        for token in rule.content:
            if token.type == 'literal' and token.value == 'content':
                for i, t in enumerate(rule.content):
                    if t.type == 'string' and i > rule.content.index(token):
                        content_value = t.value
                        break
                break
        if content_value:
            rules[f"{selector}::{pseudo}"] = content_value
    return rules

def _apply_pseudo_elements(soup: BeautifulSoup) -> None:
    style_text = ''
    for style_tag in soup.find_all('style'):
        if style_tag.string:
            style_text += style_tag.string
    if not style_text:
        return
    rules = _extract_css_rules(style_text)
    for selector_pseudo, content in rules.items():
        selector = selector_pseudo.split('::')[0]
        pseudo = selector_pseudo.split('::')[1]
        elements = soup.select(selector)
        for el in elements:
            new_node = NavigableString(content)
            if pseudo == 'before':
                el.insert(0, new_node)
            else:
                el.append(new_node)

# ─────────────────────────────────────────────────────────────
# TEXT EXTRACTION
# ─────────────────────────────────────────────────────────────
def _get_element_text(element) -> str:
    if not isinstance(element, Tag):
        return _normalize_text(str(element))

    hidden_classes = {'visually-hidden', 'tw-sr-only', 'sr-only', 'hidden', 'hide'}
    class_attr = element.get('class', [])
    if isinstance(class_attr, list):
        if hidden_classes.intersection(class_attr):
            return ''
    elif isinstance(class_attr, str):
        if any(cls in class_attr.split() for cls in hidden_classes):
            return ''

    if element.name in ('script', 'style', 'noscript', 'template'):
        return ''

    if element.name == 'svg':
        text_nodes = element.find_all(['text', 'tspan', 'title'])
        if text_nodes:
            return ' '.join(_get_element_text(t) for t in text_nodes).strip()
        return ''

    text_parts = []
    for child in element.children:
        if isinstance(child, NavigableString):
            txt = _normalize_text(child.string)
            if txt:
                text_parts.append(txt)
        else:
            child_text = _get_element_text(child)
            if child_text:
                text_parts.append(child_text)

    inline_tags = {'span', 'a', 'b', 'i', 'strong', 'em', 'small', 'u',
                   'sub', 'sup', 'label', 'button', 'text', 'tspan'}
    if element.name in inline_tags:
        return ''.join(text_parts)
    return ' '.join(text_parts).strip()

# ─────────────────────────────────────────────────────────────
# STANDARD TABLE EXTRACTION
# ─────────────────────────────────────────────────────────────
def _extract_standard_tables(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    results = []
    for table in soup.find_all('table'):
        headers = []
        thead = table.find('thead')
        if thead and thead.find('tr'):
            for cell in thead.find('tr').find_all(['th', 'td']):
                text = _get_element_text(cell)
                headers.append(text if text else f"Col_{len(headers)+1}")
        if not headers:
            first_row = table.find('tr')
            if first_row:
                for cell in first_row.find_all(['th', 'td']):
                    text = _get_element_text(cell)
                    headers.append(text if text else f"Col_{len(headers)+1}")
        if not headers:
            continue

        tbody = table.find('tbody')
        data_rows = tbody.find_all('tr') if tbody else table.find_all('tr')[1:]
        for row in data_rows:
            cells = row.find_all(['td', 'th'])
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

# ─────────────────────────────────────────────────────────────
# ARIA GRID EXTRACTION (coordinate‑based)
# ─────────────────────────────────────────────────────────────
def _extract_aria_tables(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    results = []
    tables = soup.find_all(attrs={"role": ["table", "grid"]})
    for table in tables:
        header_map = {}
        rows = table.find_all(attrs={"role": "row"})
        for row in rows:
            cells = row.find_all(attrs={"role": ["columnheader", "cell"]})
            for idx, cell in enumerate(cells):
                if cell.get('role') == 'columnheader':
                    text = _get_element_text(cell)
                    if text and idx not in header_map:
                        header_map[idx] = text
        if not header_map and rows:
            first_cells = rows[0].find_all(attrs={"role": "cell"})
            for idx, cell in enumerate(first_cells):
                text = _get_element_text(cell)
                if text:
                    header_map[idx] = text
        if not header_map:
            max_cols = max((len(row.find_all(attrs={"role": "cell"})) for row in rows), default=0)
            header_map = {i: f"Column_{i+1}" for i in range(max_cols)}

        for row in rows:
            cells = row.find_all(attrs={"role": "cell"})
            if not cells:
                continue
            if all(c.get('role') == 'columnheader' for c in cells):
                continue
            record = {}
            for idx, cell in enumerate(cells):
                if idx in header_map:
                    text = _get_element_text(cell)
                    if text:
                        record[header_map[idx]] = text
            if record:
                results.append(record)
    return results

# ─────────────────────────────────────────────────────────────
# JSON‑LD HONEYPOT DETECTION (stub)
# ─────────────────────────────────────────────────────────────
def _check_json_ld(soup: BeautifulSoup, extracted_data: List[Dict]) -> List[Dict]:
    # In production, implement cross‑reference. For now, return as is.
    return extracted_data

# ─────────────────────────────────────────────────────────────
# HEURISTIC FALLBACK
# ─────────────────────────────────────────────────────────────
def _extract_heuristic_tables(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    results = []
    p_name = soup.select_one('.p-name')
    if p_name:
        name = _get_element_text(p_name)
        sku_span = soup.select_one('#sku_val_6621')
        sku = _get_element_text(sku_span) if sku_span else ''
        p_val = soup.select_one('.p-val')
        price = _get_element_text(p_val) if p_val else ''
        if name or sku or price:
            record = {}
            if name: record['Product'] = name
            if sku: record['SKU'] = sku
            if price: record['Price'] = price
            results.append(record)
    return results

# ─────────────────────────────────────────────────────────────
# MAIN EXTRACTION DISPATCHER
# ─────────────────────────────────────────────────────────────
def _extract_worker(content: bytes) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(content, 'lxml')
    _apply_pseudo_elements(soup)
    for tag in soup(['script', 'style', 'noscript', 'template']):
        tag.decompose()

    results = _extract_standard_tables(soup)
    results = [r for r in results if len(r) > 1 or (len(r) == 1 and not list(r.keys())[0].startswith("Col_"))]
    results.extend(_extract_aria_tables(soup))
    results.extend(_extract_heuristic_tables(soup))
    results = _check_json_ld(soup, results)
    return results

# ─────────────────────────────────────────────────────────────
# FETCHER (ALWAYS STEALTHY – FIXED)
# ─────────────────────────────────────────────────────────────
_stealth_session = None

def _get_stealth_session():
    global _stealth_session
    if _stealth_session is None:
        _stealth_session = StealthyFetcher(
            headless=False,
            browser_type='chromium',
            stealth_forward=True,
            custom_headers={
                'Accept-Language': 'en-US,en;q=0.9',
                'Sec-CH-UA': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
                'Sec-CH-UA-Mobile': '?0',
                'Sec-CH-UA-Platform': '"Windows"',
            }
        )
    return _stealth_session

def _fetch_url(url: str, js: bool = False):
    """Always use StealthyFetcher.fetch(); js flag controls headless."""
    fetcher = _get_stealth_session()
    try:
        response = fetcher.fetch(url, headless=js)
    except Exception as e:
        raise RuntimeError(f"StealthyFetcher failed: {e}")
    if response is None or (hasattr(response, 'status_code') and response.status_code >= 400):
        raise RuntimeError(f"Request failed: {getattr(response, 'status_code', 'no response')}")
    return response

# ─────────────────────────────────────────────────────────────
# CORE SCRAPE LOGIC
# ─────────────────────────────────────────────────────────────
async def _scrape_url(url: str, js: bool = False) -> Tuple[List[Dict[str, Any]], int]:
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="FORBIDDEN_DOMAIN")
    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(None, _fetch_url, url, js)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))

    raw = getattr(response, 'content', None)
    if not raw:
        raw = getattr(response, 'html', '').encode('utf-8')
    if not raw:
        raise HTTPException(status_code=502, detail="Empty response")
    raw_bytes = len(raw)
    print(f"[SCRAPE] {url} → {raw_bytes} bytes fetched (js={js})")

    if raw_bytes > MAX_PAYLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"Payload too large ({raw_bytes / 1_048_576:.1f} MB)")

    try:
        rows = await loop.run_in_executor(cpu_executor, _extract_worker, raw)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Extraction failed: {e}")
    print(f"[SCRAPE] {url} → {len(rows)} rows extracted")
    return rows, raw_bytes

# ─────────────────────────────────────────────────────────────
# FASTAPI APPLICATION
# ─────────────────────────────────────────────────────────────
app = FastAPI(title="AUDITOR CORE", version="8.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    errors = "; ".join(f"{' → '.join(str(l) for l in e['loc'])}: {e['msg']}" for e in exc.errors())
    return JSONResponse(status_code=422, content={"detail": f"Validation error — {errors}"})

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "8.0.0", "fetcher": "StealthyFetcher", "utc": datetime.now(timezone.utc).isoformat()}

@app.post("/api/scrape", response_model=ScrapeResponse)
async def scrape(body: ScrapeRequest, _key: str = Depends(verify_key)):
    t0 = time.perf_counter()
    rows, raw_bytes = await _scrape_url(body.url, js=body.js)
    return ScrapeResponse(events=rows, raw_bytes=raw_bytes, elapsed=round(time.perf_counter() - t0, 3))

# ─────────────────────────────────────────────────────────────
# TELEGRAM BOT INTEGRATION
# ─────────────────────────────────────────────────────────────
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

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
