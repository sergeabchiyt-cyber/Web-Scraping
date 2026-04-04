"""
AUDITOR CORE v9.2.0 - AI-Powered Universal Web Scraper
────────────────────────────────────────────────────────────
Architecture:
  • Scrapling fetchers for static/JS content retrieval
  • Mistral AI (codestral-latest) for structured data extraction
  • NO fallback extraction – relies entirely on AI
────────────────────────────────────────────────────────────
"""

import os
import re
import time
import secrets
import asyncio
import socket
import unicodedata
import json
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel

# ── Mistral AI ────────────────────────────────────────────────────────────────
try:
    from mistralai.client import Mistral
    _MISTRAL_AVAILABLE = True
except ImportError:
    Mistral = None
    _MISTRAL_AVAILABLE = False

# ── Scrapling imports ─────────────────────────────────────────────────────────
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

print(f"[BOOT] Fetcher={_FETCHER_AVAILABLE}  Stealth={_STEALTH_AVAILABLE}  Mistral={_MISTRAL_AVAILABLE}")

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

cpu_executor = concurrent.futures.ProcessPoolExecutor(max_workers=4)
MAX_PAYLOAD_SIZE = 10_485_760          # 10 MB
MAX_HTML_FOR_AI = 40_000               # Truncate HTML before AI call
MAX_RECORDS = 100                      # Maximum records AI should return

# ── Mistral AI Configuration ─────────────────────────────────────────────────
_MISTRAL_API_KEY = os.environ.get("MISTRAL_API_KEY", "").strip()
if not _MISTRAL_API_KEY:
    print("[ERROR] MISTRAL_API_KEY environment variable not set. AI extraction will fail.")
_MISTRAL_MODEL = "codestral-latest"

def _get_mistral_client() -> Optional[Mistral]:
    """Return Mistral client if available and API key is set, else None."""
    if not _MISTRAL_AVAILABLE:
        print("[AI] Mistral library not installed.")
        return None
    if not _MISTRAL_API_KEY:
        print("[AI] No Mistral API key provided.")
        return None
    return Mistral(api_key=_MISTRAL_API_KEY)

# ═══════════════════════════════════════════════════════════════════════════════
# API KEY AUTHENTICATION (for this service, not Mistral)
# ═══════════════════════════════════════════════════════════════════════════════

_ENV_KEY = os.environ.get("AUDITOR_API_KEY", "").strip()
API_KEY = _ENV_KEY if _ENV_KEY else secrets.token_hex(32)
if not _ENV_KEY:
    print(f"[BOOT] No AUDITOR_API_KEY — generated: {API_KEY}")

def verify_key(x_api_key: str = Header(..., alias="X-Api-Key")) -> str:
    """Verify the API key for this service."""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return x_api_key

# ═══════════════════════════════════════════════════════════════════════════════
# REQUEST / RESPONSE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class ScrapeRequest(BaseModel):
    url: str
    adaptive: bool = True
    js: bool = False
    extract_type: str = "auto"  # "table", "list", "card", "auto"

class ScrapeResponse(BaseModel):
    events: List[Dict[str, Any]]
    raw_bytes: int
    elapsed: float

# ═══════════════════════════════════════════════════════════════════════════════
# SSRF PROTECTION
# ═══════════════════════════════════════════════════════════════════════════════

def _is_safe_url(url: str) -> bool:
    """Block requests to private/local IPs to prevent SSRF attacks."""
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
            (0x0A000000, 0xFF000000),   # 10.0.0.0/8
            (0xAC100000, 0xFFF00000),   # 172.16.0.0/12
            (0xC0A80000, 0xFFFF0000),   # 192.168.0.0/16
            (0x7F000000, 0xFF000000),   # 127.0.0.0/8
            (0xA9FE0000, 0xFFFF0000),   # 169.254.0.0/16
            (0x00000000, 0xFF000000),   # 0.0.0.0/8
        ]
        return not any((ip_int & mask) == (net & mask) for net, mask in private_blocks)
    except Exception:
        return False

# ═══════════════════════════════════════════════════════════════════════════════
# HTML PREPROCESSING
# ═══════════════════════════════════════════════════════════════════════════════

_ZW_CHARS = re.compile(r'[\u200b\u200c\u200d\u2060\uFEFF\u00ad]')

def _normalize(text: str) -> str:
    """Strip zero-width characters and normalize Unicode."""
    if not text:
        return ""
    text = unicodedata.normalize('NFKC', text)
    text = _ZW_CHARS.sub('', text)
    return text.strip()

def _preprocess_html(html: bytes) -> str:
    """
    Decode HTML, remove script/style tags, and truncate for AI consumption.
    """
    try:
        text = html.decode('utf-8', errors='replace')
    except Exception:
        text = html.decode('latin-1', errors='replace')

    # Remove script, style, and noscript blocks
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<noscript[^>]*>.*?</noscript>', '', text, flags=re.DOTALL | re.IGNORECASE)

    if len(text) > MAX_HTML_FOR_AI:
        text = text[:MAX_HTML_FOR_AI] + "\n\n[... TRUNCATED ...]"

    return text

# ═══════════════════════════════════════════════════════════════════════════════
# AI EXTRACTION ENGINE (Universal, no hardcoded fields)
# ═══════════════════════════════════════════════════════════════════════════════

def extract_with_ai(html_content: str, url: str, extract_type: str = "auto") -> List[Dict[str, Any]]:
    """
    Extract structured data from HTML using Mistral AI.
    Returns empty list if AI extraction fails.
    """
    result = _extract_with_mistral(html_content, url, extract_type)
    return result if result is not None else []

def _extract_with_mistral(html: str, url: str, extract_type: str) -> Optional[List[Dict[str, Any]]]:
    """Call Mistral AI and parse the JSON response."""
    client = _get_mistral_client()
    if not client:
        return None

    prompt = _build_universal_prompt(html, url, extract_type)

    try:
        print(f"[AI] Sending request to {_MISTRAL_MODEL}...")
        response = client.chat.complete(
            model=_MISTRAL_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
        content = response.choices[0].message.content
        print(f"[AI] Received response ({len(content)} chars)")
        return _parse_ai_response(content)
    except Exception as e:
        print(f"[AI] Mistral extraction failed: {e}")
        return None

def _build_universal_prompt(html: str, url: str, extract_type: str) -> str:
    """
    Create a generic extraction prompt that works for any structured data.
    No domain-specific column names or hardcoded fields.
    """
    # Provide guidance based on extract_type
    structure_hint = ""
    if extract_type == "table":
        structure_hint = "The page likely contains HTML tables. Extract each row as an object."
    elif extract_type == "list":
        structure_hint = "The page likely contains repeated list items (e.g., <li>, <div class='item'>). Extract each item as an object."
    elif extract_type == "card":
        structure_hint = "The page likely contains card-like components. Extract each card as an object."
    else:  # auto
        structure_hint = "Look for any repeated data structures: tables, lists, cards, or grids."

    return f"""You are a data extraction assistant. Extract ALL structured data records from the provided HTML.

URL: {url}
Extraction hint: {structure_hint}

Return a JSON array of objects. Each object represents one data record (row, item, card, etc.).
- If the page has column headers (e.g., <th>), use those as keys (convert to snake_case).
- If no headers exist, use generic keys like "column_1", "column_2", etc.
- Keep values as strings (trim whitespace, normalize).
- Do NOT include navigation, ads, pagination, or layout elements.
- Limit to the first {MAX_RECORDS} meaningful records.
- Output ONLY valid JSON. Do not add explanations, markdown formatting, or code fences.

HTML content:
{html[:35000]}

JSON array:"""

def _parse_ai_response(content: str) -> Optional[List[Dict[str, Any]]]:
    """Extract JSON array from AI response, handling markdown code blocks."""
    if not content:
        return None

    content = content.strip()
    # Remove markdown code fences if present
    if content.startswith('```'):
        lines = content.split('\n')
        # Find the first line that doesn't start with ```
        content = '\n'.join(line for line in lines if not line.startswith('```') and '```' not in line)

    # Locate the first '[' and last ']'
    start = content.find('[')
    end = content.rfind(']') + 1
    if start == -1 or end == 0:
        return None

    json_str = content[start:end]
    try:
        data = json.loads(json_str)
        if isinstance(data, list):
            print(f"[AI] Successfully parsed {len(data)} records")
            return data[:MAX_RECORDS]
    except json.JSONDecodeError as e:
        print(f"[AI] JSON parsing error: {e}")
        return None

    return None

# ═══════════════════════════════════════════════════════════════════════════════
# FETCHING LAYER (Scrapling)
# ═══════════════════════════════════════════════════════════════════════════════

def _fetch_static(url: str):
    """Use Scrapling Fetcher for static HTML pages."""
    if Fetcher is None:
        raise RuntimeError("Scrapling Fetcher not installed.")
    try:
        response = Fetcher().get(url)
    except Exception as e:
        raise RuntimeError(f"Fetcher.get() failed: {e}") from e
    if response is None:
        raise RuntimeError("Fetcher.get() returned None — page unreachable.")
    return response

def _fetch_js(url: str):
    """Use StealthyFetcher (Playwright) for JavaScript-heavy pages."""
    if not _STEALTH_AVAILABLE or StealthyFetcher is None:
        raise RuntimeError("StealthyFetcher unavailable. Install scrapling[all] and run 'scrapling install'.")
    try:
        response = StealthyFetcher.fetch(url, headless=True)
    except Exception as e:
        raise RuntimeError(f"StealthyFetcher.fetch() failed: {e}") from e
    if response is None:
        raise RuntimeError("StealthyFetcher.fetch() returned None.")
    return response

def _get_raw_bytes(response) -> bytes:
    """Extract HTML bytes from a Scrapling response object."""
    for attr in ('html', 'text'):
        val = getattr(response, attr, None)
        if val and isinstance(val, str) and val.strip():
            return val.encode('utf-8', errors='replace')
    for attr in ('content', 'body'):
        val = getattr(response, attr, None)
        if val:
            if isinstance(val, bytes) and val:
                return val
            if isinstance(val, str) and val.strip():
                return val.encode('utf-8', errors='replace')
    raise ValueError("Scrapling response has no usable content.")

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN SCRAPE PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

async def _scrape_url(url: str, js: bool = False, extract_type: str = "auto") -> Tuple[List[Dict[str, Any]], int]:
    """
    Fetch the URL (static or JS) and extract data using AI.
    Returns (extracted_records, raw_bytes).
    """
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="Forbidden: private/local IP addresses are blocked.")

    loop = asyncio.get_running_loop()

    async def _do_fetch(use_js: bool):
        try:
            return await loop.run_in_executor(None, _fetch_js if use_js else _fetch_static, url)
        except RuntimeError as e:
            raise HTTPException(status_code=502, detail=str(e))

    response = await _do_fetch(js)
    used_js = js

    try:
        raw = _get_raw_bytes(response)
    except ValueError as e:
        raise HTTPException(status_code=502, detail=str(e))

    raw_bytes = len(raw)
    print(f"[SCRAPE] {url} → {raw_bytes:,} bytes (js={used_js})")

    if raw_bytes == 0:
        raise HTTPException(status_code=502, detail="Empty response body — page may be blocking scrapers.")
    if raw_bytes > MAX_PAYLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"Payload too large ({raw_bytes/1_048_576:.1f} MB > 10 MB limit).")

    html_clean = _preprocess_html(raw)

    # AI extraction (no fallback)
    try:
        rows = await loop.run_in_executor(cpu_executor, extract_with_ai, html_clean, url, extract_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI extraction failed: {e}")

    # Auto JS retry if static fetch returned no data but page is large
    if not rows and not used_js and raw_bytes >= 51_200 and _STEALTH_AVAILABLE:
        print(f"[SCRAPE] No records from static fetch — retrying with JavaScript rendering")
        try:
            response2 = await _do_fetch(True)
            raw2 = _get_raw_bytes(response2)
            if raw2:
                html_clean2 = _preprocess_html(raw2)
                rows2 = await loop.run_in_executor(cpu_executor, extract_with_ai, html_clean2, url, extract_type)
                if rows2:
                    print(f"[SCRAPE] JS retry → {len(rows2)} records")
                    rows = rows2
                    raw_bytes = len(raw2)
        except Exception as e:
            print(f"[SCRAPE] JS retry failed: {e}")

    print(f"[SCRAPE] {url} → {len(rows)} records extracted")
    return rows, raw_bytes

# ═══════════════════════════════════════════════════════════════════════════════
# FASTAPI APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(title="AUDITOR CORE", version="9.2.0")

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

@app.get("/", include_in_schema=False)
async def serve_frontend():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(base_dir, "index.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    return HTMLResponse(content="<h2>404 — index.html not found</h2>", status_code=404)

@app.get("/api/key")
async def get_api_key():
    return JSONResponse({"api_key": API_KEY})

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "9.2.0",
        "fetcher": _FETCHER_AVAILABLE,
        "stealth": _STEALTH_AVAILABLE,
        "mistral": _MISTRAL_AVAILABLE,
        "ai_model": _MISTRAL_MODEL if _MISTRAL_AVAILABLE else None,
        "utc": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/api/debug-fetch")
async def debug_fetch(url: str, js: bool = False, _key: str = Depends(verify_key)):
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="Forbidden domain")
    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(None, _fetch_js if js else _fetch_static, url)
        raw = _get_raw_bytes(response)
        return {"url": url, "raw_bytes": len(raw), "preview": raw[:1000].decode('utf-8', errors='replace')}
    except Exception as e:
        return {"url": url, "error": str(e)}

@app.post("/api/scrape", response_model=ScrapeResponse)
async def scrape(body: ScrapeRequest, _key: str = Depends(verify_key)):
    t0 = time.perf_counter()
    rows, raw_bytes = await _scrape_url(body.url, js=body.js, extract_type=body.extract_type)
    return ScrapeResponse(events=rows, raw_bytes=raw_bytes, elapsed=round(time.perf_counter() - t0, 3))

@app.get("/api/token-status")
async def token_status(_key: str = Depends(verify_key)):
    # Placeholder – you can implement actual usage tracking if needed
    return {"limit_per_key": 100_000, "keys": [{"key_index": 1, "tokens_used": 0, "tokens_remaining": 100_000, "active": True}]}

@app.on_event("startup")
async def startup():
    try:
        from telegram_bot import start_bot
        start_bot()
        print("[BOOT] Telegram bot started.")
    except ImportError:
        print("[BOOT] telegram_bot.py not found — skipping.")
    except Exception as e:
        print(f"[BOOT] Telegram bot failed: {e}")

@app.on_event("shutdown")
async def shutdown():
    try:
        from telegram_bot import stop_bot
        stop_bot()
    except Exception:
        pass

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))