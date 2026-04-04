"""
AUDITOR CORE v9.4.1 - AI-Powered Universal Web Scraper (Dynamic Content Extraction)
────────────────────────────────────────────────────────────────────────────────────
Changes v9.4.1:
  • FIXED: Prompt is now fully header-driven — AI reads actual column headers from
    the HTML and uses them as JSON keys. No hardcoded field names (long/short/total).
  • FIXED: All columns extracted, not just 3. Includes OI Change 1h/4h/24h, Rate%, etc.
  • Values copied exactly as-is: signs (+/-), units (BTC/$/%/K/M/B/T) preserved.
  • Removed example row from prompt — it was causing label hallucination.

Changes v9.4.0:
  • FIXED: Replaced readability-lxml (destroys data pages) with surgical noise removal
  • FIXED: BS4 fallback now BLACKLISTS noise instead of whitelisting tags
  • Strips class/id/style attributes to reduce payload 30-40% with zero data loss
  • Only truncates when exceeding model's token limit (safe 500k chars)
────────────────────────────────────────────────────────────────────────────────────
"""

# Load environment variables from .env file first
from dotenv import load_dotenv
load_dotenv()

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
from typing import List, Dict, Any, Tuple, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel
from bs4 import BeautifulSoup

# ── readability-lxml is intentionally NOT used ────────────────────────────────
# It is designed for article extraction and destroys data-heavy pages
# (tables, exchange data, finance dashboards) by keeping only one "article" block.
# Surgical noise removal (below) is used instead.
_READABILITY_AVAILABLE = False
Document = None
print("[BOOT] readability-lxml disabled — using surgical noise removal")

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
# No hard cap – but we keep a safety limit to avoid hitting model's 256k token limit
# ~4 chars per token => 1M chars safe; we set 500k to be conservative.
MAX_SAFE_CHARS = 500_000
MAX_RECORDS = 100

# ── Mistral AI Configuration ─────────────────────────────────────────────────
_MISTRAL_API_KEY = os.environ.get("MISTRAL_API_KEY", "").strip()
if not _MISTRAL_API_KEY:
    print("[ERROR] MISTRAL_API_KEY environment variable not set. AI extraction will fail.")
_MISTRAL_MODEL = "codestral-latest"

def _get_mistral_client() -> Optional[Mistral]:
    if not _MISTRAL_AVAILABLE:
        print("[AI] Mistral library not installed.")
        return None
    if not _MISTRAL_API_KEY:
        print("[AI] No Mistral API key provided.")
        return None
    return Mistral(api_key=_MISTRAL_API_KEY)

# ═══════════════════════════════════════════════════════════════════════════════
# API KEY AUTHENTICATION (for this service)
# ═══════════════════════════════════════════════════════════════════════════════

_ENV_KEY = os.environ.get("AUDITOR_API_KEY", "").strip()
API_KEY = _ENV_KEY if _ENV_KEY else secrets.token_hex(32)
if not _ENV_KEY:
    print(f"[BOOT] No AUDITOR_API_KEY — generated: {API_KEY}")

def verify_key(x_api_key: str = Header(..., alias="X-Api-Key")) -> str:
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
    extract_type: str = "auto"

class ScrapeResponse(BaseModel):
    events: List[Dict[str, Any]]
    raw_bytes: int
    elapsed: float

# ═══════════════════════════════════════════════════════════════════════════════
# SSRF PROTECTION
# ═══════════════════════════════════════════════════════════════════════════════

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
            (0x0A000000, 0xFF000000), (0xAC100000, 0xFFF00000),
            (0xC0A80000, 0xFFFF0000), (0x7F000000, 0xFF000000),
            (0xA9FE0000, 0xFFFF0000), (0x00000000, 0xFF000000),
        ]
        return not any((ip_int & mask) == (net & mask) for net, mask in private_blocks)
    except Exception:
        return False

# ═══════════════════════════════════════════════════════════════════════════════
# DYNAMIC MAIN CONTENT EXTRACTION — surgical noise removal
# ═══════════════════════════════════════════════════════════════════════════════

_ZW_CHARS = re.compile(r'[\u200b\u200c\u200d\u2060\uFEFF\u00ad]')

# Tags that are pure chrome — always safe to drop entirely
_NOISE_TAGS = [
    'script', 'style', 'noscript', 'iframe', 'svg',
    'nav', 'footer', 'aside', 'header',
    'link', 'meta', 'base',
]

# Class/ID substrings that strongly indicate UI chrome, ads, or menus.
# This regex is intentionally broad — false positives (dropping a non-data div)
# are far less harmful than false negatives (keeping 500k of script/nav bloat).
_NOISE_ATTR_RE = re.compile(
    r'\b(ad|ads|advert|advertisement|banner|cookie|popup|modal|overlay|'
    r'sidebar|widget|promo|sponsor|social|share|comment|newsletter|'
    r'breadcrumb|menu|navbar|toolbar|toast|notification|announcement|'
    r'header|footer|nav|navigation|flyout|dropdown|offcanvas|drawer|'
    r'skip-link|back-to-top|scroll-top|lightbox|carousel__control)\b',
    re.IGNORECASE,
)

# HTML attributes worth keeping for AI structural understanding
_KEEP_ATTRS = {'colspan', 'rowspan', 'data-value', 'data-label', 'aria-label', 'title', 'alt'}


def _normalize(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize('NFKC', text)
    text = _ZW_CHARS.sub('', text)
    return text.strip()


def _extract_main_content(html: str) -> str:
    """
    Surgically removes noise (ads, nav, scripts, menus) while preserving
    ALL actual content (tables, lists, divs, text, data blocks).

    Strategy: BLACKLIST known noise — never whitelist by tag type.
    Readability is intentionally not used here; it picks a single article
    block and discards everything else, which destroys data-heavy pages.
    """
    soup = BeautifulSoup(html, 'html.parser')

    # Pass 1: drop known chrome tags entirely
    for tag in soup(_NOISE_TAGS):
        tag.decompose()

    # Pass 2: drop elements whose class or id matches noise patterns
    for tag in soup.find_all(True):
        if tag.parent is None:   # already decomposed by a parent
            continue
        classes = ' '.join(tag.get('class', []))
        tag_id  = tag.get('id', '')
        if _NOISE_ATTR_RE.search(classes) or _NOISE_ATTR_RE.search(tag_id):
            tag.decompose()

    # Pass 3: strip verbose HTML attributes — keeps colspan/rowspan/aria-label
    # for table semantics; drops class/id/style/data-* noise.
    # This alone saves 30-40% of chars on attribute-heavy pages.
    for tag in soup.find_all(True):
        tag.attrs = {k: v for k, v in tag.attrs.items() if k in _KEEP_ATTRS}

    return str(soup)


def _preprocess_html(html_bytes: bytes) -> str:
    """
    Decode → remove noise → only truncate when exceeding model token limit.
    Logs retention ratio so you can tune _NOISE_ATTR_RE if needed.
    """
    try:
        text = html_bytes.decode('utf-8', errors='replace')
    except Exception:
        text = html_bytes.decode('latin-1', errors='replace')

    original_len = len(text)
    main = _extract_main_content(text)
    cleaned_len = len(main)

    print(
        f"[PREPROCESS] {original_len:,} → {cleaned_len:,} chars "
        f"({100 * cleaned_len / max(original_len, 1):.1f}% retained)"
    )

    if cleaned_len > MAX_SAFE_CHARS:
        keep_start = int(MAX_SAFE_CHARS * 0.8)
        keep_end   = MAX_SAFE_CHARS - keep_start
        main = main[:keep_start] + "\n[... TRUNCATED ...]\n" + main[-keep_end:]
        print(f"[PREPROCESS] Truncated to {MAX_SAFE_CHARS:,} chars (was {cleaned_len:,})")

    return main

# ═══════════════════════════════════════════════════════════════════════════════
# AI EXTRACTION ENGINE — universal, header-driven
# ═══════════════════════════════════════════════════════════════════════════════

def extract_with_ai(html_content: str, url: str, extract_type: str = "auto") -> List[Dict[str, Any]]:
    result = _extract_with_mistral(html_content, url, extract_type)
    return result if result is not None else []


def _extract_with_mistral(html: str, url: str, extract_type: str) -> Optional[List[Dict[str, Any]]]:
    client = _get_mistral_client()
    if not client:
        return None

    prompt = _build_accuracy_prompt(html, url, extract_type)

    try:
        print(f"[AI] Sending to {_MISTRAL_MODEL} (HTML size: {len(html):,} chars)")
        response = client.chat.complete(
            model=_MISTRAL_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
        )
        content = response.choices[0].message.content
        print(f"[AI] Response received ({len(content)} chars)")
        return _parse_ai_response(content)
    except Exception as e:
        print(f"[AI] Mistral extraction failed: {e}")
        return None


def _build_accuracy_prompt(html: str, url: str, extract_type: str) -> str:
    """
    Fully header-driven universal prompt.

    The AI reads whatever column headers / field labels exist in the HTML
    and uses them verbatim as JSON keys. No example rows, no hardcoded field
    names — this prevents label hallucination and works on any website.
    """
    structure_hint = {
        "table": "Extract each <tr> data row as one object. Use the <th> or header row text as JSON keys.",
        "list":  "Extract each list item as one object. Use any visible label/title as the key.",
        "card":  "Extract each card or repeated block as one object. Use visible field labels as keys.",
    }.get(
        extract_type,
        "Identify the dominant repeated data structure (table rows, list items, or cards). "
        "Use whatever column headers or field labels are present in the HTML as JSON keys.",
    )

    return f"""You are a universal data extraction engine. Extract all structured data from the HTML below.

STRICT RULES — follow every one:
1. READ the actual column headers or field labels from the HTML. Use them EXACTLY as JSON keys.
   Do NOT rename, translate, shorten, or invent keys.
2. Extract EVERY column / field you find. Do not skip any.
3. Copy ALL values EXACTLY as they appear — preserve signs (+/-), units (BTC, ETH, $, %, K, M, B, T),
   colors encoded as text (e.g. "red", "green"), and any other formatting present.
4. If a cell is empty or the value is missing, use null.
5. Do NOT add fields that are not present in the source HTML.
6. Do NOT hallucinate data. If you are unsure about a value, use null.
7. Return ONLY a valid JSON array of objects — no markdown fences, no explanation, no preamble.
8. If no structured data is found, return an empty array: []

{structure_hint}

URL: {url}

HTML:
{html}

JSON array:"""


def _parse_ai_response(content: str) -> Optional[List[Dict[str, Any]]]:
    if not content:
        return None
    content = content.strip()
    # Strip markdown fences if model added them despite instructions
    if content.startswith('```'):
        lines = content.split('\n')
        content = '\n'.join(
            line for line in lines
            if not line.startswith('```') and '```' not in line
        )
    start = content.find('[')
    end   = content.rfind(']') + 1
    if start == -1 or end == 0:
        return None
    json_str = content[start:end]
    try:
        data = json.loads(json_str)
        if isinstance(data, list):
            print(f"[AI] Parsed {len(data)} records")
            return data[:MAX_RECORDS]
    except json.JSONDecodeError as e:
        print(f"[AI] JSON parse error: {e}")
    return None

# ═══════════════════════════════════════════════════════════════════════════════
# FETCHING LAYER (Scrapling)
# ═══════════════════════════════════════════════════════════════════════════════

def _fetch_static(url: str):
    if Fetcher is None:
        raise RuntimeError("Scrapling Fetcher not installed.")
    try:
        response = Fetcher().get(url)
    except Exception as e:
        raise RuntimeError(f"Fetcher.get() failed: {e}") from e
    if response is None:
        raise RuntimeError("Fetcher.get() returned None.")
    return response


def _fetch_js(url: str):
    if not _STEALTH_AVAILABLE or StealthyFetcher is None:
        raise RuntimeError("StealthyFetcher unavailable.")
    try:
        response = StealthyFetcher.fetch(url, headless=True)
    except Exception as e:
        raise RuntimeError(f"StealthyFetcher.fetch() failed: {e}") from e
    if response is None:
        raise RuntimeError("StealthyFetcher.fetch() returned None.")
    return response


def _get_raw_bytes(response) -> bytes:
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

async def _scrape_url(
    url: str,
    js: bool = False,
    extract_type: str = "auto",
) -> Tuple[List[Dict[str, Any]], int]:

    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="Forbidden: private/local IP blocked.")

    loop = asyncio.get_running_loop()

    async def _do_fetch(use_js: bool):
        try:
            return await loop.run_in_executor(
                None, _fetch_js if use_js else _fetch_static, url
            )
        except RuntimeError as e:
            raise HTTPException(status_code=502, detail=str(e))

    response = await _do_fetch(js)
    used_js  = js

    try:
        raw = _get_raw_bytes(response)
    except ValueError as e:
        raise HTTPException(status_code=502, detail=str(e))

    raw_bytes = len(raw)
    print(f"[SCRAPE] {url} → {raw_bytes:,} bytes (js={used_js})")

    if raw_bytes == 0:
        raise HTTPException(status_code=502, detail="Empty body.")
    if raw_bytes > MAX_PAYLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Payload too large ({raw_bytes / 1_048_576:.1f} MB).",
        )

    html_clean = _preprocess_html(raw)

    try:
        rows = await loop.run_in_executor(
            cpu_executor, extract_with_ai, html_clean, url, extract_type
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI extraction failed: {e}")

    # Auto-retry with JS renderer if static fetch yielded nothing
    if not rows and not used_js and raw_bytes >= 51_200 and _STEALTH_AVAILABLE:
        print(f"[SCRAPE] No records from static — retrying with JS")
        try:
            response2 = await _do_fetch(True)
            raw2 = _get_raw_bytes(response2)
            if raw2:
                html_clean2 = _preprocess_html(raw2)
                rows2 = await loop.run_in_executor(
                    cpu_executor, extract_with_ai, html_clean2, url, extract_type
                )
                if rows2:
                    rows      = rows2
                    raw_bytes = len(raw2)
        except Exception as e:
            print(f"[SCRAPE] JS retry failed: {e}")

    print(f"[SCRAPE] {url} → {len(rows)} records")
    return rows, raw_bytes

# ═══════════════════════════════════════════════════════════════════════════════
# FASTAPI APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(title="AUDITOR CORE", version="9.4.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    errors = "; ".join(
        f"{' → '.join(str(l) for l in e['loc'])}: {e['msg']}" for e in exc.errors()
    )
    return JSONResponse(status_code=422, content={"detail": f"Validation error — {errors}"})


@app.get("/", include_in_schema=False)
async def serve_frontend():
    base_dir  = os.path.dirname(os.path.abspath(__file__))
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
        "status":        "ok",
        "version":       "9.4.1",
        "fetcher":       _FETCHER_AVAILABLE,
        "stealth":       _STEALTH_AVAILABLE,
        "mistral":       _MISTRAL_AVAILABLE,
        "readability":   False,   # disabled — surgical noise removal used instead
        "ai_model":      _MISTRAL_MODEL if _MISTRAL_AVAILABLE else None,
        "max_safe_chars": MAX_SAFE_CHARS,
        "utc":           datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/debug-fetch")
async def debug_fetch(url: str, js: bool = False, _key: str = Depends(verify_key)):
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="Forbidden domain")
    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(
            None, _fetch_js if js else _fetch_static, url
        )
        raw     = _get_raw_bytes(response)
        cleaned = _preprocess_html(raw)
        return {
            "url":           url,
            "raw_bytes":     len(raw),
            "cleaned_chars": len(cleaned),
            "retention_pct": round(100 * len(cleaned) / max(len(raw), 1), 1),
            "preview":       cleaned[:2000],
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


@app.post("/api/scrape", response_model=ScrapeResponse)
async def scrape(body: ScrapeRequest, _key: str = Depends(verify_key)):
    t0 = time.perf_counter()
    rows, raw_bytes = await _scrape_url(
        body.url, js=body.js, extract_type=body.extract_type
    )
    return ScrapeResponse(
        events=rows,
        raw_bytes=raw_bytes,
        elapsed=round(time.perf_counter() - t0, 3),
    )


@app.get("/api/token-status")
async def token_status(_key: str = Depends(verify_key)):
    return {
        "limit_per_key": 100_000,
        "keys": [
            {"key_index": 1, "tokens_used": 0, "tokens_remaining": 100_000, "active": True}
        ],
    }


@app.on_event("startup")
async def startup():
    try:
        from telegram_bot import start_bot
        start_bot()
        print("[BOOT] Telegram bot started.")
    except ImportError:
        print("[BOOT] telegram_bot.py not found – skipping.")
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
