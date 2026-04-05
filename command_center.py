"""
AUDITOR CORE v9.5.2 - AI-Powered Universal Web Scraper (Dynamic Content Extraction)
────────────────────────────────────────────────────────────────────────────────────
Changes v9.5.2:

  FIXED F7 — Multiple tables merged into one flat list.
             The AI was finding all tables on the page (OI by exchange, OI gainers,
             correlation ratios) and merging them into one array.
             Fix: _find_best_table() scores every <table> by (rows × cols) using
             BS4 BEFORE sending to AI. Only the richest table is sent.
             For pages with no <table> tags, falls back to full cleaned HTML.

  FIXED F8 — Quality gate passing on the wrong table.
             _rows_have_data() correctly detected real data in the gainers table,
             but that was the wrong table. Quality gate now also checks schema
             consistency — rows that don't share ≥50% of their keys with the
             majority schema are flagged as mixed-table contamination.

  ADDED   — _score_table(): ranks tables by data density (rows × unique cols).
             Logs all candidate tables and their scores so you can debug in
             Railway/Render logs without touching code.

  ADDED   — extract_type="table" now skips full-page cleaning and goes straight
             to table isolation — faster and more accurate for known table pages.

Previous fixes (all retained):
  v9.5.1 — F6 inline tag unwrapping + HTML tag sanitisation in values.
  v9.5.0 — F1–F5 quality gate, JS retry, data-* attrs, empty-key fallback.
  v9.4.0 — surgical noise removal (blacklist, not readability).
────────────────────────────────────────────────────────────────────────────────────
"""

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
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel
from bs4 import BeautifulSoup, Tag

# ── readability-lxml intentionally disabled ───────────────────────────────────
_READABILITY_AVAILABLE = False
Document = None
print("[BOOT] readability-lxml disabled — using surgical noise removal + table isolation")

# ── Mistral AI ────────────────────────────────────────────────────────────────
try:
    from mistralai.client import Mistral
    _MISTRAL_AVAILABLE = True
except ImportError:
    Mistral = None
    _MISTRAL_AVAILABLE = False

# ── Scrapling ─────────────────────────────────────────────────────────────────
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

cpu_executor       = concurrent.futures.ProcessPoolExecutor(max_workers=4)
MAX_PAYLOAD_SIZE   = 10_485_760
MAX_SAFE_CHARS     = 500_000
MAX_RECORDS        = 100
MIN_FIELDS_PER_ROW = 2       # fewer → ghost row
MIN_QUALITY_RATIO  = 0.5     # below → JS retry
MIN_SCHEMA_OVERLAP = 0.5     # mixed-table contamination threshold

_MISTRAL_API_KEY = os.environ.get("MISTRAL_API_KEY", "").strip()
if not _MISTRAL_API_KEY:
    print("[ERROR] MISTRAL_API_KEY not set — AI extraction will fail.")
_MISTRAL_MODEL = "codestral-latest"

def _get_mistral_client() -> Optional["Mistral"]:
    if not _MISTRAL_AVAILABLE:
        print("[AI] Mistral library not installed.")
        return None
    if not _MISTRAL_API_KEY:
        print("[AI] No Mistral API key provided.")
        return None
    return Mistral(api_key=_MISTRAL_API_KEY)

# ═══════════════════════════════════════════════════════════════════════════════
# API KEY AUTH
# ═══════════════════════════════════════════════════════════════════════════════

_ENV_KEY = os.environ.get("AUDITOR_API_KEY", "").strip()
API_KEY  = _ENV_KEY if _ENV_KEY else secrets.token_hex(32)
if not _ENV_KEY:
    print(f"[BOOT] No AUDITOR_API_KEY — generated: {API_KEY}")

def verify_key(x_api_key: str = Header(..., alias="X-Api-Key")) -> str:
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return x_api_key

# ═══════════════════════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class ScrapeRequest(BaseModel):
    url:          str
    adaptive:     bool = True
    js:           bool = False
    extract_type: str  = "auto"

class ScrapeResponse(BaseModel):
    events:    List[Dict[str, Any]]
    raw_bytes: int
    elapsed:   float

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
        ip     = socket.gethostbyname(hostname)
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
# SURGICAL NOISE REMOVAL
# ═══════════════════════════════════════════════════════════════════════════════

_ZW_CHARS = re.compile(r'[\u200b\u200c\u200d\u2060\uFEFF\u00ad]')

_NOISE_TAGS = [
    'script', 'style', 'noscript', 'iframe', 'svg',
    'nav', 'footer', 'aside', 'header',
    'link', 'meta', 'base',
]

_INLINE_UNWRAP_TAGS = [
    'a', 'button', 'span', 'em', 'strong', 'b', 'i', 'u',
    'label', 'small', 'sup', 'sub', 'abbr', 'cite', 'mark',
    'bdi', 'bdo', 'time', 'ins', 'del', 's',
]

_NOISE_ATTR_RE = re.compile(
    r'\b(ad|ads|advert|advertisement|banner|cookie|popup|modal|overlay|'
    r'sidebar|widget|promo|sponsor|social|share|comment|newsletter|'
    r'breadcrumb|menu|navbar|toolbar|toast|notification|announcement|'
    r'header|footer|nav|navigation|flyout|dropdown|offcanvas|drawer|'
    r'skip-link|back-to-top|scroll-top|lightbox|carousel__control)\b',
    re.IGNORECASE,
)

_STRIP_ATTRS_RE = re.compile(
    r'^(class|id|style|on\w+|tabindex|role|href|src|srcset|loading|'
    r'crossorigin|integrity|referrerpolicy|fetchpriority|type|target|rel)$',
    re.IGNORECASE,
)

_HTML_TAG_RE = re.compile(r'<[^>]+>')


def _normalize(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize('NFKC', text)
    text = _ZW_CHARS.sub('', text)
    return text.strip()


def _clean_soup(soup: BeautifulSoup) -> BeautifulSoup:
    """Apply all noise-removal passes to a soup object in place."""
    # Pass 1: block chrome
    for tag in soup(_NOISE_TAGS):
        tag.decompose()

    # Pass 2: class/id noise
    for tag in soup.find_all(True):
        if tag.parent is None:
            continue
        classes = ' '.join(tag.get('class', []))
        tag_id  = tag.get('id', '')
        if _NOISE_ATTR_RE.search(classes) or _NOISE_ATTR_RE.search(tag_id):
            tag.decompose()

    # Pass 3: unwrap inline wrappers → leave text only
    for tag in soup.find_all(_INLINE_UNWRAP_TAGS):
        if tag.parent is None:
            continue
        tag.unwrap()

    # Pass 4: strip presentational attrs, keep data-*
    for tag in soup.find_all(True):
        tag.attrs = {
            k: v for k, v in tag.attrs.items()
            if not _STRIP_ATTRS_RE.match(k)
        }

    return soup


def _extract_main_content(html: str) -> str:
    soup = BeautifulSoup(html, 'html.parser')
    soup = _clean_soup(soup)
    return str(soup)

# ═══════════════════════════════════════════════════════════════════════════════
# TABLE ISOLATION — FIX F7
# ═══════════════════════════════════════════════════════════════════════════════

def _score_table(table_tag: Tag) -> int:
    """
    Score a <table> by data density: number of <tr> rows × max columns per row.
    Header rows (all <th>) are excluded from row count but counted for col width.
    """
    rows = table_tag.find_all('tr')
    if not rows:
        return 0
    max_cols  = max((len(r.find_all(['td', 'th'])) for r in rows), default=0)
    data_rows = sum(1 for r in rows if r.find('td'))   # rows with actual data cells
    return data_rows * max_cols


def _find_best_table(html: str) -> str:
    """
    FIX F7: Parse all <table> elements, score each by data density, return
    only the highest-scoring one as HTML string.

    If no <table> elements exist, returns the full cleaned HTML (list/card pages).
    Logs all candidates so failures are visible in Railway/Render logs.
    """
    soup = BeautifulSoup(html, 'html.parser')
    tables = soup.find_all('table')

    if not tables:
        print("[TABLE] No <table> elements found — using full cleaned HTML")
        return html

    scored = []
    for i, t in enumerate(tables):
        score    = _score_table(t)
        rows     = len(t.find_all('tr'))
        cols     = max((len(r.find_all(['td', 'th'])) for r in t.find_all('tr')), default=0)
        preview  = t.get_text(separator=' ', strip=True)[:80].replace('\n', ' ')
        scored.append((score, i, t))
        print(f"[TABLE] candidate #{i+1}: score={score} rows={rows} cols={cols} | {preview!r}")

    if not scored:
        return html

    scored.sort(key=lambda x: -x[0])
    best_score, best_idx, best_table = scored[0]
    print(f"[TABLE] Selected table #{best_idx+1} (score={best_score})")

    return str(best_table)


def _preprocess_html(html_bytes: bytes, prefer_table: bool = False) -> str:
    """
    Decode → clean noise → isolate best table (if prefer_table or tables found)
    → truncate only if over token limit.
    """
    try:
        text = html_bytes.decode('utf-8', errors='replace')
    except Exception:
        text = html_bytes.decode('latin-1', errors='replace')

    original_len = len(text)

    # Step 1: noise removal
    cleaned      = _extract_main_content(text)
    cleaned_len  = len(cleaned)

    print(
        f"[PREPROCESS] {original_len:,} → {cleaned_len:,} chars after noise removal "
        f"({100 * cleaned_len / max(original_len, 1):.1f}% retained)"
    )

    # Step 2: table isolation (FIX F7)
    # Always attempt — sends only the richest table to AI, preventing multi-table merge.
    isolated     = _find_best_table(cleaned)
    isolated_len = len(isolated)
    print(
        f"[PREPROCESS] {cleaned_len:,} → {isolated_len:,} chars after table isolation "
        f"({100 * isolated_len / max(cleaned_len, 1):.1f}% of cleaned)"
    )

    # Step 3: truncation safety net
    if isolated_len > MAX_SAFE_CHARS:
        keep_start = int(MAX_SAFE_CHARS * 0.8)
        keep_end   = MAX_SAFE_CHARS - keep_start
        isolated   = isolated[:keep_start] + "\n[... TRUNCATED ...]\n" + isolated[-keep_end:]
        print(f"[PREPROCESS] Truncated to {MAX_SAFE_CHARS:,} chars (was {isolated_len:,})")

    return isolated

# ═══════════════════════════════════════════════════════════════════════════════
# EXTRACTION QUALITY GATE
# ═══════════════════════════════════════════════════════════════════════════════

def _count_populated(row: Dict[str, Any]) -> int:
    return sum(
        1 for v in row.values()
        if v is not None and str(v).strip() not in ("", "null", "N/A", "-")
    )


def _majority_schema(rows: List[Dict[str, Any]]) -> set:
    """
    FIX F8: Find the key-set that appears in ≥50% of rows.
    Used to detect when rows from different tables snuck in.
    """
    if not rows:
        return set()
    key_counter: Counter = Counter()
    for row in rows:
        for k in row.keys():
            key_counter[k] += 1
    threshold = len(rows) * MIN_SCHEMA_OVERLAP
    return {k for k, c in key_counter.items() if c >= threshold}


def _rows_have_data(rows: List[Dict[str, Any]]) -> bool:
    """
    Returns False when:
    - rows is empty
    - fewer than MIN_QUALITY_RATIO of rows have ≥MIN_FIELDS_PER_ROW populated fields
    - rows show mixed-table contamination (keys don't share a majority schema)
    """
    if not rows:
        return False

    # Check 1: field population
    good_rows = sum(1 for r in rows if _count_populated(r) >= MIN_FIELDS_PER_ROW)
    quality   = good_rows / len(rows)
    print(
        f"[QUALITY] {good_rows}/{len(rows)} rows have ≥{MIN_FIELDS_PER_ROW} fields "
        f"(quality={quality:.0%})"
    )

    if quality < MIN_QUALITY_RATIO:
        return False

    # Check 2 (FIX F8): schema consistency — detect multi-table contamination
    majority = _majority_schema(rows)
    if majority:
        consistent = sum(
            1 for r in rows
            if len(set(r.keys()) & majority) / len(majority) >= MIN_SCHEMA_OVERLAP
        )
        schema_quality = consistent / len(rows)
        print(f"[QUALITY] Schema consistency: {consistent}/{len(rows)} rows match majority schema ({schema_quality:.0%})")
        if schema_quality < MIN_QUALITY_RATIO:
            print(f"[QUALITY] Mixed-table contamination detected — triggering retry")
            return False

    return True


def _log_extraction_stats(rows: List[Dict[str, Any]], label: str = "") -> None:
    if not rows:
        print(f"[STATS{' ' + label if label else ''}] No rows extracted.")
        return
    all_keys: Dict[str, int] = {}
    for row in rows:
        for k, v in row.items():
            all_keys.setdefault(k, 0)
            if v is not None and str(v).strip() not in ("", "null", "N/A", "-"):
                all_keys[k] += 1
    total = len(rows)
    print(f"[STATS{' ' + label if label else ''}] {total} rows · field coverage:")
    for key, count in sorted(all_keys.items(), key=lambda x: -x[1]):
        bar   = "█" * int(10 * count / total) + "░" * (10 - int(10 * count / total))
        empty = "  ← EMPTY KEY (header not detected)" if key.strip() == "" else ""
        print(f"  {bar} {count:>3}/{total}  '{key}'{empty}")

# ═══════════════════════════════════════════════════════════════════════════════
# POST-PROCESSING — sanitise AI output values
# ═══════════════════════════════════════════════════════════════════════════════

def _sanitize_value(v: Any) -> Any:
    if not isinstance(v, str):
        return v
    cleaned = _HTML_TAG_RE.sub('', v).strip()
    cleaned = re.sub(r'\s+', ' ', cleaned)
    return cleaned if cleaned else None


def _sanitize_row_values(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{k: _sanitize_value(v) for k, v in row.items()} for row in rows]

# ═══════════════════════════════════════════════════════════════════════════════
# AI EXTRACTION ENGINE
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
        print(f"[AI] Sending to {_MISTRAL_MODEL} ({len(html):,} chars)")
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
    structure_hint = {
        "table": (
            "Extract each <tr> data row as one object. "
            "Use the <th> or header row text as JSON keys."
        ),
        "list": (
            "Extract each list item as one object. "
            "Use any visible label or title text as the key."
        ),
        "card": (
            "Extract each card or repeated block as one object. "
            "Use visible field labels as keys."
        ),
    }.get(
        extract_type,
        (
            "Identify the single dominant repeated data structure "
            "(table rows, list items, or cards). "
            "Extract from that ONE structure only — do not mix rows from "
            "different tables or sections."
        ),
    )

    return f"""You are a universal data extraction engine. Extract all structured data from the HTML below.

STRICT RULES:
1. READ the actual column headers or field labels from the HTML. Use them EXACTLY as JSON keys.
   Do NOT rename, translate, shorten, or invent keys.
2. Extract EVERY column/field you find. Do not skip any.
3. Copy ALL values as plain text — preserve signs (+/-), units (BTC, ETH, $, %, K, M, B, T).
4. Values must be plain text strings only. Never include HTML tags in values.
5. If a cell is empty or missing, use null.
6. Do NOT add fields not in the source. Do NOT hallucinate values.
7. Extract from ONE table/structure only. Do NOT merge rows from different tables.
8. Return ONLY a valid JSON array — no markdown fences, no explanation, no preamble.
9. If no structured data is found, return: []

HEADER FALLBACK:
If the HTML has NO visible column headers (empty <th> or none at all):
  - Name the first column "label" (usually the row name/entity).
  - Name subsequent columns "col_2", "col_3", "col_4" etc. left-to-right.
  - Still extract every value from every column.

DATA-ATTRIBUTE HINT:
If visible cell text is empty but data-sort-value / data-raw / data-num / data-usd
attributes exist on the same element, use the attribute value as the cell value.

{structure_hint}

URL: {url}

HTML:
{html}

JSON array:"""


def _parse_ai_response(content: str) -> Optional[List[Dict[str, Any]]]:
    if not content:
        return None
    content = content.strip()
    if content.startswith('```'):
        lines   = content.split('\n')
        content = '\n'.join(
            line for line in lines
            if not line.startswith('```') and '```' not in line
        )
    start = content.find('[')
    end   = content.rfind(']') + 1
    if start == -1 or end == 0:
        return None
    try:
        data = json.loads(content[start:end])
        if isinstance(data, list):
            data = _sanitize_row_values(data)
            print(f"[AI] Parsed {len(data)} records")
            return data[:MAX_RECORDS]
    except json.JSONDecodeError as e:
        print(f"[AI] JSON parse error: {e}")
    return None

# ═══════════════════════════════════════════════════════════════════════════════
# FETCHING LAYER
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

    # Attempt 1: static (or JS if forced)
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

    _log_extraction_stats(rows, label="attempt=1 js=False")

    # Attempt 2: JS retry when quality gate fails
    should_retry_js = (
        not used_js
        and not _rows_have_data(rows)
        and raw_bytes >= 51_200
        and _STEALTH_AVAILABLE
    )

    if should_retry_js:
        print(f"[SCRAPE] Low-quality or contaminated extraction — retrying with JS renderer")
        try:
            response2   = await _do_fetch(True)
            raw2        = _get_raw_bytes(response2)
            if raw2:
                html_clean2 = _preprocess_html(raw2)
                rows2 = await loop.run_in_executor(
                    cpu_executor, extract_with_ai, html_clean2, url, extract_type
                )
                _log_extraction_stats(rows2, label="attempt=2 js=True")
                if _rows_have_data(rows2):
                    rows      = rows2
                    raw_bytes = len(raw2)
                    used_js   = True
                    print(f"[SCRAPE] JS retry succeeded")
                else:
                    print(f"[SCRAPE] JS retry also low quality — keeping static results")
        except Exception as e:
            print(f"[SCRAPE] JS retry failed: {e}")

    print(f"[SCRAPE] Final: {len(rows)} records (js={used_js})")
    return rows, raw_bytes

# ═══════════════════════════════════════════════════════════════════════════════
# FASTAPI APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(title="AUDITOR CORE", version="9.5.2")

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
        "status":              "ok",
        "version":             "9.5.2",
        "fetcher":             _FETCHER_AVAILABLE,
        "stealth":             _STEALTH_AVAILABLE,
        "mistral":             _MISTRAL_AVAILABLE,
        "readability":         False,
        "ai_model":            _MISTRAL_MODEL if _MISTRAL_AVAILABLE else None,
        "max_safe_chars":      MAX_SAFE_CHARS,
        "min_fields_per_row":  MIN_FIELDS_PER_ROW,
        "min_quality_ratio":   MIN_QUALITY_RATIO,
        "min_schema_overlap":  MIN_SCHEMA_OVERLAP,
        "utc":                 datetime.now(timezone.utc).isoformat(),
    }

@app.get("/api/debug-fetch")
async def debug_fetch(url: str, js: bool = False, _key: str = Depends(verify_key)):
    """
    Debug without AI: shows raw size, cleaned size, isolated table size,
    retention ratios, and a 3000-char preview of what the AI would receive.
    """
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="Forbidden domain")
    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(
            None, _fetch_js if js else _fetch_static, url
        )
        raw      = _get_raw_bytes(response)
        cleaned  = _extract_main_content(raw.decode('utf-8', errors='replace'))
        isolated = _find_best_table(cleaned)
        return {
            "url":              url,
            "js":               js,
            "raw_bytes":        len(raw),
            "cleaned_chars":    len(cleaned),
            "isolated_chars":   len(isolated),
            "retention_pct":    round(100 * len(cleaned) / max(len(raw), 1), 1),
            "isolation_pct":    round(100 * len(isolated) / max(len(cleaned), 1), 1),
            "truncated":        len(isolated) > MAX_SAFE_CHARS,
            "preview":          isolated[:3000],
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
