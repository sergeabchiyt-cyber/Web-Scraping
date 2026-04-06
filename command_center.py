"""
AUDITOR CORE v9.8.0 - AI-Powered Universal Web Scraper (Dynamic Content Extraction)
\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
Changes v9.8.0:
  \u2022 SWITCHED AI backend: Cerebras \u2192 Mistral La Plateforme (mistral-small-2603)
    - Model:   Mistral Small 4 (mistral-small-2603)
    - SDK:     mistralai
    - TPM:     500,000 (vs Cerebras 60,000 \u2014 8x headroom)
    - TPS:     ~148 t/s
    - Context: 256k tokens
    - Free tier: 1B tokens/month per model, data training opt-in required
  \u2022 REMOVED batch delays \u2014 500k TPM means no waiting between batches
  \u2022 REMOVED retry-on-429 logic \u2014 no longer needed at 5.8% TPM usage per batch
  \u2022 ADDED reasoning_effort="none" \u2014 disables chain-of-thought for pure extraction
    speed (JSON output does not benefit from reasoning, only adds latency/tokens)
  \u2022 ENV var: MISTRAL_API_KEY (replaces CEREBRAS_API_KEY)

Previous fixes (all retained):
  v9.7.1 \u2014 P1 batch delay, P2 retry on 429, P4 semantic column name inference.
  v9.7.0 \u2014 dynamic row-boundary batching, batch logging.
  v9.6.0 \u2014 log spam fix (score > 2 only).
  v9.5.4 \u2014 F11 empty-key promotion, F12 image-only name cells.
  v9.5.3 \u2014 F9 honest [] on JS pages, F10 JSON script preservation.
  v9.5.2 \u2014 F7 table isolation, F8 schema consistency.
  v9.5.1 \u2014 F6 inline tag unwrapping, HTML tag sanitisation.
  v9.5.0 \u2014 F1\u2013F5 quality gate, JS retry, data-* attrs, empty-key fallback.
  v9.4.0 \u2014 surgical noise removal (blacklist, not readability).
\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
"""

from dotenv import load_dotenv
load_dotenv()

import os
import re
import time
import math
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

_READABILITY_AVAILABLE = False
Document = None
print("[BOOT] readability-lxml disabled \u2014 using surgical noise removal + table isolation")

# \u2500\u2500 Mistral AI \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
try:
    from mistralai.client import Mistral
    _MISTRAL_AVAILABLE = True
except ImportError:
    Mistral = None
    _MISTRAL_AVAILABLE = False

# \u2500\u2500 Scrapling \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
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

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
# CONFIGURATION
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

cpu_executor       = concurrent.futures.ProcessPoolExecutor(max_workers=4)
MAX_PAYLOAD_SIZE   = 10_485_760
MAX_SAFE_CHARS     = 500_000
MAX_RECORDS        = 1000
MIN_FIELDS_PER_ROW = 2
MIN_QUALITY_RATIO  = 0.5
MIN_SCHEMA_OVERLAP = 0.5

# Batching \u2014 500k TPM means no delays needed between batches
# Keep batch size conservative to stay well within 256k context window
MAX_BATCH_CHARS    = 120_000   # ~30k tokens per batch
BATCH_OVERHEAD     = 4_000     # prompt + header reserved
BATCH_USABLE       = MAX_BATCH_CHARS - BATCH_OVERHEAD   # 116,000 usable
CHARS_PER_TOKEN    = 4

# \u2500\u2500 Mistral config \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
_MISTRAL_API_KEY = os.environ.get("MISTRAL_API_KEY", "").strip()
if not _MISTRAL_API_KEY:
    print("[ERROR] MISTRAL_API_KEY not set \u2014 AI extraction will fail.")
else:
    print(f"[BOOT] MISTRAL_API_KEY loaded: prefix={_MISTRAL_API_KEY[:8]}... length={len(_MISTRAL_API_KEY)}")

# Mistral Small 4 \u2014 119B MoE (6.5B active), 256k context, 148 t/s, 500k TPM free
_MISTRAL_MODEL = "mistral-small-2603"

def _get_mistral_client() -> Optional["Mistral"]:
    if not _MISTRAL_AVAILABLE:
        print("[AI] mistralai SDK not installed. Run: pip install mistralai")
        return None
    if not _MISTRAL_API_KEY:
        print("[AI] No Mistral API key provided.")
        return None
    print(f"[AI] Creating Mistral client with key prefix={_MISTRAL_API_KEY[:8]}... length={len(_MISTRAL_API_KEY)}")
    return Mistral(api_key=_MISTRAL_API_KEY)

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
# API KEY AUTH
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

_ENV_KEY = os.environ.get("AUDITOR_API_KEY", "").strip()
API_KEY  = _ENV_KEY if _ENV_KEY else secrets.token_hex(32)
if not _ENV_KEY:
    print(f"[BOOT] No AUDITOR_API_KEY \u2014 generated: {API_KEY}")

def verify_key(x_api_key: str = Header(..., alias="X-Api-Key")) -> str:
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return x_api_key

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
# MODELS
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

class ScrapeRequest(BaseModel):
    url:          str
    adaptive:     bool = True
    js:           bool = False
    extract_type: str  = "auto"

class ScrapeResponse(BaseModel):
    events:    List[Dict[str, Any]]
    raw_bytes: int
    elapsed:   float

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
# SSRF PROTECTION
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

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

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
# PREPROCESSING
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

_ZW_CHARS = re.compile(r'[\u200b\u200c\u200d\u2060\uFEFF\u00ad]')

_NOISE_TAGS = [
    'style', 'noscript', 'iframe', 'svg',
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

_JSON_DATA_SCRIPT_IDS = re.compile(
    r'(NEXT_DATA|__NUXT__|__INITIAL_STATE__|app-state|initial-data|'
    r'data-layer|redux-state|apollo-state|relay-store)',
    re.IGNORECASE,
)

# Semantic column name inference patterns
_TIME_PATTERN    = re.compile(r'^\d{1,2}:\d{2}(:\d{2})?(\s*(AM|PM))?$', re.IGNORECASE)
_DATE_PATTERN    = re.compile(
    r'\b(monday|tuesday|wednesday|thursday|friday|saturday|sunday|'
    r'january|february|march|april|may|june|july|august|september|'
    r'october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec)\b',
    re.IGNORECASE,
)
_COUNTRY_PATTERN = re.compile(r'^[A-Z]{2,3}$')
_NUMBER_PATTERN  = re.compile(r'^[+-]?\d+\.?\d*%?$')


def _normalize(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize('NFKC', text)
    text = _ZW_CHARS.sub('', text)
    return text.strip()


def _replace_img_with_alt(soup: BeautifulSoup) -> None:
    for img in soup.find_all('img'):
        if img.parent is None:
            continue
        text = (
            img.get('alt', '').strip()
            or img.get('title', '').strip()
            or img.get('aria-label', '').strip()
        )
        if text:
            img.replace_with(text)
        else:
            img.decompose()


def _extract_json_scripts(soup: BeautifulSoup) -> str:
    json_blocks = []
    for script in soup.find_all('script'):
        script_type = script.get('type', '').lower()
        script_id   = script.get('id', '')
        is_json = (
            script_type in ('application/json', 'application/ld+json')
            or bool(_JSON_DATA_SCRIPT_IDS.search(script_id))
        )
        if not is_json:
            continue
        raw_text = script.get_text(strip=True)
        if not raw_text or len(raw_text) > 50_000:
            continue
        try:
            parsed    = json.loads(raw_text)
            formatted = json.dumps(parsed, indent=2)
            label     = script_id or script_type or 'json-data'
            json_blocks.append(
                f"\n<!-- JSON DATA BLOCK: {label} -->\n<pre>{formatted}</pre>"
            )
            print(f"[JSON-SCRIPT] Preserved {len(raw_text):,} chars from script[id={label!r}]")
        except Exception:
            pass
    return '\n'.join(json_blocks)


def _infer_column_names(soup: BeautifulSoup) -> None:
    """Assign semantic names to empty <th> cells based on data patterns."""
    for table in soup.find_all('table'):
        rows = table.find_all('tr')
        if not rows:
            continue
        header_row = None
        for row in rows:
            if row.find('th'):
                header_row = row
                break
        if not header_row:
            continue
        headers   = header_row.find_all(['th', 'td'])
        data_rows = [r for r in rows if r != header_row and r.find('td')]
        if not data_rows:
            continue
        inferred = 0
        for col_idx, th in enumerate(headers):
            if th.get_text(strip=True):
                continue
            samples = []
            for dr in data_rows[:10]:
                cells = dr.find_all(['td', 'th'])
                if col_idx < len(cells):
                    val = cells[col_idx].get_text(strip=True)
                    if val:
                        samples.append(val)
            if not samples:
                continue
            threshold    = len(samples) * 0.5
            time_hits    = sum(1 for s in samples if _TIME_PATTERN.match(s))
            date_hits    = sum(1 for s in samples if _DATE_PATTERN.search(s))
            country_hits = sum(1 for s in samples if _COUNTRY_PATTERN.match(s))
            number_hits  = sum(1 for s in samples if _NUMBER_PATTERN.match(s))
            if time_hits >= threshold:
                name = "Time"
            elif date_hits >= threshold:
                name = "Date"
            elif country_hits >= threshold:
                name = "Country"
            elif number_hits >= threshold:
                name = "Value"
            else:
                continue
            th.string = name
            inferred += 1
            print(f"[INFER] col {col_idx+1} \u2192 '{name}' (samples: {samples[:3]})")
        if inferred:
            print(f"[INFER] {inferred} column name(s) inferred from data patterns")


def _clean_soup(soup: BeautifulSoup) -> Tuple[BeautifulSoup, str]:
    _replace_img_with_alt(soup)
    json_appendix = _extract_json_scripts(soup)

    for script in soup.find_all('script'):
        script.decompose()
    for tag in soup(_NOISE_TAGS):
        tag.decompose()
    for tag in soup.find_all(True):
        if tag.parent is None:
            continue
        classes = ' '.join(tag.get('class', []))
        tag_id  = tag.get('id', '')
        if _NOISE_ATTR_RE.search(classes) or _NOISE_ATTR_RE.search(tag_id):
            tag.decompose()
    for tag in soup.find_all(_INLINE_UNWRAP_TAGS):
        if tag.parent is None:
            continue
        tag.unwrap()

    _infer_column_names(soup)

    for tag in soup.find_all(True):
        tag.attrs = {
            k: v for k, v in tag.attrs.items()
            if not _STRIP_ATTRS_RE.match(k)
        }

    return soup, json_appendix


def _extract_main_content(html: str) -> str:
    soup = BeautifulSoup(html, 'html.parser')
    soup, json_appendix = _clean_soup(soup)
    body = str(soup)
    if json_appendix:
        print(f"[PREPROCESS] Appending {len(json_appendix):,} chars of JSON initial-state data")
    return body + json_appendix

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
# TABLE ISOLATION
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

def _score_table(table_tag: Tag) -> int:
    rows      = table_tag.find_all('tr')
    if not rows:
        return 0
    max_cols  = max((len(r.find_all(['td', 'th'])) for r in rows), default=0)
    data_rows = sum(1 for r in rows if r.find('td'))
    return data_rows * max_cols


def _find_best_table(html: str) -> str:
    soup   = BeautifulSoup(html, 'html.parser')
    tables = soup.find_all('table')

    if not tables:
        print("[TABLE] No <table> elements found \u2014 using full cleaned HTML")
        return html

    scored = []
    for i, t in enumerate(tables):
        score = _score_table(t)
        if score > 2:
            rows    = len(t.find_all('tr'))
            cols    = max((len(r.find_all(['td', 'th'])) for r in t.find_all('tr')), default=0)
            preview = t.get_text(separator=' ', strip=True)[:80].replace('\n', ' ')
            print(f"[TABLE] candidate #{i+1}: score={score} rows={rows} cols={cols} | {preview!r}")
        scored.append((score, i, t))

    if not scored:
        return html

    scored.sort(key=lambda x: -x[0])
    best_score, best_idx, best_table = scored[0]
    print(f"[TABLE] Selected #{best_idx+1} (score={best_score})")
    return str(best_table)


def _preprocess_html(html_bytes: bytes) -> str:
    try:
        text = html_bytes.decode('utf-8', errors='replace')
    except Exception:
        text = html_bytes.decode('latin-1', errors='replace')

    original_len = len(text)
    cleaned      = _extract_main_content(text)
    cleaned_len  = len(cleaned)
    print(f"[PREPROCESS] {original_len:,} \u2192 {cleaned_len:,} chars after noise removal "
          f"({100 * cleaned_len / max(original_len, 1):.1f}% retained)")

    isolated     = _find_best_table(cleaned)
    isolated_len = len(isolated)
    print(f"[PREPROCESS] {cleaned_len:,} \u2192 {isolated_len:,} chars after table isolation")

    return isolated

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
# DYNAMIC ROW-BOUNDARY BATCHING
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

def _split_table_into_batches(html: str) -> List[Tuple[str, int, int]]:
    soup     = BeautifulSoup(html, 'html.parser')
    all_rows = soup.find_all('tr')

    if not all_rows:
        print("[BATCH] No <tr> elements \u2014 treating as single non-table batch")
        return [(html, 0, 0)]

    header_row = None
    data_rows  = []
    for row in all_rows:
        if header_row is None and row.find('th'):
            header_row = row
        else:
            data_rows.append(row)

    header_html  = str(header_row) if header_row else ""
    header_chars = len(header_html)
    total_rows   = len(data_rows)

    if total_rows == 0:
        print("[BATCH] No data rows \u2014 sending header only")
        return [(html, 0, 0)]

    sample        = data_rows[:min(10, total_rows)]
    sample_chars  = sum(len(str(r)) for r in sample)
    avg_row_chars = max(sample_chars / len(sample), 1)

    usable_per_batch = BATCH_USABLE - header_chars
    batch_size       = max(int(usable_per_batch / avg_row_chars), 1)
    num_batches      = math.ceil(total_rows / batch_size)
    est_tokens       = int(avg_row_chars / CHARS_PER_TOKEN)

    print(f"[BATCH] Plan: {total_rows} rows | avg row={avg_row_chars:.0f} chars "
          f"({est_tokens} tokens) | batch_size={batch_size} rows | "
          f"batches={num_batches} | header={header_chars} chars")

    total_data_chars = sum(len(str(r)) for r in data_rows)
    if total_data_chars + header_chars <= BATCH_USABLE:
        print(f"[BATCH] All {total_rows} rows fit in one batch "
              f"({total_data_chars + header_chars:,} chars) \u2014 no splitting")
        return [(html, 0, total_rows - 1)]

    batches: List[Tuple[str, int, int]] = []
    current_rows: List[Tag] = []
    current_chars: int      = header_chars
    batch_start_idx: int    = 0

    for i, row in enumerate(data_rows):
        row_html  = str(row)
        row_chars = len(row_html)

        if row_chars > BATCH_USABLE:
            if current_rows:
                batch_html = _assemble_batch_html(header_html, current_rows)
                batches.append((batch_html, batch_start_idx, i - 1))
                _log_batch_plan(len(batches), num_batches, batch_start_idx, i - 1, batch_html)
                current_rows  = []
                current_chars = header_chars
            batch_html = _assemble_batch_html(header_html, [row])
            batches.append((batch_html, i, i))
            print(f"[BATCH] #{len(batches)}/{num_batches}: "
                  f"row {i+1} (OVERSIZED: {row_chars:,} chars)")
            batch_start_idx = i + 1
            continue

        if current_chars + row_chars > BATCH_USABLE and current_rows:
            batch_html = _assemble_batch_html(header_html, current_rows)
            batches.append((batch_html, batch_start_idx, i - 1))
            _log_batch_plan(len(batches), num_batches, batch_start_idx, i - 1, batch_html)
            current_rows    = []
            current_chars   = header_chars
            batch_start_idx = i

        current_rows.append(row)
        current_chars += row_chars

    if current_rows:
        batch_html = _assemble_batch_html(header_html, current_rows)
        batches.append((batch_html, batch_start_idx, total_rows - 1))
        _log_batch_plan(len(batches), num_batches, batch_start_idx, total_rows - 1, batch_html)

    print(f"[BATCH] Split complete: {len(batches)} batches for {total_rows} rows")
    return batches


def _log_batch_plan(batch_num: int, total: int, start: int, end: int, html: str) -> None:
    chars  = len(html)
    tokens = chars // CHARS_PER_TOKEN
    print(f"[BATCH] #{batch_num}/{total}: rows {start+1}\u2013{end+1} | "
          f"{chars:,} chars | ~{tokens:,} tokens")


def _assemble_batch_html(header_html: str, rows: List[Tag]) -> str:
    rows_html = ''.join(str(r) for r in rows)
    return f"<table>{header_html}{rows_html}</table>"

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
# EXTRACTION QUALITY GATE
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

def _count_populated(row: Dict[str, Any]) -> int:
    return sum(
        1 for v in row.values()
        if v is not None and str(v).strip() not in ("", "null", "N/A", "-")
    )


def _majority_schema(rows: List[Dict[str, Any]]) -> set:
    if not rows:
        return set()
    key_counter: Counter = Counter()
    for row in rows:
        for k in row.keys():
            key_counter[k] += 1
    threshold = len(rows) * MIN_SCHEMA_OVERLAP
    return {k for k, c in key_counter.items() if c >= threshold}


def _rows_have_data(rows: List[Dict[str, Any]]) -> bool:
    if not rows:
        return False

    good_rows = sum(1 for r in rows if _count_populated(r) >= MIN_FIELDS_PER_ROW)
    quality   = good_rows / len(rows)
    print(f"[QUALITY] {good_rows}/{len(rows)} rows have \u2265{MIN_FIELDS_PER_ROW} fields "
          f"(quality={quality:.0%})")

    if quality < MIN_QUALITY_RATIO:
        return False

    majority = _majority_schema(rows)
    if majority:
        consistent     = sum(
            1 for r in rows
            if len(set(r.keys()) & majority) / len(majority) >= MIN_SCHEMA_OVERLAP
        )
        schema_quality = consistent / len(rows)
        print(f"[QUALITY] Schema consistency: {consistent}/{len(rows)} ({schema_quality:.0%})")
        if schema_quality < MIN_QUALITY_RATIO:
            print(f"[QUALITY] Mixed-table contamination \u2014 triggering retry")
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
    print(f"[STATS{' ' + label if label else ''}] {total} rows \u00b7 field coverage:")
    for key, count in sorted(all_keys.items(), key=lambda x: -x[1]):
        bar   = "\u2588" * int(10 * count / total) + "\u2591" * (10 - int(10 * count / total))
        empty = "  \u2190 EMPTY KEY" if str(key).strip() == "" else ""
        print(f"  {bar} {count:>3}/{total}  '{key}'{empty}")

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
# POST-PROCESSING
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

def _sanitize_value(v: Any) -> Any:
    if not isinstance(v, str):
        return v
    cleaned = _HTML_TAG_RE.sub('', v).strip()
    cleaned = re.sub(r'\s+', ' ', cleaned)
    return cleaned if cleaned else None


def _clean_row_keys(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cleaned  = []
    promoted = 0
    dropped  = 0
    for row in rows:
        new_row: Dict[str, Any] = {}
        for k, v in row.items():
            if k is None or str(k).strip() == "":
                if v is not None and str(v).strip() and "label" not in row:
                    new_row["label"] = _sanitize_value(v)
                    promoted += 1
                else:
                    dropped += 1
            else:
                new_row[k] = _sanitize_value(v)
        cleaned.append(new_row)
    if promoted or dropped:
        print(f"[POSTPROCESS] Empty-key cleanup: {promoted} promoted to 'label', "
              f"{dropped} dropped")
    return cleaned


def _sanitize_row_values(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    stripped = [{k: _sanitize_value(v) for k, v in row.items()} for row in rows]
    return _clean_row_keys(stripped)

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
# AI EXTRACTION ENGINE \u2014 Mistral Small 4
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

def extract_with_ai(html_content: str, url: str, extract_type: str = "auto") -> List[Dict[str, Any]]:
    """
    Entry point. Splits large tables into row-boundary batches, calls Mistral
    per batch, merges results. No delays needed \u2014 500k TPM gives ample headroom.
    """
    batches = _split_table_into_batches(html_content)

    if len(batches) == 1:
        result = _extract_with_mistral(html_content, url, extract_type)
        return result if result is not None else []

    all_rows: List[Dict[str, Any]] = []
    for idx, (batch_html, start, end) in enumerate(batches):
        batch_num = idx + 1
        print(f"[BATCH] Sending batch {batch_num}/{len(batches)} to AI "
              f"(rows {start+1}\u2013{end+1})")
        result = _extract_with_mistral(batch_html, url, extract_type)
        if result:
            print(f"[BATCH] #{batch_num} result: {len(result)} records extracted")
            all_rows.extend(result)
        else:
            print(f"[BATCH] #{batch_num} result: 0 records \u2014 batch may have failed")

    print(f"[BATCH] Merge complete: {len(all_rows)} total records from {len(batches)} batches")
    return all_rows[:MAX_RECORDS]


def _extract_with_mistral(html: str, url: str, extract_type: str) -> Optional[List[Dict[str, Any]]]:
    client = _get_mistral_client()
    if not client:
        return None
    prompt = _build_accuracy_prompt(html, url, extract_type)
    try:
        print(f"[AI] Sending to {_MISTRAL_MODEL} ({len(html):,} chars "
              f"~{len(html) // CHARS_PER_TOKEN:,} tokens)")
        response = client.chat.complete(
            model=_MISTRAL_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            # reasoning_effort="none" disables chain-of-thought \u2014 pure extraction
            # is faster and cheaper without it (no reasoning tokens billed)
            extra_body={"reasoning_effort": "none"},
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
            "Extract from that ONE structure only."
        ),
    )

    return f"""You are a universal data extraction engine. Extract all structured data from the HTML below.

STRICT RULES:
1. READ the actual column headers or field labels from the HTML. Use them EXACTLY as JSON keys.
   Do NOT rename, translate, shorten, or invent keys.
2. Extract EVERY column/field you find. Do not skip any.
3. Copy ALL values as plain text \u2014 preserve signs (+/-), units (BTC, ETH, $, %, K, M, B, T).
4. Values must be plain text strings only. Never include HTML tags in values.
5. If a cell is empty or missing, use null.
6. Do NOT add fields not in the source. Do NOT hallucinate values.
7. Extract from ONE table/structure only. Do NOT merge rows from different tables.
8. Return ONLY a valid JSON array \u2014 no markdown fences, no explanation, no preamble.
9. If no structured data is found, return: []

HEADER FALLBACK:
If the HTML has NO visible column headers (empty <th> or none at all):
  - Name the first column "label" (usually the row name/entity).
  - Name subsequent columns "col_2", "col_3", "col_4" etc. left-to-right.
  - Still extract every value from every column.

IMAGE-TEXT RULE:
Some cells contain only a plain text name (converted from <img alt="..."> before you
received this HTML). Treat that plain text as the cell value normally.

DATA-ATTRIBUTE HINT:
If visible cell text is empty but data-sort-value / data-raw / data-num / data-usd
attributes exist on the same element, use the attribute value as the cell value.

JSON DATA BLOCKS:
The HTML may contain <!-- JSON DATA BLOCK: ... --> sections with <pre> JSON.
If these blocks contain more complete data than the table, prefer them.

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

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
# FETCHING LAYER
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

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

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
# MAIN SCRAPE PIPELINE
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

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
    print(f"[SCRAPE] {url} \u2192 {raw_bytes:,} bytes (js={used_js})")

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

    _log_extraction_stats(rows, label="attempt=1")

    needs_better = not used_js and not _rows_have_data(rows) and raw_bytes >= 51_200

    if needs_better:
        if _STEALTH_AVAILABLE:
            print(f"[SCRAPE] Low-quality extraction \u2014 retrying with JS renderer")
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
                        print(f"[SCRAPE] JS retry also low quality \u2014 returning []")
                        rows = []
            except Exception as e:
                print(f"[SCRAPE] JS retry failed: {e}")
        else:
            print(
                f"[SCRAPE] Page appears JS-rendered (ghost rows) but StealthyFetcher "
                f"unavailable \u2014 returning [] to avoid ghost rows."
            )
            rows = []

    print(f"[SCRAPE] Final: {len(rows)} records (js={used_js})")
    return rows, raw_bytes

# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
# FASTAPI APPLICATION
# \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550

app = FastAPI(title="AUDITOR CORE", version="9.8.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    errors = "; ".join(
        f"{' \u2192 '.join(str(l) for l in e['loc'])}: {e['msg']}" for e in exc.errors()
    )
    return JSONResponse(status_code=422, content={"detail": f"Validation error \u2014 {errors}"})

@app.get("/", include_in_schema=False)
async def serve_frontend():
    base_dir  = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(base_dir, "index.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    return HTMLResponse(content="<h2>404 \u2014 index.html not found</h2>", status_code=404)

@app.get("/api/key")
async def get_api_key():
    return JSONResponse({"api_key": API_KEY})

@app.get("/api/health")
async def health():
    return {
        "status":             "ok",
        "version":            "9.8.0",
        "fetcher":            _FETCHER_AVAILABLE,
        "stealth":            _STEALTH_AVAILABLE,
        "mistral":            _MISTRAL_AVAILABLE,
        "readability":        False,
        "ai_model":           _MISTRAL_MODEL if _MISTRAL_AVAILABLE else None,
        "max_safe_chars":     MAX_SAFE_CHARS,
        "max_batch_chars":    MAX_BATCH_CHARS,
        "batch_usable":       BATCH_USABLE,
        "min_fields_per_row": MIN_FIELDS_PER_ROW,
        "min_quality_ratio":  MIN_QUALITY_RATIO,
        "min_schema_overlap": MIN_SCHEMA_OVERLAP,
        "utc":                datetime.now(timezone.utc).isoformat(),
    }

@app.get("/api/debug-fetch")
async def debug_fetch(url: str, js: bool = False, _key: str = Depends(verify_key)):
    """Debug without AI: sizes at each processing stage + batch plan + preview."""
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="Forbidden domain")
    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(
            None, _fetch_js if js else _fetch_static, url
        )
        raw      = _get_raw_bytes(response)
        text     = raw.decode('utf-8', errors='replace')
        cleaned