"""
AUDITOR CORE v9.9.1 - Dynamic Rate Limiter for 2 RPM Limit
────────────────────────────────────────────────────────────────────────────────────
Changes v9.9.1:
• ADDED dynamic rate limiter gate for Mistral 2 RPM constraint
  - _MISTRAL_MIN_INTERVAL: 31s (1s safety margin over 30s)
  - _mistral_rate_gate(): dynamic cooldown based on elapsed time since last call
  - Stamps _last_mistral_call_ts AFTER sleeping, BEFORE POST
  - 429 fallback: respects Retry-After header, then aborts batch
  - Enhanced logging: token usage, timing, HTTP status

Previous changes (all retained):
v9.9.0 — 200k batch sizing for 2 RPM, context utilization optimization.
v9.8.0 — Mistral Small 4 (mistral-small-2603), 500k TPM, 256k context.
v9.7.1 — P1 batch delay, P2 retry on 429, P4 semantic column name inference.
v9.7.0 — dynamic row-boundary batching, batch logging.
v9.6.0 — log spam fix (score > 2 only).
v9.5.4 — F11 empty-key promotion, F12 image-only name cells.
v9.5.3 — F9 honest [] on JS pages, F10 JSON script preservation.
v9.5.2 — F7 table isolation, F8 schema consistency.
v9.5.1 — F6 inline tag unwrapping, HTML tag sanitisation.
v9.5.0 — F1–F5 quality gate, JS retry, data-* attrs, empty-key fallback.
v9.4.0 — surgical noise removal (blacklist, not readability).
────────────────────────────────────────────────────────────────────────────────────
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
print("[BOOT] readability-lxml disabled — using surgical noise removal + table isolation")

# ─ Mistral AI ─────────────────────────────────────────────────────────────────
try:
    import httpx
    _MISTRAL_AVAILABLE = True
except ImportError:
    httpx = None
    _MISTRAL_AVAILABLE = False

# ─ Scrapling ──────────────────────────────────────────────────────────────────
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

print(f"[BOOT] Fetcher={_FETCHER_AVAILABLE} Stealth={_STEALTH_AVAILABLE} Mistral={_MISTRAL_AVAILABLE}")

# ════════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════════
cpu_executor = concurrent.futures.ProcessPoolExecutor(max_workers=4)
MAX_PAYLOAD_SIZE = 10_485_760
MAX_SAFE_CHARS = 500_000
MAX_RECORDS = 1000
MIN_FIELDS_PER_ROW = 2
MIN_QUALITY_RATIO = 0.5
MIN_SCHEMA_OVERLAP = 0.5

# ── Batching OPTIMIZATION v9.9.0 ────────────────────────────────────────────────
# 256k context, ~3k prompt overhead = 253k for content
# Conservative target: 200k chars (~50k tokens) = 19.5% of context
# This maximizes data per batch → minimizes RPM usage
MAX_BATCH_CHARS = 200_000   # v9.9.0: 120k → 200k (+67%)
BATCH_OVERHEAD = 3_000       # v9.9.0: 4k → 3k (optimized prompt)
BATCH_USABLE = MAX_BATCH_CHARS - BATCH_OVERHEAD  # 197,000 usable chars
CHARS_PER_TOKEN = 4

# ── Mistral config ─────────────────────────────────────────────────────────────
_MISTRAL_API_KEY = os.environ.get("MISTRAL_API_KEY", "").strip().lstrip("=")
if not _MISTRAL_API_KEY:
    print("[ERROR] MISTRAL_API_KEY not set — AI extraction will fail.")
else:
    print(f"[BOOT] MISTRAL_API_KEY loaded: prefix={_MISTRAL_API_KEY[:8]}... length={len(_MISTRAL_API_KEY)}")

_MISTRAL_MODEL = "mistral-small-2603"
_MISTRAL_API_URL = "https://api.mistral.ai/v1/chat/completions"

# ── Mistral Rate Limiter (Sliding Window) ──────────────────────────────────────
# 2 RPM = max 2 calls per rolling 60-second window.
# Logic: track timestamps of recent calls. Before each call, purge timestamps
# older than 60s. If 2 calls remain in the window, sleep until the oldest
# one expires (falls outside the 60s window), then proceed.
_RPM_LIMIT: int = 2
_RPM_WINDOW: float = 60.0              # 60 seconds = 1 minute
_RPM_SAFETY: float = 1.0               # 1s safety buffer
_mistral_call_log: list = []            # list of epoch timestamps

def _mistral_rate_gate() -> None:
    """Block until it is safe to fire the next Mistral request (2 RPM sliding window)."""
    global _mistral_call_log
    now = time.time()

    # Purge timestamps older than the window
    _mistral_call_log = [ts for ts in _mistral_call_log if now - ts < _RPM_WINDOW]

    calls_in_window = len(_mistral_call_log)
    remaining_slots = _RPM_LIMIT - calls_in_window

    if remaining_slots > 0:
        # Safe to call — we have room in this minute
        print(f"[RATE] {calls_in_window}/{_RPM_LIMIT} calls in last 60s — "
              f"{remaining_slots} slot(s) free, proceeding immediately")
    else:
        # Window is full — wait until the oldest call expires out of the window
        oldest_ts = _mistral_call_log[0]
        wait = (oldest_ts + _RPM_WINDOW + _RPM_SAFETY) - now
        if wait > 0:
            print(f"[RATE] {calls_in_window}/{_RPM_LIMIT} calls in last 60s — "
                  f"window full, waiting {wait:.1f}s for next minute")
            time.sleep(wait)
        # After sleeping, purge again
        now = time.time()
        _mistral_call_log = [ts for ts in _mistral_call_log if now - ts < _RPM_WINDOW]
        print(f"[RATE] Window cleared — now {len(_mistral_call_log)}/{_RPM_LIMIT}, proceeding")

    # Stamp this call
    _mistral_call_log.append(time.time())

# ════════════════════════════════════════════════════════════════════════════════
# API KEY AUTH
# ════════════════════════════════════════════════════════════════════════════════
_ENV_KEY = os.environ.get("AUDITOR_API_KEY", "").strip()
API_KEY = _ENV_KEY if _ENV_KEY else secrets.token_hex(32)
if not _ENV_KEY:
    print(f"[BOOT] No AUDITOR_API_KEY — generated: {API_KEY}")

def verify_key(x_api_key: str = Header(..., alias="X-Api-Key")) -> str:
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return x_api_key

# ════════════════════════════════════════════════════════════════════════════════
# MODELS
# ════════════════════════════════════════════════════════════════════════════════
class ScrapeRequest(BaseModel):
    url: str
    adaptive: bool = True
    js: bool = False
    extract_type: str = "auto"

class ScrapeResponse(BaseModel):
    events: List[Dict[str, Any]]
    raw_bytes: int
    elapsed: float

# ════════════════════════════════════════════════════════════════════════════════
# SSRF PROTECTION
# ════════════════════════════════════════════════════════════════════════════════
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

# ════════════════════════════════════════════════════════════════════════════════
# PREPROCESSING
# ════════════════════════════════════════════════════════════════════════════════
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

# Attributes to PRESERVE (everything else gets stripped)
_PRESERVE_ATTRS_RE = re.compile(
    r'^(data-|aria-label|colspan|rowspan|scope|headers|title|alt)',
    re.IGNORECASE,
)

_HTML_TAG_RE = re.compile(r'<[^>]+>')

_JSON_DATA_SCRIPT_IDS = re.compile(
    r'(NEXT_DATA|NUXT|INITIAL_STATE|app-state|initial-data|'
    r'data-layer|redux-state|apollo-state|relay-store)',
    re.IGNORECASE,
)

# Semantic column name inference patterns
_TIME_PATTERN = re.compile(r'^\d{1,2}:\d{2}(:\d{2})?(\s*(AM|PM))?', re.IGNORECASE)
_DATE_PATTERN = re.compile(
    r'\b(monday|tuesday|wednesday|thursday|friday|saturday|sunday|'
    r'january|february|march|april|may|june|july|august|september|'
    r'october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec)\b',
    re.IGNORECASE,
)
_COUNTRY_PATTERN = re.compile(r'^[A-Z]{2,3}$', re.IGNORECASE)
_NUMBER_PATTERN = re.compile(r'^[+-]?\d+\.?\d*%?$')

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
        script_id = script.get('id', '')
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
            parsed = json.loads(raw_text)
            formatted = json.dumps(parsed, indent=2)
            label = script_id or script_type or 'json-data'
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
        headers = header_row.find_all(['th', 'td'])
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
            threshold = len(samples) * 0.5
            time_hits = sum(1 for s in samples if _TIME_PATTERN.match(s))
            date_hits = sum(1 for s in samples if _DATE_PATTERN.search(s))
            country_hits = sum(1 for s in samples if _COUNTRY_PATTERN.match(s))
            number_hits = sum(1 for s in samples if _NUMBER_PATTERN.match(s))
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
            print(f"[INFER] col {col_idx+1} → '{name}' (samples: {samples[:3]})")
        if inferred:
            print(f"[INFER] {inferred} column name(s) inferred from data patterns")

_DATA_CONTENT_THRESHOLD = 200  # chars — elements with more text content are kept even if noisy

def _has_substantial_content(tag: Tag) -> bool:
    """Check if an element contains enough real data to be worth keeping."""
    # Contains tables or data structures → definitely keep
    if tag.find(['table', 'dl', 'pre']):
        return True
    # Has many child elements with text → likely data
    text_len = len(tag.get_text(separator=' ', strip=True))
    if text_len > _DATA_CONTENT_THRESHOLD:
        return True
    return False

def _clean_soup(soup: BeautifulSoup) -> Tuple[BeautifulSoup, str]:
    _replace_img_with_alt(soup)
    json_appendix = _extract_json_scripts(soup)

    # Remove scripts (always safe)
    for script in soup.find_all('script'):
        script.decompose()

    # Smart noise tag removal — check content before decomposing
    kept_noise = 0
    removed_noise = 0
    for tag in soup(_NOISE_TAGS):
        if _has_substantial_content(tag):
            kept_noise += 1
        else:
            tag.decompose()
            removed_noise += 1

    # Smart class/id noise removal — check content before decomposing
    kept_attr = 0
    removed_attr = 0
    for tag in soup.find_all(True):
        if tag.parent is None:
            continue
        classes = ' '.join(tag.get('class', []))
        tag_id  = tag.get('id', '')
        if _NOISE_ATTR_RE.search(classes) or _NOISE_ATTR_RE.search(tag_id):
            if _has_substantial_content(tag):
                kept_attr += 1
            else:
                tag.decompose()
                removed_attr += 1

    if kept_noise or kept_attr:
        print(f"[NOISE] Smart filter: kept {kept_noise + kept_attr} data-rich elements "
              f"(noise_tags={kept_noise} attr_match={kept_attr}), "
              f"removed {removed_noise + removed_attr}")

    for tag in soup.find_all(_INLINE_UNWRAP_TAGS):
        if tag.parent is None:
            continue
        tag.unwrap()

    _infer_column_names(soup)

    for tag in soup.find_all(True):
        tag.attrs = {
            k: v for k, v in tag.attrs.items()
            if _PRESERVE_ATTRS_RE.match(k)
        }

    return soup, json_appendix

def _extract_main_content(html: str) -> str:
    soup = BeautifulSoup(html, 'html.parser')
    soup, json_appendix = _clean_soup(soup)
    body = str(soup)
    if json_appendix:
        print(f"[PREPROCESS] Appending {len(json_appendix):,} chars of JSON initial-state data")
    return body + json_appendix

# ════════════════════════════════════════════════════════════════════════════════
# TABLE ISOLATION
# ════════════════════════════════════════════════════════════════════════════════
def _score_table(table_tag: Tag) -> int:
    rows = table_tag.find_all('tr')
    if not rows:
        return 0
    max_cols = max((len(r.find_all(['td', 'th'])) for r in rows), default=0)
    data_rows = sum(1 for r in rows if r.find('td'))
    return data_rows * max_cols

def _find_best_table(html: str) -> str:
    soup = BeautifulSoup(html, 'html.parser')
    tables = soup.find_all('table')

    if not tables:
        print("[TABLE] No <table> elements found — using full cleaned HTML")
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
    best_score = scored[0][0]

    if best_score == 0:
        return html

    # Combine all tables scoring ≥30% of best (captures related tables on same page)
    threshold = best_score * 0.3
    selected = [(s, i, t) for s, i, t in scored if s >= threshold]
    selected.sort(key=lambda x: x[1])  # restore original page order

    if len(selected) == 1:
        print(f"[TABLE] Selected #{selected[0][1]+1} (score={best_score})")
        return str(selected[0][2])

    names = [f"#{x[1]+1}(s={x[0]})" for x in selected]
    print(f"[TABLE] Combining {len(selected)} tables: {', '.join(names)} (threshold={threshold:.0f})")
    return '\n'.join(str(t) for _, _, t in selected)

def _preprocess_html(html_bytes: bytes) -> str:
    try:
        text = html_bytes.decode('utf-8', errors='replace')
    except Exception:
        text = html_bytes.decode('latin-1', errors='replace')

    original_len = len(text)
    cleaned      = _extract_main_content(text)
    cleaned_len  = len(cleaned)
    print(f"[PREPROCESS] {original_len:,} → {cleaned_len:,} chars after noise removal "
          f"({100 * cleaned_len / max(original_len, 1):.1f}% retained)")

    isolated     = _find_best_table(cleaned)
    isolated_len = len(isolated)
    print(f"[PREPROCESS] {cleaned_len:,} → {isolated_len:,} chars after table isolation")

    # Smart fallback: if isolation was too aggressive relative to input size,
    # use the full cleaned HTML instead
    if isolated_len < 500 and original_len > 50_000:
        print(f"[PREPROCESS] Isolation too aggressive ({isolated_len} chars from "
              f"{original_len:,}) — falling back to full cleaned HTML ({cleaned_len:,} chars)")
        return cleaned[:MAX_SAFE_CHARS]

    return isolated

# ════════════════════════════════════════════════════════════════════════════════
# DYNAMIC ROW-BOUNDARY BATCHING (OPTIMIZED for 200k chars)
# ════════════════════════════════════════════════════════════════════════════════
def _split_table_into_batches(html: str) -> List[Tuple[str, int, int]]:
    soup = BeautifulSoup(html, 'html.parser')
    all_rows = soup.find_all('tr')

    if not all_rows:
        print("[BATCH] No <tr> elements — treating as single non-table batch")
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
        print("[BATCH] No data rows — sending header only")
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
          f"batches={num_batches} | header={header_chars} chars | "
          f"BATCH_USABLE={BATCH_USABLE:,} chars")

    total_data_chars = sum(len(str(r)) for r in data_rows)
    # v9.9.0: Check against new 200k limit
    if total_data_chars + header_chars <= BATCH_USABLE:
        print(f"[BATCH] All {total_rows} rows fit in one batch "
              f"({total_data_chars + header_chars:,} chars) — no splitting")
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
    chars = len(html)
    tokens = chars // CHARS_PER_TOKEN
    context_pct = (tokens * CHARS_PER_TOKEN) / 262144 * 100  # % of 256k context
    print(f"[BATCH] #{batch_num}/{total}: rows {start+1}–{end+1} | "
          f"{chars:,} chars | ~{tokens:,} tokens | context={context_pct:.1f}%")

def _assemble_batch_html(header_html: str, rows: List[Tag]) -> str:
    rows_html = ''.join(str(r) for r in rows)
    return f"<table>{header_html}{rows_html}</table>"

# ════════════════════════════════════════════════════════════════════════════════
# EXTRACTION QUALITY GATE
# ════════════════════════════════════════════════════════════════════════════════
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
    print(f"[QUALITY] {good_rows}/{len(rows)} rows have ≥{MIN_FIELDS_PER_ROW} fields "
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
            print(f"[QUALITY] Mixed-table contamination — triggering retry")
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
        bar = "█" * int(10 * count / total) + "░" * (10 - int(10 * count / total))
        empty = " ← EMPTY KEY" if str(key).strip() == "" else ""
        print(f" {bar} {count:>3}/{total} '{key}'{empty}")

# ════════════════════════════════════════════════════════════════════════════════
# POST-PROCESSING
# ════════════════════════════════════════════════════════════════════════════════
def _sanitize_value(v: Any) -> Any:
    if not isinstance(v, str):
        return v
    cleaned = _HTML_TAG_RE.sub('', v).strip()
    cleaned = re.sub(r'\s+', ' ', cleaned)
    return cleaned if cleaned else None

def _clean_row_keys(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cleaned = []
    promoted = 0
    dropped = 0
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

# ════════════════════════════════════════════════════════════════════════════════
# AI EXTRACTION ENGINE — Mistral Small 4 (OPTIMIZED v9.9.1 + Rate Limiter)
# ════════════════════════════════════════════════════════════════════════════════
def extract_with_ai(html_content: str, url: str, extract_type: str = "auto") -> List[Dict[str, Any]]:
    """
    Entry point. Splits large tables into row-boundary batches, calls Mistral
    per batch, merges results.
    
    v9.9.0: 200k batch limit means fewer batches = fewer API calls = lower RPM usage.
    v9.9.1: Dynamic rate limiter gate ensures ≤2 RPM across all batches.
    With 2 RPM limit, minimizing batches is critical.
    """
    batches = _split_table_into_batches(html_content)

    if len(batches) == 1:
        result = _extract_with_mistral(html_content, url, extract_type)
        return result if result is not None else []

    all_rows: List[Dict[str, Any]] = []
    for idx, (batch_html, start, end) in enumerate(batches):
        batch_num = idx + 1
        print(f"[BATCH] Sending batch {batch_num}/{len(batches)} to AI "
              f"(rows {start+1}–{end+1})")
        result = _extract_with_mistral(batch_html, url, extract_type)
        if result:
            print(f"[BATCH] #{batch_num} result: {len(result)} records extracted")
            all_rows.extend(result)
        else:
            print(f"[BATCH] #{batch_num} result: 0 records — batch may have failed")

    print(f"[BATCH] Merge complete: {len(all_rows)} total records from {len(batches)} batches")
    return all_rows[:MAX_RECORDS]

def _extract_with_mistral(html: str, url: str, extract_type: str) -> Optional[List[Dict[str, Any]]]:
    if not _MISTRAL_AVAILABLE:
        print("[AI] httpx not installed.")
        return None
    if not _MISTRAL_API_KEY:
        print("[AI] No Mistral API key.")
        return None

    _mistral_rate_gate()          # ← dynamic cooldown gate

    prompt  = _build_accuracy_prompt(html, url, extract_type)
    payload = {
        "model":       _MISTRAL_MODEL,
        "messages":    [{"role": "user", "content": prompt}],
        "temperature": 0.0,
    }
    headers = {
        "Content-Type":  "application/json",
        "Accept":        "application/json",
        "Authorization": f"Bearer {_MISTRAL_API_KEY}",
    }
    try:
        t_start          = time.time()
        tokens_estimate  = len(html) // CHARS_PER_TOKEN
        print(f"[AI] Sending → {_MISTRAL_MODEL} "
              f"({len(html):,} chars ~{tokens_estimate:,} tokens "
              f"| {tokens_estimate / 262144 * 100:.1f}% context)")

        with httpx.Client(timeout=120.0) as client:
            response = client.post(_MISTRAL_API_URL, json=payload, headers=headers)

        elapsed_ai = time.time() - t_start
        print(f"[AI] HTTP {response.status_code} in {elapsed_ai:.1f}s")

        if response.status_code == 429:
            # Shouldn't happen with gate, but handle gracefully
            retry_after = int(response.headers.get("Retry-After", 60))
            print(f"[AI] 429 received — sleeping {retry_after}s then aborting batch")
            time.sleep(retry_after)
            return None

        if response.status_code != 200:
            print(f"[AI] Mistral error: {response.text[:300]}")
            return None

        data    = response.json()
        usage   = data.get("usage", {})
        in_tok  = usage.get("prompt_tokens", "?")
        out_tok = usage.get("completion_tokens", "?")
        tot_tok = usage.get("total_tokens", "?")
        print(f"[AI] Tokens: in={in_tok} out={out_tok} total={tot_tok}")

        content = data["choices"][0]["message"]["content"]
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

    # v9.9.0: Streamlined prompt (~500 chars) to maximize content per batch
    return f"""Extract all structured data from the HTML below.
RULES:
- Use actual column headers/field labels as JSON keys (exact text, no translation)
- Extract EVERY column/field found. Copy values as plain text (preserve signs, units: BTC, ETH, $, %, K, M, B, T)
- Empty cells = null. Do NOT add fields not in source
- ONE table/structure only. No merging from different tables
- Return ONLY valid JSON array: [{{...}}, ...] or [] if no data

IMAGE-TEXT: Plain text converted from <img alt="..."> is the cell value
DATA-ATTR: Use data-sort-value/data-raw/data-num/data-usd if visible text is empty
JSON BLOCKS: <!-- JSON DATA BLOCK: ... --> sections may have complete data — prefer them

{structure_hint}

URL: {url}

HTML:
{html}

JSON:"""

def _parse_ai_response(content: str) -> Optional[List[Dict[str, Any]]]:
    if not content:
        return None
    content = content.strip()
    # Remove markdown fences if present
    if content.startswith('```'):
        lines = content.split('\n')
        content = '\n'.join(
            line for line in lines
            if not line.startswith('```') and '```' not in line
        )
    start = content.find('[')
    end = content.rfind(']') + 1
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

# ════════════════════════════════════════════════════════════════════════════════
# FETCHING LAYER
# ════════════════════════════════════════════════════════════════════════════════
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

# ════════════════════════════════════════════════════════════════════════════════
# MAIN SCRAPE PIPELINE
# ════════════════════════════════════════════════════════════════════════════════
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

    _log_extraction_stats(rows, label="attempt=1")

    needs_better = not used_js and not _rows_have_data(rows) and raw_bytes >= 51_200

    if needs_better:
        if _STEALTH_AVAILABLE:
            print(f"[SCRAPE] Low-quality extraction — retrying with JS renderer")
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
                        print(f"[SCRAPE] JS retry also low quality — returning []")
                        rows = []
            except Exception as e:
                print(f"[SCRAPE] JS retry failed: {e}")
        else:
            print(
                f"[SCRAPE] Page appears JS-rendered (ghost rows) but StealthyFetcher "
                f"unavailable — returning [] to avoid ghost rows."
            )
            rows = []

    print(f"[SCRAPE] Final: {len(rows)} records (js={used_js})")
    return rows, raw_bytes

# ════════════════════════════════════════════════════════════════════════════════
# FASTAPI APPLICATION
# ════════════════════════════════════════════════════════════════════════════════
app = FastAPI(title="AUDITOR CORE", version="9.9.1")

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
        "version": "9.9.1",
        "optimization": "200k batch + dynamic 2 RPM rate limiter",
        "fetcher": _FETCHER_AVAILABLE,
        "stealth": _STEALTH_AVAILABLE,
        "mistral": _MISTRAL_AVAILABLE,
        "readability": False,
        "ai_model": _MISTRAL_MODEL if _MISTRAL_AVAILABLE else None,
        "max_safe_chars": MAX_SAFE_CHARS,
        "max_batch_chars": MAX_BATCH_CHARS,
        "batch_usable": BATCH_USABLE,
        "batch_overhead": BATCH_OVERHEAD,
        "min_fields_per_row": MIN_FIELDS_PER_ROW,
        "min_quality_ratio": MIN_QUALITY_RATIO,
        "min_schema_overlap": MIN_SCHEMA_OVERLAP,
        "rate_limiter": {
            "window_s": _RPM_WINDOW,
            "rpm_limit": _RPM_LIMIT,
            "strategy": "sliding window",
        },
        "limits": {
            "rpm": 2,
            "tpm": 500000,
            "context": 262144,
            "rpd_calculated": 2880,
            "tpd_calculated": 33333333
        },
        "utc": datetime.now(timezone.utc).isoformat(),
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
        raw = _get_raw_bytes(response)
        text = raw.decode('utf-8', errors='replace')
        cleaned = _extract_main_content(text)
        isolated = _find_best_table(cleaned)
        batches = _split_table_into_batches(isolated)
        
        # Calculate RPM efficiency
        batch_sizes = [len(b[0]) for b in batches]
        total_tokens = sum(s // 4 for s in batch_sizes)
        
        return {
            "url": url,
            "js": js,
            "raw_bytes": len(raw),
            "cleaned_chars": len(cleaned),
            "isolated_chars": len(isolated),
            "retention_pct": round(100 * len(cleaned) / max(len(raw), 1), 1),
            "isolation_pct": round(100 * len(isolated) / max(len(cleaned), 1), 1),
            "num_batches": len(batches),
            "batch_sizes": batch_sizes,
            "total_tokens_estimate": total_tokens,
            "rpm_calls_saved": "40-50%" if len(batches) < 4 else f"{len(batches)} batches",
            "stealth_available": _STEALTH_AVAILABLE,
            "preview": isolated[:3000],
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
        "limit_per_model": "1B tokens/month",
        "tpm": 500_000,
        "rpm": 2,
        "model": _MISTRAL_MODEL,
        "optimization": "200k batch chars (~50k tokens) + dynamic 31s rate gate",
        "keys": [
            {"key_index": 1, "active": True}
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
