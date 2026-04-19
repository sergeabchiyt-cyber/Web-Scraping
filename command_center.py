"""
AUDITOR CORE v9.9.2 — Google AI Studio (Gemma 4 26B A4B)
"""

from dotenv import load_dotenv
load_dotenv()

import os, re, time, math, secrets, asyncio, socket, unicodedata, json
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

try:
    import httpx
    _AI_AVAILABLE = True
except ImportError:
    httpx = None
    _AI_AVAILABLE = False

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

print(f"[BOOT] Fetcher={_FETCHER_AVAILABLE} Stealth={_STEALTH_AVAILABLE} AI={_AI_AVAILABLE}")

# ════════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════════
cpu_executor = concurrent.futures.ProcessPoolExecutor(max_workers=4)
MAX_PAYLOAD_SIZE   = 10_485_760
MAX_SAFE_CHARS     = 500_000
MAX_RECORDS        = 1000
MIN_FIELDS_PER_ROW = 2
MIN_QUALITY_RATIO  = 0.5
MIN_SCHEMA_OVERLAP = 0.5

MAX_BATCH_CHARS = 200_000
BATCH_OVERHEAD  = 3_000
BATCH_USABLE    = MAX_BATCH_CHARS - BATCH_OVERHEAD
CHARS_PER_TOKEN = 4

_GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "").strip().lstrip("=")
if not _GOOGLE_API_KEY:
    print("[ERROR] GOOGLE_API_KEY not set — AI extraction will fail.")
else:
    print(f"[BOOT] GOOGLE_API_KEY loaded: prefix={_GOOGLE_API_KEY[:8]}... length={len(_GOOGLE_API_KEY)}")

_GOOGLE_MODEL   = "gemma-4-26b-a4b-it"
_GOOGLE_API_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"

_RPM_LIMIT      = 15
_RPM_WINDOW     = 60.0
_RPM_SAFETY     = 1.0
_mistral_call_log: list = []

def _mistral_rate_gate() -> None:
    global _mistral_call_log
    now = time.time()
    _mistral_call_log = [ts for ts in _mistral_call_log if now - ts < _RPM_WINDOW]
    calls_in_window  = len(_mistral_call_log)
    remaining_slots  = _RPM_LIMIT - calls_in_window
    if remaining_slots > 0:
        print(f"[RATE] {calls_in_window}/{_RPM_LIMIT} calls in last 60s — {remaining_slots} slot(s) free")
    else:
        oldest_ts = _mistral_call_log[0]
        wait = (oldest_ts + _RPM_WINDOW + _RPM_SAFETY) - now
        if wait > 0:
            print(f"[RATE] Window full — waiting {wait:.1f}s")
            time.sleep(wait)
        now = time.time()
        _mistral_call_log = [ts for ts in _mistral_call_log if now - ts < _RPM_WINDOW]
        print(f"[RATE] Window cleared — now {len(_mistral_call_log)}/{_RPM_LIMIT}")
    _mistral_call_log.append(time.time())

# ════════════════════════════════════════════════════════════════════════════════
# API KEY AUTH
# ════════════════════════════════════════════════════════════════════════════════
_ENV_KEY = os.environ.get("AUDITOR_API_KEY", "").strip()
API_KEY  = _ENV_KEY if _ENV_KEY else secrets.token_hex(32)
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
    url:          str
    adaptive:     bool = True
    js:           bool = False
    extract_type: str  = "auto"

class ScrapeResponse(BaseModel):
    events:    List[Dict[str, Any]]
    raw_bytes: int
    elapsed:   float

class RawResponse(BaseModel):
    url:           str
    raw_bytes:     int
    cleaned_chars: int
    isolated_chars: int
    retention_pct: float
    isolation_pct: float
    num_batches:   int
    batch_sizes:   List[int]
    content:       str
    elapsed:       float

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

# ════════════════════════════════════════════════════════════════════════════════
# PREPROCESSING
# ════════════════════════════════════════════════════════════════════════════════
_ZW_CHARS = re.compile(r'[\u200b\u200c\u200d\u2060\uFEFF\u00ad]')
_ALWAYS_REMOVE_TAGS  = ['script','style','noscript','iframe','svg','link','meta','base','template','br','hr']
_SMART_NOISE_TAGS    = ['nav','footer','aside','header','dialog']
_INLINE_UNWRAP_TAGS  = ['a','button','span','em','strong','b','i','u','label','small','sup','sub','abbr','cite','mark','bdi','bdo','time','ins','del','s']
_NOISE_ATTR_RE       = re.compile(r'\b(ad|ads|advert|advertisement|banner|cookie|popup|modal|overlay|sidebar|widget|promo|sponsor|social|share|comment|newsletter|breadcrumb|menu|navbar|toolbar|toast|notification|announcement|header|footer|nav|navigation|flyout|dropdown|offcanvas|drawer|skip-link|back-to-top|scroll-top|lightbox|carousel__control)\b', re.IGNORECASE)
_PRESERVE_ATTRS_RE   = re.compile(r'^(data-|aria-label|colspan|rowspan|scope|headers|title|alt|class)', re.IGNORECASE)
_HTML_TAG_RE         = re.compile(r'<[^>]+>')
_JSON_DATA_SCRIPT_IDS= re.compile(r'(NEXT_DATA|NUXT|INITIAL_STATE|app-state|initial-data|data-layer|redux-state|apollo-state|relay-store)', re.IGNORECASE)
_TIME_PATTERN        = re.compile(r'^\d{1,2}:\d{2}(:\d{2})?(\s*(AM|PM))?', re.IGNORECASE)
_DATE_PATTERN        = re.compile(r'\b(monday|tuesday|wednesday|thursday|friday|saturday|sunday|january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|oct|nov|dec)\b', re.IGNORECASE)
_COUNTRY_PATTERN     = re.compile(r'^[A-Z]{2,3}$', re.IGNORECASE)
_NUMBER_PATTERN      = re.compile(r'^[+-]?\d+\.?\d*%?$')
_DATA_CONTENT_THRESHOLD = 200

def _normalize(text: str) -> str:
    if not text: return ""
    text = unicodedata.normalize('NFKC', text)
    text = _ZW_CHARS.sub('', text)
    return text.strip()

def _replace_img_with_alt(soup: BeautifulSoup) -> None:
    for img in soup.find_all('img'):
        if img.parent is None: continue
        text = img.get('alt','').strip() or img.get('title','').strip() or img.get('aria-label','').strip()
        if text: img.replace_with(text)
        else:    img.decompose()

def _extract_json_scripts(soup: BeautifulSoup) -> str:
    json_blocks = []
    for script in soup.find_all('script'):
        script_type = script.get('type','').lower()
        script_id   = script.get('id','')
        is_json = (script_type in ('application/json','application/ld+json') or bool(_JSON_DATA_SCRIPT_IDS.search(script_id)))
        if not is_json: continue
        raw_text = script.get_text(strip=True)
        if not raw_text or len(raw_text) > 50_000: continue
        try:
            parsed    = json.loads(raw_text)
            formatted = json.dumps(parsed, indent=2)
            label     = script_id or script_type or 'json-data'
            json_blocks.append(f"\n<!-- JSON DATA BLOCK: {label} -->\n<pre>{formatted}</pre>")
        except Exception: pass
    return '\n'.join(json_blocks)

def _infer_column_names(soup: BeautifulSoup) -> None:
    for table in soup.find_all('table'):
        rows = table.find_all('tr')
        if not rows: continue
        header_row = None
        for row in rows:
            if row.find('th'): header_row = row; break
        if not header_row: continue
        headers   = header_row.find_all(['th','td'])
        data_rows = [r for r in rows if r != header_row and r.find('td')]
        if not data_rows: continue
        inferred = 0
        for col_idx, th in enumerate(headers):
            if th.get_text(strip=True): continue
            samples = []
            for dr in data_rows[:10]:
                cells = dr.find_all(['td','th'])
                if col_idx < len(cells):
                    val = cells[col_idx].get_text(strip=True)
                    if val: samples.append(val)
            if not samples: continue
            threshold   = len(samples) * 0.5
            time_hits   = sum(1 for s in samples if _TIME_PATTERN.match(s))
            date_hits   = sum(1 for s in samples if _DATE_PATTERN.search(s))
            country_hits= sum(1 for s in samples if _COUNTRY_PATTERN.match(s))
            number_hits = sum(1 for s in samples if _NUMBER_PATTERN.match(s))
            if   time_hits    >= threshold: name = "Time"
            elif date_hits    >= threshold: name = "Date"
            elif country_hits >= threshold: name = "Country"
            elif number_hits  >= threshold: name = "Value"
            else: continue
            th.string = name
            inferred += 1
        if inferred:
            print(f"[INFER] {inferred} column name(s) inferred from data patterns")

def _calc_data_density(text: str) -> float:
    if not text: return 0.0
    data_chars = sum(1 for c in text if c.isdigit() or c in '$%+-.,')
    return data_chars / len(text)

def _has_substantial_content(tag: Tag) -> bool:
    if tag.find(['table','dl','pre']): return True
    text = tag.get_text(separator=' ', strip=True)
    if len(text) > _DATA_CONTENT_THRESHOLD and _calc_data_density(text) > 0.05: return True
    return False

def _clean_soup(soup: BeautifulSoup) -> Tuple[BeautifulSoup, str]:
    _replace_img_with_alt(soup)
    json_appendix = _extract_json_scripts(soup)
    for tag in soup(_ALWAYS_REMOVE_TAGS): tag.decompose()
    for tag in soup(_SMART_NOISE_TAGS):
        if not _has_substantial_content(tag): tag.decompose()
    for tag in soup.find_all(True):
        if tag.parent is None: continue
        classes = ' '.join(tag.get('class',[]))
        tag_id  = tag.get('id','')
        if _NOISE_ATTR_RE.search(classes) or _NOISE_ATTR_RE.search(tag_id):
            if not _has_substantial_content(tag): tag.decompose()
    for tag in soup.find_all(_INLINE_UNWRAP_TAGS):
        if tag.parent is None: continue
        tag.unwrap()
    _infer_column_names(soup)
    for tag in soup.find_all(True):
        tag.attrs = {k: v for k, v in tag.attrs.items() if _PRESERVE_ATTRS_RE.match(k)}
    return soup, json_appendix

def _extract_main_content(html: str) -> str:
    soup = BeautifulSoup(html, 'html.parser')
    soup, json_appendix = _clean_soup(soup)
    return str(soup) + json_appendix

def _score_table(table_tag: Tag) -> int:
    rows     = table_tag.find_all('tr')
    if not rows: return 0
    max_cols = max((len(r.find_all(['td','th'])) for r in rows), default=0)
    data_rows= sum(1 for r in rows if r.find('td'))
    return data_rows * max_cols

def _get_structural_signature(tag: Tag) -> str:
    if not isinstance(tag, Tag): return ""
    ignore  = {'odd','even','active','hover','focus','first','last','selected','hidden','row-alt'}
    classes = sorted(c for c in tag.get('class',[]) if c.lower() not in ignore and not c.startswith('ng-') and not re.match(r'^(row|col)-\d+$', c))
    return f"{tag.name}:{'.'.join(classes)}" if classes else tag.name

def _find_repeated_structures(soup: BeautifulSoup) -> Optional[str]:
    candidates = []
    for container in soup.find_all(True):
        children = [c for c in container.children if isinstance(c, Tag)]
        if len(children) < 3: continue
        sig_groups: Dict[str, list] = {}
        for child in children:
            sig = _get_structural_signature(child)
            if sig: sig_groups.setdefault(sig, []).append(child)
        for sig, elements in sig_groups.items():
            count = len(elements)
            if count < 3: continue
            text_blocks  = [el.get_text(separator=' ', strip=True) for el in elements]
            full_text    = ' '.join(text_blocks)
            total_text   = len(full_text)
            total_html   = sum(len(str(el)) for el in elements)
            html_density = total_text / max(total_html, 1)
            if total_text < 50: continue
            data_density = _calc_data_density(full_text)
            if data_density < 0.05: continue
            score = count * (data_density + 0.1) * html_density
            candidates.append((score, count, data_density, sig, elements))
    if not candidates: return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    best_score, best_count, best_data_density, best_sig, best_elements = candidates[0]
    print(f"[DENSITY] Selected: {best_count}× '{best_sig}' score={best_score:.2f}")
    return '\n'.join(str(el) for el in best_elements)

def _find_best_table(html: str) -> str:
    soup   = BeautifulSoup(html, 'html.parser')
    tables = soup.find_all('table')
    if not tables:
        region = _find_repeated_structures(soup)
        return region if region else html
    scored = [((_score_table(t)), i, t) for i, t in enumerate(tables)]
    scored.sort(key=lambda x: -x[0])
    best_score = scored[0][0]
    if best_score == 0: return html
    threshold  = best_score * 0.3
    selected   = [(s, i, t) for s, i, t in scored if s >= threshold]
    selected.sort(key=lambda x: -x[0])
    if len(selected) == 1: return str(selected[0][2])
    return '\n'.join(str(t) for _, _, t in selected)

def _preprocess_html(html_bytes: bytes) -> str:
    try:    text = html_bytes.decode('utf-8', errors='replace')
    except: text = html_bytes.decode('latin-1', errors='replace')
    original_len = len(text)
    cleaned      = _extract_main_content(text)
    cleaned_len  = len(cleaned)
    print(f"[PREPROCESS] {original_len:,} → {cleaned_len:,} chars ({100*cleaned_len/max(original_len,1):.1f}% retained)")
    isolated     = _find_best_table(cleaned)
    isolated_len = len(isolated)
    print(f"[PREPROCESS] {cleaned_len:,} → {isolated_len:,} chars after table isolation")
    if isolated_len < 500 and original_len > 50_000:
        print(f"[PREPROCESS] Isolation too aggressive — falling back to full cleaned HTML")
        return cleaned[:MAX_SAFE_CHARS]
    return isolated

# ════════════════════════════════════════════════════════════════════════════════
# DYNAMIC ROW-BOUNDARY BATCHING
# ════════════════════════════════════════════════════════════════════════════════
def _split_table_into_batches(html: str) -> List[Tuple[str, int, int]]:
    soup     = BeautifulSoup(html, 'html.parser')
    all_rows = soup.find_all('tr')
    if not all_rows: return [(html, 0, 0)]
    header_row = None
    data_rows  = []
    for row in all_rows:
        if header_row is None and row.find('th'): header_row = row
        else: data_rows.append(row)
    header_html  = str(header_row) if header_row else ""
    header_chars = len(header_html)
    total_rows   = len(data_rows)
    if total_rows == 0: return [(html, 0, 0)]
    sample       = data_rows[:min(10, total_rows)]
    sample_chars = sum(len(str(r)) for r in sample)
    avg_row_chars= max(sample_chars / len(sample), 1)
    usable_per_batch = BATCH_USABLE - header_chars
    batch_size   = max(int(usable_per_batch / avg_row_chars), 1)
    num_batches  = math.ceil(total_rows / batch_size)
    print(f"[BATCH] Plan: {total_rows} rows | avg={avg_row_chars:.0f} chars | batches={num_batches}")
    total_data_chars = sum(len(str(r)) for r in data_rows)
    if total_data_chars + header_chars <= BATCH_USABLE:
        return [(html, 0, total_rows - 1)]
    batches: List[Tuple[str, int, int]] = []
    current_rows:  List[Tag] = []
    current_chars: int       = header_chars
    batch_start_idx: int     = 0
    for i, row in enumerate(data_rows):
        row_html  = str(row)
        row_chars = len(row_html)
        if row_chars > BATCH_USABLE:
            if current_rows:
                batch_html = _assemble_batch_html(header_html, current_rows)
                batches.append((batch_html, batch_start_idx, i - 1))
                current_rows  = []
                current_chars = header_chars
            batches.append((_assemble_batch_html(header_html, [row]), i, i))
            batch_start_idx = i + 1
            continue
        if current_chars + row_chars > BATCH_USABLE and current_rows:
            batches.append((_assemble_batch_html(header_html, current_rows), batch_start_idx, i - 1))
            current_rows    = []
            current_chars   = header_chars
            batch_start_idx = i
        current_rows.append(row)
        current_chars += row_chars
    if current_rows:
        batches.append((_assemble_batch_html(header_html, current_rows), batch_start_idx, total_rows - 1))
    print(f"[BATCH] Split complete: {len(batches)} batches")
    return batches

def _assemble_batch_html(header_html: str, rows: List[Tag]) -> str:
    return f"<table>{header_html}{''.join(str(r) for r in rows)}</table>"

# ════════════════════════════════════════════════════════════════════════════════
# EXTRACTION QUALITY GATE
# ════════════════════════════════════════════════════════════════════════════════
def _count_populated(row: Dict[str, Any]) -> int:
    return sum(1 for v in row.values() if v is not None and str(v).strip() not in ("","null","N/A","-"))

def _majority_schema(rows: List[Dict[str, Any]]) -> set:
    if not rows: return set()
    key_counter: Counter = Counter()
    for row in rows:
        for k in row.keys(): key_counter[k] += 1
    threshold = len(rows) * MIN_SCHEMA_OVERLAP
    return {k for k, c in key_counter.items() if c >= threshold}

def _rows_have_data(rows: List[Dict[str, Any]]) -> bool:
    if not rows: return False
    good_rows = sum(1 for r in rows if _count_populated(r) >= MIN_FIELDS_PER_ROW)
    quality   = good_rows / len(rows)
    print(f"[QUALITY] {good_rows}/{len(rows)} rows quality={quality:.0%}")
    if quality < MIN_QUALITY_RATIO: return False
    majority = _majority_schema(rows)
    if majority:
        consistent     = sum(1 for r in rows if len(set(r.keys()) & majority) / len(majority) >= MIN_SCHEMA_OVERLAP)
        schema_quality = consistent / len(rows)
        if schema_quality < MIN_QUALITY_RATIO: return False
    return True

def _log_extraction_stats(rows: List[Dict[str, Any]], label: str = "") -> None:
    if not rows: print(f"[STATS] No rows extracted."); return
    all_keys: Dict[str, int] = {}
    for row in rows:
        for k, v in row.items():
            all_keys.setdefault(k, 0)
            if v is not None and str(v).strip() not in ("","null","N/A","-"): all_keys[k] += 1
    total = len(rows)
    print(f"[STATS {label}] {total} rows")
    for key, count in sorted(all_keys.items(), key=lambda x: -x[1]):
        bar = "█" * int(10 * count / total) + "░" * (10 - int(10 * count / total))
        print(f" {bar} {count:>3}/{total} '{key}'")

# ════════════════════════════════════════════════════════════════════════════════
# POST-PROCESSING
# ════════════════════════════════════════════════════════════════════════════════
def _sanitize_value(v: Any) -> Any:
    if not isinstance(v, str): return v
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
                    new_row["label"] = _sanitize_value(v); promoted += 1
                else: dropped += 1
            else:
                new_row[k] = _sanitize_value(v)
        cleaned.append(new_row)
    if promoted or dropped:
        print(f"[POSTPROCESS] Empty-key: {promoted} promoted, {dropped} dropped")
    return cleaned

def _sanitize_row_values(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return _clean_row_keys([{k: _sanitize_value(v) for k, v in row.items()} for row in rows])

# ════════════════════════════════════════════════════════════════════════════════
# AI EXTRACTION ENGINE
# ════════════════════════════════════════════════════════════════════════════════
def extract_with_ai(html_content: str, url: str, extract_type: str = "auto") -> List[Dict[str, Any]]:
    batches = _split_table_into_batches(html_content)
    if len(batches) == 1:
        result = _extract_with_ai(html_content, url, extract_type)
        return result if result is not None else []
    all_rows: List[Dict[str, Any]] = []
    for idx, (batch_html, start, end) in enumerate(batches):
        result = _extract_with_ai(batch_html, url, extract_type)
        if result: all_rows.extend(result)
    return all_rows[:MAX_RECORDS]

def _extract_with_ai(html: str, url: str, extract_type: str) -> Optional[List[Dict[str, Any]]]:
    if not _AI_AVAILABLE:    return None
    if not _GOOGLE_API_KEY:  return None
    _mistral_rate_gate()
    prompt  = _build_accuracy_prompt(html, url, extract_type)
    payload = {
        "model":       _GOOGLE_MODEL,
        "messages":    [{"role": "user", "content": prompt}],
        "temperature": 0.0,
    }
    headers = {
        "Content-Type":  "application/json",
        "Accept":        "application/json",
        "Authorization": f"Bearer {_GOOGLE_API_KEY}",
    }
    t_start = time.time()
    print(f"[AI] Sending → {_GOOGLE_MODEL} ({len(html):,} chars)")
    MAX_RETRIES = 3
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with httpx.Client(timeout=120.0) as client:
                response = client.post(_GOOGLE_API_URL, json=payload, headers=headers)
            elapsed_ai = time.time() - t_start
            print(f"[AI] HTTP {response.status_code} in {elapsed_ai:.1f}s")
            if response.status_code in [500, 502, 503, 504]:
                if attempt < MAX_RETRIES: time.sleep(2 ** attempt); continue
                return None
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                print(f"[AI] 429 — sleeping {retry_after}s")
                time.sleep(retry_after); return None
            if response.status_code != 200:
                print(f"[AI] Error body: {response.text[:300]}")
                return None
            break
        except Exception as e:
            if attempt < MAX_RETRIES: time.sleep(2 ** attempt); continue
            print(f"[AI] Failed: {e}"); return None
    try:
        data    = response.json()
        content = data["choices"][0]["message"]["content"]
        return _parse_ai_response(content)
    except Exception as e:
        print(f"[AI] Parse error: {e}"); return None

def _build_accuracy_prompt(html: str, url: str, extract_type: str) -> str:
    structure_hint = {
        "table": "Extract each <tr> data row as one object. Use <th> text as JSON keys.",
        "list":  "Extract each list item as one object.",
        "card":  "Extract each card as one object.",
    }.get(extract_type, "Identify the densest data grid. MERGE related tables by shared keys.")
    return f"""Extract all structured data from the HTML below.
RULES:
- Use actual column headers as JSON keys (exact text)
- Cross-reference multiple tables if present
- Extract EVERY column/field. Copy values as plain text
- Return ONLY valid JSON array: [{{...}}, ...] or []

{structure_hint}

URL: {url}

HTML:
{html}

JSON:"""

def _parse_ai_response(content: str) -> Optional[List[Dict[str, Any]]]:
    if not content: return None
    content = content.strip()
    if content.startswith('```'):
        lines   = content.split('\n')
        content = '\n'.join(line for line in lines if not line.startswith('```') and '```' not in line)
    start = content.find('[')
    end   = content.rfind(']') + 1
    if start == -1 or end == 0: return None
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
    if Fetcher is None: raise RuntimeError("Scrapling Fetcher not installed.")
    response = Fetcher().get(url)
    if response is None: raise RuntimeError("Fetcher.get() returned None.")
    return response

def _fetch_js(url: str):
    if not _STEALTH_AVAILABLE or StealthyFetcher is None: raise RuntimeError("StealthyFetcher unavailable.")
    response = StealthyFetcher.fetch(url, headless=True)
    if response is None: raise RuntimeError("StealthyFetcher.fetch() returned None.")
    return response

def _get_raw_bytes(response) -> bytes:
    for attr in ('html','text'):
        val = getattr(response, attr, None)
        if val and isinstance(val, str) and val.strip(): return val.encode('utf-8', errors='replace')
    for attr in ('content','body'):
        val = getattr(response, attr, None)
        if val:
            if isinstance(val, bytes) and val: return val
            if isinstance(val, str) and val.strip(): return val.encode('utf-8', errors='replace')
    raise ValueError("Scrapling response has no usable content.")

# ════════════════════════════════════════════════════════════════════════════════
# MAIN SCRAPE PIPELINE
# ════════════════════════════════════════════════════════════════════════════════
async def _scrape_url(url: str, js: bool = False, extract_type: str = "auto") -> Tuple[List[Dict[str, Any]], int]:
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="Forbidden: private/local IP blocked.")
    loop = asyncio.get_running_loop()

    async def _do_fetch(use_js: bool):
        try:
            return await loop.run_in_executor(None, _fetch_js if use_js else _fetch_static, url)
        except RuntimeError as e:
            raise HTTPException(status_code=502, detail=str(e))

    response  = await _do_fetch(js)
    used_js   = js
    try:    raw = _get_raw_bytes(response)
    except ValueError as e: raise HTTPException(status_code=502, detail=str(e))
    raw_bytes = len(raw)
    if raw_bytes == 0:               raise HTTPException(status_code=502, detail="Empty body.")
    if raw_bytes > MAX_PAYLOAD_SIZE: raise HTTPException(status_code=413, detail=f"Payload too large.")
    html_clean = _preprocess_html(raw)
    try:
        rows = await loop.run_in_executor(cpu_executor, extract_with_ai, html_clean, url, extract_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI extraction failed: {e}")
    _log_extraction_stats(rows, label="attempt=1")
    needs_better = not used_js and not _rows_have_data(rows) and raw_bytes >= 51_200
    if needs_better:
        if _STEALTH_AVAILABLE:
            try:
                response2   = await _do_fetch(True)
                raw2        = _get_raw_bytes(response2)
                if raw2:
                    html_clean2 = _preprocess_html(raw2)
                    rows2 = await loop.run_in_executor(cpu_executor, extract_with_ai, html_clean2, url, extract_type)
                    if _rows_have_data(rows2):
                        rows = rows2; raw_bytes = len(raw2); used_js = True
                    else:
                        rows = []
            except Exception as e:
                print(f"[SCRAPE] JS retry failed: {e}")
        else:
            rows = []
    print(f"[SCRAPE] Final: {len(rows)} records (js={used_js})")
    return rows, raw_bytes

# ════════════════════════════════════════════════════════════════════════════════
# FASTAPI APPLICATION
# ════════════════════════════════════════════════════════════════════════════════
app = FastAPI(title="AUDITOR CORE", version="9.9.2")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    errors = "; ".join(f"{' → '.join(str(l) for l in e['loc'])}: {e['msg']}" for e in exc.errors())
    return JSONResponse(status_code=422, content={"detail": f"Validation error — {errors}"})

@app.get("/", include_in_schema=False)
async def serve_frontend():
    base_dir  = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(base_dir, "index.html")
    if os.path.exists(html_path): return FileResponse(html_path)
    return HTMLResponse(content="<h2>404 — index.html not found</h2>", status_code=404)

@app.get("/api/key")
async def get_api_key():
    return JSONResponse({"api_key": API_KEY})

@app.get("/api/health")
async def health():
    return {
        "status":       "ok",
        "version":      "9.9.2",
        "fetcher":      _FETCHER_AVAILABLE,
        "stealth":      _STEALTH_AVAILABLE,
        "ai":           _AI_AVAILABLE,
        "readability":  False,
        "ai_model":     _GOOGLE_MODEL if _AI_AVAILABLE else None,
        "ai_provider":  "Google AI Studio",
        "max_batch_chars": MAX_BATCH_CHARS,
        "batch_usable":    BATCH_USABLE,
        "rate_limiter": {"window_s": _RPM_WINDOW, "rpm_limit": _RPM_LIMIT, "strategy": "sliding window"},
        "utc": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/api/debug-fetch")
async def debug_fetch(url: str, js: bool = False, _key: str = Depends(verify_key)):
    if not _is_safe_url(url): raise HTTPException(status_code=403, detail="Forbidden domain")
    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(None, _fetch_js if js else _fetch_static, url)
        raw      = _get_raw_bytes(response)
        text     = raw.decode('utf-8', errors='replace')
        cleaned  = _extract_main_content(text)
        isolated = _find_best_table(cleaned)
        batches  = _split_table_into_batches(isolated)
        return {
            "url": url, "js": js,
            "raw_bytes": len(raw), "cleaned_chars": len(cleaned), "isolated_chars": len(isolated),
            "retention_pct": round(100*len(cleaned)/max(len(raw),1),1),
            "isolation_pct": round(100*len(isolated)/max(len(cleaned),1),1),
            "num_batches": len(batches), "batch_sizes": [len(b[0]) for b in batches],
            "stealth_available": _STEALTH_AVAILABLE, "preview": isolated[:3000],
        }
    except Exception as e:
        return {"url": url, "error": str(e)}

@app.post("/api/scrape", response_model=ScrapeResponse)
async def scrape(body: ScrapeRequest, _key: str = Depends(verify_key)):
    t0              = time.perf_counter()
    rows, raw_bytes = await _scrape_url(body.url, js=body.js, extract_type=body.extract_type)
    return ScrapeResponse(events=rows, raw_bytes=raw_bytes, elapsed=round(time.perf_counter()-t0,3))

@app.post("/api/raw", response_model=RawResponse)
async def raw_fetch(body: ScrapeRequest, _key: str = Depends(verify_key)):
    """
    Fetch + preprocess (noise removal → table isolation → batch plan).
    Skips AI entirely. Returns isolated HTML in `content` field.
    """
    if not _is_safe_url(body.url):
        raise HTTPException(status_code=403, detail="Forbidden: private/local IP blocked.")
    t0   = time.perf_counter()
    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(None, _fetch_js if body.js else _fetch_static, body.url)
        raw      = _get_raw_bytes(response)
    except (RuntimeError, ValueError) as e:
        raise HTTPException(status_code=502, detail=str(e))
    raw_bytes = len(raw)
    if raw_bytes == 0:               raise HTTPException(status_code=502, detail="Empty body.")
    if raw_bytes > MAX_PAYLOAD_SIZE: raise HTTPException(status_code=413, detail="Payload too large.")
    text     = raw.decode("utf-8", errors="replace")
    cleaned  = _extract_main_content(text)
    isolated = _find_best_table(cleaned)
    batches  = _split_table_into_batches(isolated)
    return RawResponse(
        url             = body.url,
        raw_bytes       = raw_bytes,
        cleaned_chars   = len(cleaned),
        isolated_chars  = len(isolated),
        retention_pct   = round(100 * len(cleaned) / max(raw_bytes, 1), 1),
        isolation_pct   = round(100 * len(isolated) / max(len(cleaned), 1), 1),
        num_batches     = len(batches),
        batch_sizes     = [len(b[0]) for b in batches],
        content         = isolated,
        elapsed         = round(time.perf_counter() - t0, 3),
    )

@app.get("/api/token-status")
async def token_status(_key: str = Depends(verify_key)):
    return {
        "provider":  "Google AI Studio",
        "model":     _GOOGLE_MODEL,
        "rpm":       _RPM_LIMIT,
        "rpd":       1500,
        "keys":      [{"key_index": 1, "active": True}],
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
    except Exception: pass

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
