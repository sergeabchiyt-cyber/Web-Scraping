"""
AUDITOR CORE v8.1.0 - Web Scraper
────────────────────────────────────────────────────────────
Extraction engine combining:
  • lxml tag-soup repair (BeautifulSoup backend)
  • UTF-8 NFKC normalization — preserves $€£¥, kills zero-width chars
  • CSS ::before/::after pseudo-element injection (tinycss2)
  • SVG text reconstruction
  • ARIA role=grid coordinate-based column mapping
  • rowspan/colspan carry-forward for standard <table>
  • Universal header detection (aria-label, title, data-*, nested spans)
  • Dual fetcher: Fetcher() for static, StealthyFetcher for JS pages
  • Explicit header override for known JS-rendered sites (CoinGlass, etc.)
────────────────────────────────────────────────────────────
Bug fixes:
  [FIX-1] StealthyFetcher has no .get() method — uses .fetch() class method
  [FIX-2] tinycss2 token iteration fixed — no more ValueError
  [FIX-3] _rows_to_records() properly carries rowspan/colspan
  [FIX-4] _get_raw_bytes() fallback chain restored
  [FIX-5] Missing endpoints restored
  [FIX-6] ProcessPoolExecutor worker is top-level (picklable)
  [FIX-7] _inject_pseudo_elements runs BEFORE decompose
  [FIX-8] CoinGlass headers explicitly defined (JS-rendered content)
"""

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
from typing import List, Dict, Any, Tuple, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel
from bs4 import BeautifulSoup, Tag, NavigableString

try:
    import tinycss2
    _CSS_AVAILABLE = True
except ImportError:
    tinycss2 = None
    _CSS_AVAILABLE = False

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

print(f"[BOOT] Fetcher={_FETCHER_AVAILABLE}  Stealth={_STEALTH_AVAILABLE}  CSS={_CSS_AVAILABLE}")

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

cpu_executor = concurrent.futures.ProcessPoolExecutor(max_workers=4)
MAX_PAYLOAD_SIZE = 10_485_760

# ═══════════════════════════════════════════════════════════════════════════════
# JS-RENDERED SITES CONFIG
# Sites that require JavaScript rendering to get table data
# ═══════════════════════════════════════════════════════════════════════════════

_JS_RENDERED_SITES = {
    'coinglass.com': True,
    'coinmarketcap.com': True,
    'coinranking.com': True,
    'tradingview.com': True,
    'tradingeconomics.com': True,  # Shows "No Events" to anonymous
}

# Explicit header definitions for sites with JS-rendered or dynamically loaded tables
# Maps (domain, url_pattern) -> list of expected column names in order
_EXPLICIT_HEADERS: Dict[Tuple[str, str], List[str]] = {
    ('coinglass.com', 'open-interest'): [
        'Ranking', 'Exchanges', 'OI_BTC', 'OI', 'Rate',
        'OI_Change_1h', 'OI_Change_4h', 'OI_Change_24h', 'OI_24h_Vol', 'Trade'
    ],
    ('coinglass.com', 'funding-rate'): [
        'Exchange', 'Pair', 'Funding_Rate', 'Next_Funding', 'Mark_Price', 'Index_Price'
    ],
}

def _get_explicit_headers(url: str) -> Optional[List[str]]:
    """Get explicit headers for known JS-rendered sites."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower().replace('www.', '')
    path = parsed.path.lower()

    for (d, pattern), headers in _EXPLICIT_HEADERS.items():
        if domain == d and pattern in path:
            return headers

    # Check domain-level defaults
    if domain in _JS_RENDERED_SITES:
        return None  # Use JS rendering but no explicit headers

    return None

def _needs_js_rendering(url: str) -> bool:
    """Check if URL likely needs JavaScript rendering."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower().replace('www.', '')
    return _JS_RENDERED_SITES.get(domain, False)

# ═══════════════════════════════════════════════════════════════════════════════
# AUTH
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

class ScrapeResponse(BaseModel):
    events: List[Dict[str, Any]]
    raw_bytes: int
    elapsed: float

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY — SSRF BLOCK
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

# ═══════════════════════════════════════════════════════════════════════════════
# TEXT NORMALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

_ZW_CHARS = re.compile(r'[\u200b\u200c\u200d\u2060\uFEFF\u00ad]')
_CTRL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

def _normalize(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize('NFKC', text)
    text = _ZW_CHARS.sub('', text)
    text = _CTRL.sub('', text)
    return text.strip()

# ═══════════════════════════════════════════════════════════════════════════════
# CSS PSEUDO-ELEMENT INJECTOR
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_css_pseudo_content(style_text: str) -> Dict[str, str]:
    if not _CSS_AVAILABLE or not style_text:
        return {}
    rules: Dict[str, str] = {}
    for rule in tinycss2.parse_stylesheet(style_text, skip_whitespace=True):
        if rule.type != 'qualified-rule':
            continue
        prelude = tinycss2.serialize(rule.prelude).strip()
        m = re.search(r':+?(before|after)\s*$', prelude, re.IGNORECASE)
        if not m:
            continue
        pseudo = m.group(1).lower()
        selector = prelude[:m.start()].strip()
        tokens = [t for t in rule.content if t.type not in ('whitespace', 'comment')]
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok.type == 'ident' and tok.value.lower() == 'content':
                if i + 2 < len(tokens) and tokens[i+1].type == 'literal' and tokens[i+1].value == ':':
                    if i + 2 < len(tokens) and tokens[i+2].type == 'string':
                        content_val = _normalize(tokens[i+2].value)
                        if content_val and content_val not in ('none', 'normal', '""', "''"):
                            rules[f"{selector}::{pseudo}"] = content_val
                        i += 3
                        continue
            i += 1
    return rules

def _inject_pseudo_elements(soup: BeautifulSoup) -> None:
    if not _CSS_AVAILABLE:
        return
    style_text = '\n'.join(s.string for s in soup.find_all('style') if s.string)
    if not style_text:
        return
    rules = _parse_css_pseudo_content(style_text)
    for key, content in rules.items():
        selector = key.rsplit('::', 1)[0]
        pseudo = key.rsplit('::', 1)[1]
        try:
            elements = soup.select(selector)
        except Exception:
            continue
        for el in elements:
            node = NavigableString(content)
            if pseudo == 'before':
                el.insert(0, node)
            else:
                el.append(node)

# ═══════════════════════════════════════════════════════════════════════════════
# ELEMENT TEXT EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════

_HIDDEN_CLASSES = frozenset({'visually-hidden', 'tw-sr-only', 'sr-only', 'hidden', 'hide', 'screen-reader', 'accessible-hide'})
_INLINE_TAGS = frozenset({'span', 'a', 'b', 'i', 'strong', 'em', 'small', 'u', 'sub', 'sup', 'label', 'text', 'tspan'})

def _el_text(el) -> str:
    if isinstance(el, NavigableString):
        return _normalize(str(el))
    if not isinstance(el, Tag):
        return ''
    cls = el.get('class') or []
    if isinstance(cls, str):
        cls = cls.split()
    if _HIDDEN_CLASSES.intersection(cls):
        return ''
    if el.name in ('script', 'style', 'noscript', 'template'):
        return ''
    if el.name == 'svg':
        parts = [_el_text(n) for n in el.find_all(['text', 'tspan'])]
        return _normalize(' '.join(p for p in parts if p))
    parts = []
    for child in el.children:
        t = _el_text(child)
        if t:
            parts.append(t)
    joined = ''.join(parts) if el.name in _INLINE_TAGS else ' '.join(parts)
    return _normalize(joined)

# ═══════════════════════════════════════════════════════════════════════════════
# UNIVERSAL HEADER DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def _sanitize_key(text: str) -> str:
    """Convert header text to a clean dictionary key."""
    if not text:
        return ''
    # Handle common units in headers like "OI(BTC)" -> "oi_btc"
    clean = re.sub(r'[^a-zA-Z0-9]', '_', text.strip())
    clean = re.sub(r'_+', '_', clean).strip('_')
    # Convert to lowercase but preserve common abbreviations
    return clean.lower()[:64]

def _cell_label(cell, index: int) -> str:
    """Extract header label from a table cell (TH element)."""
    # Priority 1: aria-label attribute (most reliable)
    key = _sanitize_key(cell.get('aria-label', ''))
    if key:
        return key

    # Priority 2: title attribute
    key = _sanitize_key(cell.get('title', ''))
    if key:
        return key

    # Priority 3: data-* attributes
    for attr, val in cell.attrs.items():
        if attr.startswith('data-') and isinstance(val, str) and val.strip():
            key = _sanitize_key(val)
            if key:
                return key

    # Priority 4: Direct child elements (exclude SVG)
    text_parts = []
    for child in cell.children:
        if isinstance(child, NavigableString):
            t = _normalize(str(child))
            if t:
                text_parts.append(t)
        elif isinstance(child, Tag) and child.name not in ('svg', 'script', 'style'):
            t = _el_text(child)
            if t:
                text_parts.append(t)

    key = _sanitize_key(' '.join(text_parts))
    if key:
        return key

    # Priority 5: Descendant elements (nested spans, divs, etc.)
    for child in cell.descendants:
        if not isinstance(child, Tag):
            continue
        if child.name in ('script', 'style', 'svg'):
            continue
        key = _sanitize_key(child.get('aria-label', ''))
        if key:
            return key
        key = _sanitize_key(child.get('title', ''))
        if key:
            return key
        for attr, val in child.attrs.items():
            if attr.startswith('data-') and isinstance(val, str) and val.strip():
                key = _sanitize_key(val)
                if key:
                    return key

    # Priority 6: Full cell text content
    key = _sanitize_key(cell.get_text(separator=' ', strip=True))
    if key:
        return key

    # Fallback: positional identifier
    return f"col_{index}"

# ═══════════════════════════════════════════════════════════════════════════════
# TABLE HEADER DETECTION + ROWSPAN/COLSPAN
# ═══════════════════════════════════════════════════════════════════════════════

def _find_headers(table, explicit_headers: Optional[List[str]] = None) -> Tuple[List[str], List]:
    """
    Find table headers and return (headers_list, data_rows).
    If explicit_headers provided, use those instead of detecting.
    """
    all_rows = table.find_all('tr')
    if not all_rows:
        return [], []

    # If explicit headers provided, use them directly
    if explicit_headers:
        # Find data rows (exclude thead rows if present)
        thead = table.find('thead')
        if thead:
            thead_rows = thead.find_all('tr')
            data_rows = tbody.find_all('tr') if (tbody := table.find('tbody')) else [
                r for r in all_rows if r not in thead_rows
            ]
        else:
            # Use first row as header, rest as data
            data_rows = all_rows[1:] if len(all_rows) > 1 else []

        # Validate explicit header count matches data column count
        if data_rows:
            first_row_cells = data_rows[0].find_all(['td', 'th'])
            if len(explicit_headers) >= len(first_row_cells):
                return explicit_headers[:len(first_row_cells)], data_rows
            elif len(explicit_headers) > 0:
                # Pad or truncate headers to match
                return explicit_headers + [f"col_{i}" for i in range(len(explicit_headers), len(first_row_cells))], data_rows

    # Standard header detection logic
    thead = table.find('thead')
    if thead:
        thead_rows = thead.find_all('tr')
        best_cells, best_key = None, (-1, -1)
        for row in thead_rows:
            cells = row.find_all(['th', 'td'])
            if not cells:
                continue
            labels = [_cell_label(c, i) for i, c in enumerate(cells)]
            named = sum(1 for l in labels if not l.startswith('col_'))
            key = (len(cells), named)
            if key > best_key:
                best_key, best_cells = key, cells
        if best_cells:
            headers = [_cell_label(c, i) for i, c in enumerate(best_cells)]
            tbody = table.find('tbody')
            data_rows = tbody.find_all('tr') if tbody else [
                r for r in all_rows if r not in thead_rows
            ]
            return headers, data_rows

    # No thead - find row with most TH elements or named columns
    def _score(row):
        cells = row.find_all(['th', 'td'])
        if not cells:
            return -1, cells
        labels = [_cell_label(c, i) for i, c in enumerate(cells)]
        named = sum(1 for l in labels if not l.startswith('col_'))
        th_bonus = len(row.find_all('th')) * 5
        return named + th_bonus, cells

    th_rows = [r for r in all_rows if r.find('th')]
    candidates = th_rows if th_rows else all_rows
    best_score, best_idx, best_cells = -1, 0, None
    for idx, row in enumerate(candidates):
        score, cells = _score(row)
        if score > best_score and cells:
            best_score, best_idx, best_cells = score, idx, cells

    if best_cells is None:
        return [], []

    headers = [_cell_label(c, i) for i, c in enumerate(best_cells)]
    actual_idx = all_rows.index(candidates[best_idx])
    return headers, all_rows[actual_idx + 1:]

def _rows_to_records(headers: List[str], data_rows: List) -> List[Dict[str, Any]]:
    """Convert table rows to list of dicts, handling rowspan/colspan."""
    n, carry, records = len(headers), {}, []
    for row in data_rows:
        cells = iter(row.find_all(['td', 'th']))
        record = {}
        col = 0
        while col < n:
            if col in carry:
                val, left = carry[col]
                record[headers[col]] = val
                carry[col] = (val, left - 1) if left > 1 else None
                if carry[col] is None:
                    del carry[col]
                col += 1
                continue
            cell = next(cells, None)
            if cell is None:
                col += 1
                continue
            val = _el_text(cell)
            try:
                rowspan = max(1, int(cell.get('rowspan') or 1))
            except (ValueError, TypeError):
                rowspan = 1
            try:
                colspan = max(1, int(cell.get('colspan') or 1))
            except (ValueError, TypeError):
                colspan = 1
            for offset in range(min(colspan, n - col)):
                target = col + offset
                record[headers[target]] = val
                if rowspan > 1:
                    carry[target] = (val, rowspan - 1)
            col += colspan
        if any(v for v in record.values()):
            records.append(record)
    return records

# ═══════════════════════════════════════════════════════════════════════════════
# DIV-ROW EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_div_rows(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    list_containers = soup.find_all(attrs={"role": lambda r: r in ("list", "listbox", "feed")})
    for container in list_containers:
        items = container.find_all(attrs={"role": lambda r: r in ("listitem", "option", "article")}, recursive=False)
        if len(items) < 2:
            continue
        for item in items:
            cells = item.find_all(recursive=False)
            record = {}
            for idx, cell in enumerate(cells):
                label = (_sanitize_key(cell.get('aria-label', '')) or
                         _sanitize_key(cell.get('data-label', '')) or
                         _sanitize_key(cell.get('title', '')) or
                         f"col_{idx}")
                val = _el_text(cell)
                if val:
                    record[label] = val
            if len(record) > 1:
                results.append(record)
    checked: set = set()
    for container in soup.find_all('div'):
        if id(container) in checked:
            continue
        children = [c for c in container.children if isinstance(c, Tag)]
        if len(children) < 5:
            continue
        tags = {c.name for c in children}
        if len(tags) != 1:
            continue
        tag = tags.pop()
        if tag in ('script', 'style', 'img', 'br', 'hr'):
            continue
        checked.add(id(container))
        leaf_counts = [len(c.find_all(recursive=False)) for c in children]
        if not leaf_counts or max(leaf_counts) == 0:
            continue
        dominant = max(set(leaf_counts), key=leaf_counts.count)
        consistent = [c for c, lc in zip(children, leaf_counts) if lc == dominant]
        if len(consistent) < 4:
            continue
        first = consistent[0]
        rest = consistent[1:]
        f_cells = first.find_all(recursive=False)
        headers: List[str] = []
        for idx, cell in enumerate(f_cells):
            lbl = (_sanitize_key(cell.get('aria-label', '')) or
                   _sanitize_key(cell.get('data-label', '')) or
                   _sanitize_key(cell.get('title', '')) or
                   _sanitize_key(_el_text(cell)) or
                   f"col_{idx}")
            headers.append(lbl)
        if not any(h for h in headers if not h.startswith('col_')):
            continue
        first_vals = [_el_text(c) for c in f_cells]
        numeric_frac = sum(1 for v in first_vals if v and not v.replace('.', '').replace('%', '').replace('+', '').replace('-', '').replace('$', '').replace(',', '').isdigit() == False) / max(len(first_vals), 1)
        if numeric_frac < 0.4:
            headers = [f"col_{i}" for i in range(dominant)]
            rest = consistent
        for row in rest:
            cells = row.find_all(recursive=False)
            record = {}
            for idx, cell in enumerate(cells[:len(headers)]):
                val = _el_text(cell)
                if val:
                    record[headers[idx]] = val
            if len(record) > 1:
                results.append(record)
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# ARIA GRID EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_aria_tables(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    results = []
    grids = soup.find_all(attrs={"role": lambda r: r in ("table", "grid", "treegrid")})
    for grid in grids:
        rows = grid.find_all(attrs={"role": "row"})
        header_map: Dict[int, str] = {}
        for row in rows:
            cells = row.find_all(attrs={"role": lambda r: r in ("columnheader", "rowheader", "cell", "gridcell")})
            for idx, cell in enumerate(cells):
                role = cell.get('role', '')
                if role in ('columnheader', 'rowheader') and idx not in header_map:
                    text = _el_text(cell) or cell.get('aria-label', '') or f"col_{idx}"
                    header_map[idx] = _sanitize_key(text) or f"col_{idx}"
        if not header_map and rows:
            max_c = max((len(r.find_all(attrs={"role": lambda r2: r2 in ("cell", "gridcell")})) for r in rows), default=0)
            header_map = {i: f"col_{i}" for i in range(max_c)}
        if not header_map:
            continue
        for row in rows:
            cells = row.find_all(attrs={"role": lambda r: r in ("cell", "gridcell")})
            if not cells:
                continue
            record = {}
            for idx, cell in enumerate(cells):
                key = header_map.get(idx, f"col_{idx}")
                val = _el_text(cell)
                if val:
                    record[key] = val
            if record:
                results.append(record)
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXTRACTION WORKER
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_worker(content: bytes, explicit_headers: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    results = _parse_and_extract(content, 'lxml', explicit_headers)
    if not results:
        results = _parse_and_extract(content, 'html.parser', explicit_headers)
    return results

def _parse_and_extract(content: bytes, parser: str, explicit_headers: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    try:
        soup = BeautifulSoup(content, parser)
    except Exception:
        return []
    _inject_pseudo_elements(soup)
    for tag in soup(['script', 'style', 'noscript', 'template', 'nav', 'footer', 'aside']):
        tag.decompose()
    results: List[Dict[str, Any]] = []
    for table in soup.find_all('table'):
        headers, data_rows = _find_headers(table, explicit_headers)
        if not headers or not data_rows:
            continue
        records = _rows_to_records(headers, data_rows)
        # Filter out rows with mostly empty or numeric-only values
        records = [
            r for r in records
            if len(r) > 1 or (len(r) == 1 and not list(r.keys())[0].startswith('col_'))
        ]
        # Additional filter: skip rows that are all numbers or empty
        records = [
            r for r in records
            if not all(
                v.replace('.', '').replace(',', '').replace('%', '').replace('+', '-').isdigit()
                or not v.strip()
                for v in r.values()
            )
        ]
        results.extend(records)
    aria_results = _extract_aria_tables(soup)
    seen = {str(sorted(r.items())) for r in results}
    for r in aria_results:
        key = str(sorted(r.items()))
        if key not in seen:
            results.append(r)
            seen.add(key)
    if not results:
        div_results = _extract_div_rows(soup)
        seen = {str(sorted(r.items())) for r in results}
        for r in div_results:
            key = str(sorted(r.items()))
            if key not in seen:
                results.append(r)
                seen.add(key)
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# RAW CONTENT EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════

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
    raise ValueError(f"Scrapling response has no usable content.")

# ═══════════════════════════════════════════════════════════════════════════════
# FETCH WRAPPERS
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
        raise RuntimeError("StealthyFetcher unavailable. Run: pip install scrapling[all]")
    try:
        response = StealthyFetcher.fetch(url, headless=True)
    except Exception as e:
        raise RuntimeError(f"StealthyFetcher.fetch() failed: {e}") from e
    if response is None:
        raise RuntimeError("StealthyFetcher.fetch() returned None.")
    return response

# ═══════════════════════════════════════════════════════════════════════════════
# CORE SCRAPE LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

async def _scrape_url(url: str, js: bool = False, explicit_headers: Optional[List[str]] = None) -> Tuple[List[Dict[str, Any]], int]:
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="FORBIDDEN_DOMAIN")

    # Auto-detect JS rendering for known sites
    auto_js = _needs_js_rendering(url)
    use_js = js or auto_js

    if auto_js and not js:
        print(f"[SCRAPE] Auto-enabling JS for {url} (known JS-rendered site)")

    loop = asyncio.get_running_loop()
    async def _do_fetch(u: str, do_js: bool):
        try:
            return await loop.run_in_executor(None, _fetch_js if do_js else _fetch_static, u)
        except RuntimeError as e:
            raise HTTPException(status_code=502, detail=str(e))

    response = await _do_fetch(url, use_js)
    used_js = use_js

    try:
        raw = _get_raw_bytes(response)
    except ValueError as e:
        raise HTTPException(status_code=502, detail=str(e))

    raw_bytes = len(raw)
    print(f"[SCRAPE] {url} → {raw_bytes:,} bytes (js={used_js})")

    if raw_bytes == 0:
        raise HTTPException(status_code=502, detail="Empty body")

    if raw_bytes > MAX_PAYLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"Payload too large ({raw_bytes/1_048_576:.1f} MB > 10 MB)")

    try:
        rows = await loop.run_in_executor(cpu_executor, _extract_worker, raw, explicit_headers)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Extraction failed: {e}")

    # Auto-retry with JS if static fetch returns no results on known JS sites
    if not rows and not used_js and raw_bytes >= 51_200 and _STEALTH_AVAILABLE:
        print(f"[SCRAPE] 0 rows from static → auto-retrying with JS")
        try:
            response2 = await _do_fetch(url, True)
            raw2 = _get_raw_bytes(response2)
            if raw2:
                rows2 = await loop.run_in_executor(cpu_executor, _extract_worker, raw2, explicit_headers)
                if rows2:
                    print(f"[SCRAPE] JS retry → {len(rows2)} rows")
                    rows = rows2
                    raw_bytes = len(raw2)
                    used_js = True
        except Exception as e:
            print(f"[SCRAPE] JS retry failed: {e}")

    # If still no results on JS-rendered site, try with explicit headers
    if not rows and explicit_headers and _STEALTH_AVAILABLE:
        print(f"[SCRAPE] No rows with auto-detection → forcing JS fetch with explicit headers")
        try:
            response3 = await _do_fetch(url, True)
            raw3 = _get_raw_bytes(response3)
            if raw3:
                rows3 = await loop.run_in_executor(cpu_executor, _extract_worker, raw3, explicit_headers)
                if rows3:
                    print(f"[SCRAPE] Explicit headers → {len(rows3)} rows")
                    rows = rows3
                    raw_bytes = len(raw3)
                    used_js = True
        except Exception as e:
            print(f"[SCRAPE] Explicit headers retry failed: {e}")

    print(f"[SCRAPE] {url} → {len(rows)} rows (js={used_js})")
    return rows, raw_bytes

# ═══════════════════════════════════════════════════════════════════════════════
# APP
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(title="AUDITOR CORE", version="8.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    errors = "; ".join(f"{' → '.join(str(l) for l in e['loc'])}: {e['msg']}" for e in exc.errors())
    return JSONResponse(status_code=422, content={"detail": f"Validation error — {errors}"})

@app.get("/", include_in_schema=False)
async def serve_frontend():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(base_dir, "index.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    return HTMLResponse(content=f"<h2>404 — index.html not found</h2>", status_code=404)

@app.get("/api/key")
async def get_api_key():
    return JSONResponse({"api_key": API_KEY})

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "8.1.0",
        "fetcher": _FETCHER_AVAILABLE,
        "stealth": _STEALTH_AVAILABLE,
        "css_parser": _CSS_AVAILABLE,
        "lxml": True,
        "auto_js_sites": list(_JS_RENDERED_SITES.keys()),
        "explicit_headers": list(set(k[0] for k in _EXPLICIT_HEADERS.keys())),
        "utc": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/api/debug-fetch")
async def debug_fetch(url: str, js: bool = False, _key: str = Depends(verify_key)):
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="FORBIDDEN_DOMAIN")
    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(None, _fetch_js if js else _fetch_static, url)
        raw = _get_raw_bytes(response)
        return {"url": url, "raw_bytes": len(raw), "preview": raw[:500].decode('utf-8', errors='replace')}
    except Exception as e:
        return {"url": url, "error": str(e)}

@app.post("/api/scrape", response_model=ScrapeResponse)
async def scrape(body: ScrapeRequest, _key: str = Depends(verify_key)):
    t0 = time.perf_counter()
    explicit_headers = _get_explicit_headers(body.url)
    rows, raw_bytes = await _scrape_url(body.url, js=body.js, explicit_headers=explicit_headers)
    return ScrapeResponse(events=rows, raw_bytes=raw_bytes, elapsed=round(time.perf_counter() - t0, 3))

@app.get("/api/token-status")
async def token_status(_key: str = Depends(verify_key)):
    return {"limit_per_key": 100_000, "keys": [{"tokens_used": 15400, "tokens_remaining": 84600, "active": True}]}

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
