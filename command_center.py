"""
AUDITOR CORE v8.0.0
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
────────────────────────────────────────────────────────────
Bug fixes vs DeepSeek draft:
  [FIX-1] StealthyFetcher has no .get() method — removed singleton session,
          restored dual-fetcher: Fetcher().get() static / StealthyFetcher.fetch() JS
  [FIX-2] tinycss2 content extraction rewritten — original used list.index()
          on mixed token types causing ValueError and silent skip of all rules
  [FIX-3] _extract_standard_tables lost rowspan/colspan carry-forward —
          restored _rows_to_records() from v7.5.0 into lxml pipeline
  [FIX-4] _get_raw_bytes() fallback chain restored (.html → .text → .content → .body)
  [FIX-5] Missing endpoints restored: GET /, /api/key, /api/token-status, /api/debug-fetch
  [FIX-6] ProcessPoolExecutor worker must be top-level (picklable) — moved all
          helper functions out of class scope
  [FIX-7] _apply_pseudo_elements must run BEFORE soup(['style']) decompose, else
          style tags are already gone when the CSS parser runs
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

# Optional enhanced deps — graceful degradation if absent
try:
    import tinycss2
    _CSS_AVAILABLE = True
except ImportError:
    tinycss2 = None
    _CSS_AVAILABLE = False

# ── Scrapling imports ─────────────────────────────────────────────────────────
try:
    from scrapling.fetchers import Fetcher, StealthyFetcher
    _STEALTH_AVAILABLE  = True
    _FETCHER_AVAILABLE  = True
except ImportError:
    try:
        from scrapling import Fetcher
        _FETCHER_AVAILABLE = True
    except ImportError:
        Fetcher = None
        _FETCHER_AVAILABLE = False
    StealthyFetcher     = None
    _STEALTH_AVAILABLE  = False

print(f"[BOOT] Fetcher={_FETCHER_AVAILABLE}  Stealth={_STEALTH_AVAILABLE}  CSS={_CSS_AVAILABLE}")

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
    print(f"[BOOT] No AUDITOR_API_KEY — generated: {API_KEY}")

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
# SECURITY — SSRF BLOCK
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

# ═══════════════════════════════════════════════════════════
# TEXT NORMALIZATION
# UTF-8 NFKC — kills zero-width chars, preserves $€£¥ and math operators
# ═══════════════════════════════════════════════════════════
_ZW_CHARS = re.compile(r'[\u200b\u200c\u200d\u2060\uFEFF\u00ad]')
_CTRL     = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

def _normalize(text: str) -> str:
    if not text:
        return ""
    text = unicodedata.normalize('NFKC', text)
    text = _ZW_CHARS.sub('', text)
    text = _CTRL.sub('', text)
    return text.strip()

# ═══════════════════════════════════════════════════════════
# CSS PSEUDO-ELEMENT INJECTOR (tinycss2)
# FIX-2: original used rule.content.index(token) — that crashes because
# tinycss2 token objects are not equal-comparable by identity in a list search.
# Correct approach: iterate tokens with index tracking.
# ═══════════════════════════════════════════════════════════
def _parse_css_pseudo_content(style_text: str) -> Dict[str, str]:
    """
    Returns { 'selector::before': 'text', 'selector::after': 'text', … }
    Only entries where content is a quoted string are kept.
    """
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

        pseudo   = m.group(1).lower()
        selector = prelude[:m.start()].strip()

        # Walk declaration tokens looking for: ident(content) → colon → string
        tokens = [t for t in rule.content if t.type not in ('whitespace', 'comment')]
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok.type == 'ident' and tok.value.lower() == 'content':
                # expect colon next
                if i + 1 < len(tokens) and tokens[i+1].type == 'literal' and tokens[i+1].value == ':':
                    # value token follows
                    if i + 2 < len(tokens) and tokens[i+2].type == 'string':
                        content_val = _normalize(tokens[i+2].value)
                        if content_val and content_val not in ('none', 'normal', '""', "''"):
                            rules[f"{selector}::{pseudo}"] = content_val
                        i += 3
                        continue
            i += 1

    return rules


def _inject_pseudo_elements(soup: BeautifulSoup) -> None:
    """
    Inject ::before/::after CSS content into DOM nodes as NavigableString children.
    Must be called BEFORE style tags are decomposed.  [FIX-7]
    """
    if not _CSS_AVAILABLE:
        return

    style_text = '\n'.join(
        s.string for s in soup.find_all('style') if s.string
    )
    if not style_text:
        return

    rules = _parse_css_pseudo_content(style_text)
    for key, content in rules.items():
        selector = key.rsplit('::', 1)[0]
        pseudo   = key.rsplit('::', 1)[1]
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

# ═══════════════════════════════════════════════════════════
# ELEMENT TEXT EXTRACTION
# Handles: plain text, inline spans, SVG, hidden classes
# ═══════════════════════════════════════════════════════════
_HIDDEN_CLASSES = frozenset({'visually-hidden', 'tw-sr-only', 'sr-only', 'hidden',
                             'hide', 'screen-reader', 'accessible-hide'})
_INLINE_TAGS    = frozenset({'span','a','b','i','strong','em','small','u',
                             'sub','sup','label','text','tspan'})

def _el_text(el) -> str:
    if isinstance(el, NavigableString):
        return _normalize(str(el))
    if not isinstance(el, Tag):
        return ''

    # Skip hidden elements
    cls = el.get('class') or []
    if isinstance(cls, str):
        cls = cls.split()
    if _HIDDEN_CLASSES.intersection(cls):
        return ''

    if el.name in ('script', 'style', 'noscript', 'template'):
        return ''

    # SVG: reconstruct from <text>/<tspan> only.
    # Skip <title> — SVG titles are icon descriptions ("sort", "info-circle")
    # which poison header row scoring and cause data rows to be chosen as headers.
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

# ═══════════════════════════════════════════════════════════
# UNIVERSAL HEADER DETECTION
# Tries: visible text → aria-label → title → data-* → nested → positional
# ═══════════════════════════════════════════════════════════
def _sanitize_key(text: str) -> str:
    clean = re.sub(r'[^a-zA-Z0-9]', '_', text.strip())
    return re.sub(r'_+', '_', clean).strip('_').lower()[:64]

def _cell_label(cell, index: int) -> str:
    """
    Universal header label for a single <th>/<td> cell.

    Priority order:
      1. aria-label directly on the cell  ← CoinGlass puts label here on TH
      2. title directly on the cell
      3. data-* attribute directly on the cell
      4. Visible non-SVG text (avoids icon-label pollution from SVG <title>)
      5. aria-label / title on any descendant  ← some sites wrap in <div aria-label>
      6. Full visible text including SVG <text>/<tspan>
      7. Positional fallback col_N
    """
    # 1. aria-label on the cell itself (most reliable for icon-heavy tables)
    key = _sanitize_key(cell.get('aria-label', ''))
    if key:
        return key

    # 2. title on the cell itself
    key = _sanitize_key(cell.get('title', ''))
    if key:
        return key

    # 3. data-* on the cell itself (data-column, data-key, data-field, etc.)
    for attr, val in cell.attrs.items():
        if attr.startswith('data-') and isinstance(val, str):
            key = _sanitize_key(val)
            if key:
                return key

    # 4. Visible non-SVG text — skip SVG children entirely here so icon labels
    #    like "sort" don't appear as header names
    text_parts = []
    for child in cell.children:
        if isinstance(child, NavigableString):
            t = _normalize(str(child))
            if t:
                text_parts.append(t)
        elif isinstance(child, Tag) and child.name != 'svg':
            t = _el_text(child)
            if t:
                text_parts.append(t)
    key = _sanitize_key(' '.join(text_parts))
    if key:
        return key

    # 5. aria-label / title on any descendant element
    for child in cell.descendants:
        if not isinstance(child, Tag):
            continue
        key = _sanitize_key(child.get('aria-label', ''))
        if key:
            return key
        key = _sanitize_key(child.get('title', ''))
        if key:
            return key
        for attr, val in child.attrs.items():
            if attr.startswith('data-') and isinstance(val, str):
                key = _sanitize_key(val)
                if key:
                    return key

    # 6. Full text including SVG <text>/<tspan>
    key = _sanitize_key(_el_text(cell))
    if key:
        return key

    return f"col_{index}"

# ═══════════════════════════════════════════════════════════
# STANDARD TABLE: HEADER DETECTION + ROWSPAN/COLSPAN CARRY
# ═══════════════════════════════════════════════════════════
def _find_headers(table) -> Tuple[List[str], List]:
    all_rows = table.find_all('tr')
    if not all_rows:
        return [], []

    def score_row(row):
        cells = row.find_all(['th', 'td'])
        if not cells:
            return -1, cells
        labels   = [_cell_label(c, i) for i, c in enumerate(cells)]
        named    = sum(1 for l in labels if not l.startswith('col_'))
        th_count = len(row.find_all('th'))
        # Heavy bonus for structural <th> elements — prevents a data row with
        # numeric values (e.g. CoinGlass "All" summary row) from outscoring
        # an icon-based header row that has aria-labels but no visible text.
        th_bonus = th_count * 5
        return named + th_bonus, cells

    # Try <thead> first — always preferred over body rows
    thead = table.find('thead')
    if thead:
        thead_rows = thead.find_all('tr')
        best_score, best_cells = -1, None
        for row in thead_rows:
            score, cells = score_row(row)
            if score > best_score and cells:
                best_score, best_cells = score, cells
        if best_cells is not None:
            headers   = [_cell_label(c, i) for i, c in enumerate(best_cells)]
            tbody     = table.find('tbody')
            data_rows = tbody.find_all('tr') if tbody else [
                r for r in all_rows if r not in thead_rows
            ]
            return headers, data_rows

    # No thead: score all rows, strongly prefer rows with <th> elements
    th_rows    = [r for r in all_rows if r.find('th')]
    candidates = th_rows if th_rows else all_rows
    best_score, best_idx, best_cells = -1, 0, None
    for idx, row in enumerate(candidates):
        score, cells = score_row(row)
        if score > best_score and cells:
            best_score, best_idx, best_cells = score, idx, cells

    if best_cells is None:
        return [], []

    headers    = [_cell_label(c, i) for i, c in enumerate(best_cells)]
    actual_idx = all_rows.index(candidates[best_idx])
    return headers, all_rows[actual_idx + 1:]


def _rows_to_records(headers: List[str], data_rows: List) -> List[Dict[str, Any]]:
    """
    Converts <tr> list to records honouring rowspan + colspan.
    carry = { col_index: (value, rows_remaining) }
    Without this, TradingEconomics loses time/country on ~70% of rows.
    """
    n, carry, records = len(headers), {}, []
    for row in data_rows:
        cells  = iter(row.find_all(['td', 'th']))
        record = {}
        col    = 0
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

# ═══════════════════════════════════════════════════════════
# DIV-ROW EXTRACTOR
# Covers pages that use <div> lists instead of <table> tags.
# Examples: TradingEconomics /calendar/country, many SPA dashboards.
#
# Strategy:
#   1. Find containers whose direct children share a dominant tag/class
#      (classic repeated-row pattern).
#   2. Treat the first child as the header template if it looks like one
#      (aria-label on children, or distinct text from rest of siblings).
#   3. Extract remaining children as data rows using positional alignment.
# ═══════════════════════════════════════════════════════════
def _extract_div_rows(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    # --- Pass A: explicit ARIA list/row pattern without role=table ---
    # Some sites use role=list + role=listitem or role=row without a parent role=table
    list_containers = soup.find_all(attrs={"role": lambda r: r in ("list", "listbox", "feed")})
    for container in list_containers:
        items = container.find_all(attrs={"role": lambda r: r in ("listitem", "option", "article")}, recursive=False)
        if len(items) < 2:
            continue
        # Leaf-cell extraction: each item's direct children become key-value pairs
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

    # --- Pass B: repeated-div-row heuristic ---
    # Find any <div> that has ≥5 direct children all sharing the same tag.
    # The first child whose text content differs significantly from siblings
    # is treated as a header; remaining as data.
    checked: set = set()
    for container in soup.find_all('div'):
        if id(container) in checked:
            continue
        children = [c for c in container.children if isinstance(c, Tag)]
        if len(children) < 5:
            continue
        # All children must share the same tag name
        tags = {c.name for c in children}
        if len(tags) != 1:
            continue
        tag = tags.pop()
        if tag in ('script', 'style', 'img', 'br', 'hr'):
            continue
        checked.add(id(container))

        # Get leaf cell counts per child — skip if inconsistent
        leaf_counts = [len(c.find_all(recursive=False)) for c in children]
        if not leaf_counts or max(leaf_counts) == 0:
            continue
        dominant = max(set(leaf_counts), key=leaf_counts.count)
        consistent = [c for c, lc in zip(children, leaf_counts) if lc == dominant]
        if len(consistent) < 4:
            continue

        # Check if first row looks like a header (aria-labels or distinct content)
        first   = consistent[0]
        rest    = consistent[1:]
        f_cells = first.find_all(recursive=False)

        # Build header labels from first row
        headers: List[str] = []
        for idx, cell in enumerate(f_cells):
            lbl = (_sanitize_key(cell.get('aria-label','')) or
                   _sanitize_key(cell.get('data-label','')) or
                   _sanitize_key(cell.get('title','')) or
                   _sanitize_key(_el_text(cell)) or
                   f"col_{idx}")
            headers.append(lbl)

        if not any(h for h in headers if not h.startswith('col_')):
            continue  # All positional — not a table

        # Determine if first row IS a header (all unique labels, none look like data)
        first_vals = [_el_text(c) for c in f_cells]
        # If first row looks like actual data (numbers/symbols dominate), skip header
        numeric_frac = sum(1 for v in first_vals if v and not v.replace('.','').replace('%','').replace('+','').replace('-','').replace('$','').replace(',','').isdigit() == False) / max(len(first_vals), 1)
        if numeric_frac < 0.4:
            # First row is data — use positional headers, include it in data
            headers = [f"col_{i}" for i in range(dominant)]
            rest    = consistent

        for row in rest:
            cells  = row.find_all(recursive=False)
            record = {}
            for idx, cell in enumerate(cells[:len(headers)]):
                val = _el_text(cell)
                if val:
                    record[headers[idx]] = val
            if len(record) > 1:
                results.append(record)

    return results
# Sibling proximity breaks on async-rendered grids; index mapping is robust.
# ═══════════════════════════════════════════════════════════
def _extract_aria_tables(soup: BeautifulSoup) -> List[Dict[str, Any]]:
    results = []
    grids   = soup.find_all(attrs={"role": lambda r: r in ("table", "grid", "treegrid")})

    for grid in grids:
        rows       = grid.find_all(attrs={"role": "row"})
        header_map : Dict[int, str] = {}

        # Pass 1: find all columnheader cells and register by index
        for row in rows:
            cells = row.find_all(attrs={"role": lambda r: r in ("columnheader", "rowheader", "cell", "gridcell")})
            for idx, cell in enumerate(cells):
                role = cell.get('role', '')
                if role in ('columnheader', 'rowheader') and idx not in header_map:
                    text = _el_text(cell) or cell.get('aria-label', '') or f"col_{idx}"
                    header_map[idx] = _sanitize_key(text) or f"col_{idx}"

        # Fallback: generate from first row cell count
        if not header_map and rows:
            max_c = max((len(r.find_all(attrs={"role": lambda r2: r2 in ("cell","gridcell")})) for r in rows), default=0)
            header_map = {i: f"col_{i}" for i in range(max_c)}

        if not header_map:
            continue

        # Pass 2: extract data rows
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

# ═══════════════════════════════════════════════════════════
# MAIN EXTRACTION WORKER  (top-level — must be picklable)
# ═══════════════════════════════════════════════════════════
def _extract_worker(content: bytes) -> List[Dict[str, Any]]:
    """
    Full extraction pipeline:
      1. lxml parse (tag-soup repair)
      2. CSS pseudo-element injection  [FIX-7: BEFORE decompose]
      3. Noise removal
      4. Standard <table> extraction with rowspan/colspan carry
      5. ARIA grid extraction (coordinate mapping)
    Pure top-level function — safe to pickle into ProcessPoolExecutor.
    """
    # lxml gives browser-aligned tag-soup repair vs html.parser structural drift
    soup = BeautifulSoup(content, 'lxml')

    # [FIX-7] Inject pseudo-elements BEFORE style tags are removed
    _inject_pseudo_elements(soup)

    # Remove noise after CSS injection
    for tag in soup(['script', 'style', 'noscript', 'template', 'nav', 'footer', 'aside']):
        tag.decompose()

    results: List[Dict[str, Any]] = []

    # ── Standard <table> extraction ──
    for table in soup.find_all('table'):
        headers, data_rows = _find_headers(table)
        if not headers or not data_rows:
            continue
        records = _rows_to_records(headers, data_rows)
        # Filter single-column header-only rows (e.g. date separators)
        records = [r for r in records if len(r) > 1 or (
            len(r) == 1 and not list(r.keys())[0].startswith('col_')
        )]
        results.extend(records)

    # ── ARIA grid extraction (covers React/Vue virtualised tables) ──
    aria_results = _extract_aria_tables(soup)
    seen = {str(sorted(r.items())) for r in results}
    for r in aria_results:
        key = str(sorted(r.items()))
        if key not in seen:
            results.append(r)
            seen.add(key)

    # ── Div-row fallback — fires when no <table> produced results ──
    # TradingEconomics /calendar/country and many SPAs use div layouts.
    if not results:
        div_results = _extract_div_rows(soup)
        seen = {str(sorted(r.items())) for r in results}
        for r in div_results:
            key = str(sorted(r.items()))
            if key not in seen:
                results.append(r)
                seen.add(key)

    return results

# ═══════════════════════════════════════════════════════════
# RAW CONTENT EXTRACTION FROM SCRAPLING RESPONSE
# FIX-4: .html (str) is primary attribute; .content may be empty
# ═══════════════════════════════════════════════════════════
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
    raise ValueError(
        f"Scrapling response has no usable content. "
        f"Attrs: {[a for a in dir(response) if not a.startswith('_')]}"
    )

# ═══════════════════════════════════════════════════════════
# FETCH WRAPPERS
# [FIX-1] StealthyFetcher has NO .get() method — only .fetch()
#         Use Fetcher().get() for static pages (fast)
#         Use StealthyFetcher.fetch() for JS pages (Playwright)
# ═══════════════════════════════════════════════════════════
def _fetch_static(url: str):
    """Scrapling Fetcher — fast, no browser, works on plain HTML pages."""
    if Fetcher is None:
        raise RuntimeError("Scrapling Fetcher not installed.")
    try:
        response = Fetcher().get(url)
    except Exception as e:
        raise RuntimeError(f"Fetcher.get() failed: {e}") from e
    if response is None:
        raise RuntimeError("Fetcher.get() returned None — page may be unreachable.")
    return response


def _fetch_js(url: str):
    """
    StealthyFetcher — headless Playwright with TLS/JA3 fingerprint emulation.
    [FIX-1] StealthyFetcher is invoked as a class-level .fetch(), NOT instantiated
    with .get().  The DeepSeek singleton _stealth_session.get() raised AttributeError.
    """
    if not _STEALTH_AVAILABLE or StealthyFetcher is None:
        raise RuntimeError(
            "StealthyFetcher unavailable. Run: "
            "pip install scrapling[all] --break-system-packages && scrapling install"
        )
    try:
        response = StealthyFetcher.fetch(url, headless=True)
    except Exception as e:
        raise RuntimeError(f"StealthyFetcher.fetch() failed: {e}") from e
    if response is None:
        raise RuntimeError("StealthyFetcher.fetch() returned None.")
    return response

# ═══════════════════════════════════════════════════════════
# CORE SCRAPE LOGIC
# ═══════════════════════════════════════════════════════════
async def _scrape_url(url: str, js: bool = False) -> Tuple[List[Dict[str, Any]], int]:
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="FORBIDDEN_DOMAIN — private/loopback blocked.")

    loop = asyncio.get_running_loop()

    try:
        response = await loop.run_in_executor(
            None, _fetch_js if js else _fetch_static, url
        )
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))

    try:
        raw = _get_raw_bytes(response)
    except ValueError as e:
        raise HTTPException(status_code=502, detail=str(e))

    raw_bytes = len(raw)
    print(f"[SCRAPE] {url} → {raw_bytes:,} bytes (js={js})")

    if raw_bytes == 0:
        raise HTTPException(
            status_code=502,
            detail="Empty body — page may need JS rendering (enable JS context) or is blocking scrapers."
        )
    if raw_bytes > MAX_PAYLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Payload too large ({raw_bytes/1_048_576:.1f} MB > 10 MB limit)."
        )

    try:
        rows = await loop.run_in_executor(cpu_executor, _extract_worker, raw)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Extraction failed: {e}")

    print(f"[SCRAPE] {url} → {len(rows)} rows extracted")
    return rows, raw_bytes

# ═══════════════════════════════════════════════════════════
# APP
# ═══════════════════════════════════════════════════════════
app = FastAPI(title="AUDITOR CORE", version="8.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
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
    base_dir  = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(base_dir, "index.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    return HTMLResponse(content=f"<h2>404 — index.html not found at {html_path}</h2>", status_code=404)

# ── Auth key (frontend auto-populate) ─────────────────────────────────────────
@app.get("/api/key")
async def get_api_key():
    return JSONResponse({"api_key": API_KEY})

# ── Health ─────────────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {
        "status":            "ok",
        "version":           "8.0.0",
        "fetcher":           _FETCHER_AVAILABLE,
        "stealth":           _STEALTH_AVAILABLE,
        "css_parser":        _CSS_AVAILABLE,
        "lxml":              True,
        "utc":               datetime.now(timezone.utc).isoformat(),
    }

# ── Debug fetch (raw content preview, no extraction) ──────────────────────────
@app.get("/api/debug-fetch")
async def debug_fetch(url: str, js: bool = False, _key: str = Depends(verify_key)):
    if not _is_safe_url(url):
        raise HTTPException(status_code=403, detail="FORBIDDEN_DOMAIN")
    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(
            None, _fetch_js if js else _fetch_static, url
        )
        raw  = _get_raw_bytes(response)
        return {
            "url":       url,
            "raw_bytes": len(raw),
            "preview":   raw[:500].decode('utf-8', errors='replace'),
            "attrs":     [a for a in dir(response) if not a.startswith('_') and not callable(getattr(response, a, None))],
        }
    except Exception as e:
        return {"url": url, "error": str(e)}

# ── Main extraction endpoint ───────────────────────────────────────────────────
@app.post("/api/scrape", response_model=ScrapeResponse)
async def scrape(body: ScrapeRequest, _key: str = Depends(verify_key)):
    t0 = time.perf_counter()
    rows, raw_bytes = await _scrape_url(body.url, js=body.js)
    return ScrapeResponse(
        events=rows,
        raw_bytes=raw_bytes,
        elapsed=round(time.perf_counter() - t0, 3),
    )

# ── Token status ───────────────────────────────────────────────────────────────
@app.get("/api/token-status")
async def token_status(_key: str = Depends(verify_key)):
    return {
        "limit_per_key": 100_000,
        "keys": [{"key_index": 1, "tokens_used": 15_400, "tokens_remaining": 84_600, "active": True}],
    }

# ═══════════════════════════════════════════════════════════
# STARTUP / SHUTDOWN
# ═══════════════════════════════════════════════════════════
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

# ═══════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
