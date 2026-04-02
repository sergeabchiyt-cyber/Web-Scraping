import re
import os
import json
import secrets
import asyncio
import uvicorn
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel
from typing import Optional

# ── Telegram bot (background thread) ────────────────────────────────────────
try:
    from telegram_bot import start_bot_thread
    _TELEGRAM_AVAILABLE = True
except ImportError:
    _TELEGRAM_AVAILABLE = False
    print("[AUDITOR] python-telegram-bot not installed — Telegram disabled.")
    print("[AUDITOR] Install: pip install python-telegram-bot")

# ── Scrapling fetchers ────────────────────────────────────────────────────────
try:
    from scrapling.fetchers import Fetcher, StealthyFetcher
    _STEALTH_AVAILABLE = True
except ImportError:
    try:
        from scrapling import Fetcher
        StealthyFetcher = None
        _STEALTH_AVAILABLE = False
    except ImportError:
        raise

# ── Groq / Qwen3-32B — Dual Key Rotation ─────────────────────────────────────
# 300K TPM / 1K RPM — switch keys at TOKEN_LIMIT threshold.
# Token counts reset at midnight UTC (Groq's daily limit window).

TOKEN_LIMIT = 295_000   # switch keys just under the 300K TPM ceiling

GROQ_MODEL = 'qwen/qwen3-32b'

_GROQ_KEYS = [
    os.environ.get('GROQ_API_KEY',   ''),
    os.environ.get('GROQ_API_KEY_2', ''),
]

_token_counters = {0: {"date": "", "tokens": 0}, 1: {"date": "", "tokens": 0}}
_active_key_idx = 0


def _get_active_key() -> str:
    return _GROQ_KEYS[_active_key_idx]


def _record_tokens(used: int) -> None:
    global _active_key_idx
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    c = _token_counters[_active_key_idx]
    if c["date"] != today:
        c["date"]   = today
        c["tokens"] = 0
    c["tokens"] += used
    total = c["tokens"]
    print(f"[GROQ] Key {_active_key_idx + 1} daily usage: {total:,} / {TOKEN_LIMIT:,} tokens")
    if total >= TOKEN_LIMIT:
        next_idx = (_active_key_idx + 1) % len(_GROQ_KEYS)
        print(f"[GROQ] Key {_active_key_idx + 1} hit limit — rotating to Key {next_idx + 1}")
        _active_key_idx = next_idx


def get_token_status() -> dict:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return {
        "active_key": _active_key_idx + 1,
        "limit_per_key": TOKEN_LIMIT,
        "keys": [
            {
                "key_index": i + 1,
                "date": _token_counters[i]["date"] or today,
                "tokens_used": _token_counters[i]["tokens"],
                "tokens_remaining": max(0, TOKEN_LIMIT - _token_counters[i]["tokens"]),
                "active": i == _active_key_idx,
            }
            for i in range(len(_GROQ_KEYS))
        ]
    }


# ═══════════════════════════════════════════════════════════
# APP + AUTH
# ═══════════════════════════════════════════════════════════
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    try:
        from telegram_bot import start_bot
        start_bot()
    except Exception as e:
        print(f"[TELEGRAM] Failed to start bot: {e}")
    yield

app = FastAPI(title="AUDITOR Scrape API", version="4.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

_env_key = os.environ.get("AUDITOR_API_KEY", "").strip()
API_KEY: str = _env_key if _env_key else secrets.token_hex(16)
if not _env_key:
    print("\n[AUDITOR] No AUDITOR_API_KEY set — generated for this session.")
print(f"[AUDITOR] API Key: {API_KEY}\n")

if _TELEGRAM_AVAILABLE:
    start_bot_thread()


def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="UNAUTHORIZED — include a valid X-Api-Key header."
        )


# ═══════════════════════════════════════════════════════════
# FETCH
# ═══════════════════════════════════════════════════════════

def _normalise_url(url: str) -> str:
    url = url.strip()
    if url and not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def _do_fetch(url: str, adaptive: bool, js: bool):
    """Sync fetch — always called from a thread executor."""
    if js:
        StealthyFetcher.adaptive = adaptive
        return StealthyFetcher.fetch(
            url, headless=True, network_idle=True,
            wait=15,
            google_search=True)
    else:
        fetcher = Fetcher()
        fetcher.configure(adaptive=adaptive)
        return fetcher.get(url)


def _page_to_text(response) -> str:
    """
    Extract all visible text from the page, deduplicated and ordered.
    Also grabs value= attributes to catch JS-injected prices in input elements.
    """
    seen  = set()
    parts = []
    for node in (response.css('*') or []):
        t = (node.text or '').strip()
        if t and 2 < len(t) < 400 and t not in seen:
            seen.add(t)
            parts.append(t)
        v = (node.attrib.get('value') or '').strip()
        if v and 2 < len(v) < 400 and v not in seen:
            seen.add(v)
            parts.append(v)
    return '\n'.join(parts)[:10000]


# ═══════════════════════════════════════════════════════════
# QWEN3-32B EXTRACTION VIA GROQ
# ═══════════════════════════════════════════════════════════

async def _extract_with_kimi(page_text: str, url: str) -> list:
    """
    Send page content to Qwen3-32B via Groq.
    reasoning_effort=high for maximum accuracy.
    max_completion_tokens=40960 — full model ceiling.
    """
    now_utc = datetime.now(timezone.utc)
    now_str = now_utc.strftime("%Y-%m-%d %H:%M UTC")

    system_msg = (
        "You are an expert data extraction engine. "
        "You receive raw text scraped from any web page and return a clean, "
        "structured JSON array. You intelligently identify what the page contains "
        "— calendar events, articles, products, tables, listings, financial data, "
        "or anything else — and extract every item with all its fields. "
        "You infer the schema from context. "
        "Your only output is a valid JSON array. "
        "No markdown. No explanation. No preamble. Just the JSON array."
    )

    user_msg = (
        f"Current UTC time: {now_str}\n"
        f"Source URL: {url}\n\n"
        "Below is raw text scraped from a web page. "
        "Analyse the content, understand what kind of data this page contains, "
        "identify the schema (what fields each item has), "
        "then extract EVERY item you can find.\n\n"
        "RULES:\n"
        "1. Extract ALL items — do not skip or truncate\n"
        "2. Exclude navigation menus, ads, cookie notices, login prompts, "
        "   footers, and other UI boilerplate\n"
        "3. Infer field names from context — use clear, lowercase_underscore names\n"
        "4. Dates, times, units, and quantities near items belong to those items\n"
        "5. Labeled values count as structured data — prices, metrics, statistics, "
        "   measurements, rates, or any named number on the page must be extracted. "
        "   Even a small set of key-value pairs (e.g. 4 fuel prices) is valid output\n"
        "6. If the page contains time-based events, include an is_past boolean "
        "   (true if the item datetime < current UTC time)\n"
        "7. Keep values exactly as shown — do not reformat numbers or dates\n"
        "8. Use null for any field that is not present for a given item\n\n"
        "Return ONLY the JSON array. No markdown. No explanation.\n\n"
        f"RAW PAGE TEXT:\n{page_text}"
    )

    def _call_groq():
        from groq import Groq
        client = Groq(api_key=_get_active_key())
        completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user",   "content": user_msg},
            ],
            temperature=0.1,
            max_completion_tokens=40960,
            top_p=0.95,
            reasoning_effort="default",
            stream=False,
            stop=None,
        )
        usage = getattr(completion, 'usage', None)
        if usage:
            _record_tokens(getattr(usage, 'total_tokens', 0))
        return completion.choices[0].message.content

    loop = asyncio.get_event_loop()
    raw  = await loop.run_in_executor(None, _call_groq)
    raw  = raw.strip()
    raw  = re.sub(r'^```(?:json)?\s*', '', raw, flags=re.M)
    raw  = re.sub(r'\s*```\s*$',       '', raw, flags=re.M)
    raw  = raw.strip()

    try:
        items = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"[AUDITOR] JSON parse failed: {e} — attempting recovery")
        items = None

        raw_stripped = raw.strip()
        if not raw_stripped.startswith('['):
            raw_stripped = '[' + raw_stripped

        positions = [i for i, ch in enumerate(raw_stripped) if ch == '}']

        for pos in reversed(positions):
            candidate = raw_stripped[:pos + 1].rstrip().rstrip(',') + ']'
            try:
                items = json.loads(candidate)
                print(f"[AUDITOR] Recovery succeeded: {len(items)} events (truncated at char {pos})")
                break
            except json.JSONDecodeError:
                continue

        if items is None:
            print(f"[AUDITOR] All recovery attempts failed. Raw first 400:\n{raw[:400]}")
            raise HTTPException(status_code=500,
                                detail=f"Qwen3 returned unparseable JSON: {e}")

    events = [ev for ev in items if isinstance(ev, dict)]
    print(f"[AUDITOR] Qwen3-32B → {len(events)} events from {url}")
    return events


# ═══════════════════════════════════════════════════════════
# MAIN SCRAPE ENTRY POINT
# ═══════════════════════════════════════════════════════════

async def scrape_url(url: str, adaptive: bool = True, js: bool = False) -> tuple:
    import traceback
    url = _normalise_url(url)

    if js and not _STEALTH_AVAILABLE:
        raise HTTPException(
            status_code=501,
            detail="StealthyFetcher not installed. "
                   "Run: pip install scrapling[all] --break-system-packages "
                   "then: scrapling install"
        )

    loop = asyncio.get_event_loop()
    try:
        response = await loop.run_in_executor(
            None, lambda: _do_fetch(url, adaptive, js))
    except Exception as e:
        print(f"[AUDITOR] fetch error:\n{traceback.format_exc()}")
        raise HTTPException(status_code=500,
                            detail=f"{type(e).__name__}: {str(e) or repr(e)}")

    if not response:
        raise HTTPException(status_code=502, detail="TARGET_UNREACHABLE")

    page_text = _page_to_text(response)
    raw_count = len([l for l in page_text.split('\n') if l.strip()])

    events = await _extract_with_kimi(page_text, url)

    from collections import defaultdict
    groups = defaultdict(list)
    for ev in events:
        groups[ev.get('country') or 'Unknown'].append(ev)

    sections = [
        {
            'heading':     country,
            'heading_tag': 'div',
            'records':     evs,
        }
        for country, evs in sorted(groups.items())
    ]

    result = {
        'events':        events,
        'flat_data':     events,
        'sections':      sections,
        'clean_count':   len(events),
        'section_count': len(sections),
    }
    return result, raw_count


# ═══════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════

class FrontendPayload(BaseModel):
    target_url:    str
    concurrency_limit: int   = 2
    download_delay:    float = 1.5
    adaptive_parsing:  bool  = True
    js_rendering:      bool  = False

class ApiScrapePayload(BaseModel):
    url:      str
    adaptive: bool = True
    js:       bool = False


# ═══════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════

@app.get("/api/health", tags=["API"])
async def health():
    return {"status": "OK", "service": "AUDITOR", "version": "4.0.0"}

@app.get("/api/key", tags=["Internal"])
async def get_api_key():
    return {"api_key": API_KEY}

@app.get("/api/token-status", tags=["Internal"])
async def token_status():
    return get_token_status()


@app.get("/", tags=["Frontend"], include_in_schema=False)
async def serve_frontend():
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
    if os.path.exists(html_path):
        return FileResponse(html_path, media_type="text/html")
    return HTMLResponse("<h2>index.html not found — upload it alongside command_center.py</h2>", status_code=404)


def _build_response(result: dict, url: str, raw_count: int) -> dict:
    return {
        "status":        "COMPLETED",
        "url":           url,
        "raw_count":     raw_count,
        "clean_count":   result["clean_count"],
        "section_count": result["section_count"],
        "sections":      result["sections"],
        "data":          result["flat_data"],
        "events":        result["events"],
    }


@app.post("/execute_extraction", tags=["Internal"])
async def execute_extraction(payload: FrontendPayload):
    try:
        result, raw_count = await scrape_url(
            payload.target_url, payload.adaptive_parsing, payload.js_rendering)
        return JSONResponse(content=_build_response(result, payload.target_url, raw_count))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scrape", tags=["API"], dependencies=[Depends(require_api_key)])
async def api_scrape(payload: ApiScrapePayload):
    try:
        result, raw_count = await scrape_url(payload.url, payload.adaptive, payload.js)
        return JSONResponse(content=_build_response(result, payload.url, raw_count))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scrape/records", tags=["API"], dependencies=[Depends(require_api_key)])
async def api_scrape_records(payload: ApiScrapePayload):
    try:
        result, _ = await scrape_url(payload.url, payload.adaptive, payload.js)
        records = [e for e in result["events"] if e.get("actual")]
        return JSONResponse(content={
            "status":  "COMPLETED",
            "url":     payload.url,
            "count":   len(records),
            "records": records,
        })
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scrape/{data_type}", tags=["API"], dependencies=[Depends(require_api_key)])
async def api_scrape_by_type(data_type: str, payload: ApiScrapePayload):
    VALID = {"currency", "percentage", "number", "date", "url", "email", "duration"}
    if data_type not in VALID:
        raise HTTPException(400, detail=f"Invalid type '{data_type}'. Valid: {sorted(VALID)}")
    try:
        result, _ = await scrape_url(payload.url, payload.adaptive, payload.js)
        filtered = [e for e in result["events"]
                    if data_type in (e.get("types") or [])]
        return JSONResponse(content={
            "status":  "COMPLETED",
            "url":     payload.url,
            "type":    data_type,
            "count":   len(filtered),
            "records": filtered,
        })
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
