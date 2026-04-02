import re
import os
import secrets
import asyncio
import socket
import concurrent.futures
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any, Union
from collections import Counter

import uvicorn
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl
from bs4 import BeautifulSoup

# ── Scrapling framework ───────────────────────────────────────────────────────
try:
    from scrapling.fetchers import Fetcher, StealthyFetcher
    _STEALTH_AVAILABLE = True
except ImportError:
    _STEALTH_AVAILABLE = False

# ═══════════════════════════════════════════════════════════
# GLOBAL EXECUTOR & LIMITS
# ═══════════════════════════════════════════════════════════
# Limits CPU-bound parsing to separate OS processes
cpu_executor = concurrent.futures.ProcessPoolExecutor(max_workers=min(32, (os.cpu_count() or 1) + 4))
MAX_PAYLOAD_SIZE = 10_485_760  # 10MB threshold

# ═══════════════════════════════════════════════════════════
# SECURITY PROTOCOLS
# ═══════════════════════════════════════════════════════════

def _is_safe_url(url: str) -> bool:
    """SSRF Mitigation: Prevent resolution to internal/private subnets."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'): return False
        hostname = parsed.hostname
        if not hostname: return False
        
        ip = socket.gethostbyname(hostname)
        ip_obj = socket.inet_aton(ip)
        ip_int = int.from_bytes(ip_obj, 'big')
        
        # RFC 1918 and Cloud Metadata Ranges
        private_blocks = [
            (0x0A000000, 0xFF000000), # 10.0.0.0/8
            (0xAC100000, 0xFFF00000), # 172.16.0.0/12
            (0xC0A80000, 0xFFFF0000), # 192.168.0.0/16
            (0x7F000000, 0xFF000000), # 127.0.0.0/8
            (0xA9FE0000, 0xFFFF0000), # 169.254.0.0/16 (Link-local/AWS/GCP)
            (0x00000000, 0xFF000000)  # 0.0.0.0/8
        ]
        
        return not any((ip_int & mask) == (net & mask) for net, mask in private_blocks)
    except (socket.gaierror, ValueError):
        return False

# ═══════════════════════════════════════════════════════════
# ENGINE CORE (EXECUTED IN PROCESS POOL)
# ═══════════════════════════════════════════════════════════

def _sanitize_key(text: str) -> str:
    clean = re.sub(r'[^a-zA-Z0-9]', '_', text.strip())
    return re.sub(r'_+', '_', clean).strip('_').lower()[:64]

def _clean_value(text: str) -> Union[str, Dict[str, Any]]:
    """Preserve data context for financial and metric-based assets."""
    if not text: return None
    t = text.strip()
    
    # Financial Context Preservation
    fin = re.match(r'^([\+\-]?)([\$€£¥])\s?([\d,]+\.?\d*)\s?([KMBT]?)$', t)
    if fin:
        sign, curr, val, suffix = fin.groups()
        mult = {'K': 1e3, 'M': 1e6, 'B': 1e9, 'T': 1e12, '': 1}
        try:
            return {
                "raw": t,
                "numeric": float(val.replace(',', '')) * mult.get(suffix, 1) * (-1 if sign == '-' else 1),
                "currency": curr,
                "type": "financial"
            }
        except ValueError: pass

    # Percentage Context
    pct = re.match(r'^([\+\-]?)([\d,]+\.?\d*)\s?%$', t)
    if pct:
        sign, val = pct.groups()
        try:
            return {
                "raw": t,
                "numeric": float(val.replace(',', '')) * (-1 if sign == '-' else 1),
                "type": "percentage"
            }
        except ValueError: pass

    return t[:2000]

def _extract_worker(content: bytes) -> List[Dict[str, Any]]:
    """Main worker function for ProcessPoolExecutor."""
    soup = BeautifulSoup(content, 'lxml' if 'lxml' in globals() else 'html.parser')
    for tag in soup(['script', 'style', 'nav', 'footer', 'aside', 'svg', 'iframe']):
        tag.decompose()
    
    results = []
    
    # 1. Table Extraction (Highest Integrity)
    for table in soup.find_all('table'):
        rows = table.find_all('tr')
        if not rows: continue
        headers = [_sanitize_key(th.get_text(strip=True)) or f"col_{i}" for i, th in enumerate(rows[0].find_all(['th', 'td']))]
        for row in rows[1:]:
            cells = row.find_all(['td', 'th'])
            if len(cells) != len(headers): continue
            item = {headers[i]: _clean_value(c.get_text(strip=True)) for i, c in enumerate(cells)}
            if any(isinstance(v, dict) for v in item.values()): results.append(item)

    # 2. Key-Value List Extraction
    for dl in soup.find_all('dl'):
        item = {}
        for dt, dd in zip(dl.find_all('dt'), dl.find_all('dd')):
            item[_sanitize_key(dt.get_text(strip=True))] = _clean_value(dd.get_text(strip=True))
        if item: results.append(item)

    # 3. Component/Grid Extraction (Contextual Merge)
    groups = {}
    for card in soup.find_all(['div', 'article', 'section']):
        text = card.get_text(separator='|', strip=True)
        parts = [p.strip() for p in text.split('|') if p.strip()]
        if len(parts) < 2: continue
        
        item = {}
        for i, p in enumerate(parts):
            if ':' in p:
                k, v = p.split(':', 1)
                item[_sanitize_key(k)] = _clean_value(v)
            elif i == 0: item['identity'] = p
            elif re.search(r'[\d]', p): item[f'attr_{i}'] = _clean_value(p)
        
        if len(item) >= 2:
            key = item.get('identity', 'gen_') + str(len(item))
            groups[key] = {**(groups.get(key, {})), **item}

    results.extend(groups.values())
    return results

# ═══════════════════════════════════════════════════════════
# API & ORCHESTRATION
# ═══════════════════════════════════════════════════════════

app = FastAPI(title="AUDITOR CORE", version="7.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=False, 
    allow_methods=["POST"], 
    allow_headers=["X-Api-Key", "Content-Type"],
)

_ENV_KEY = os.environ.get("AUDITOR_API_KEY", "").strip()
API_KEY = _ENV_KEY if _ENV_KEY else secrets.token_hex(32)
if not _ENV_KEY: print(f"[BOOT] GENERATED KEY: {API_KEY}")

def validate_auth(x_api_key: str = Header(..., alias="X-Api-Key")):
    if not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")

class ScrapeRequest(BaseModel):
    url: HttpUrl
    js: bool = False

@app.post("/api/v1/extract", dependencies=[Depends(validate_auth)])
async def extract(payload: ScrapeRequest):
    target = str(payload.url)
    if not _is_safe_url(target):
        raise HTTPException(status_code=403, detail="FORBIDDEN_DESTINATION")

    loop = asyncio.get_event_loop()
    
    # 1. Network I/O (Async Thread)
    try:
        if payload.js:
            if not _STEALTH_AVAILABLE: raise ValueError("Stealth engine missing")
            response = await loop.run_in_executor(None, lambda: StealthyFetcher.fetch(target, headless=True, network_idle=True, wait=10))
        else:
            response = await loop.run_in_executor(None, lambda: Fetcher().get(target))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"FETCH_ERROR: {str(e)}")

    if not response or not hasattr(response, 'content'):
        raise HTTPException(status_code=502, detail="NULL_RESPONSE")

    content = response.content
    if len(content) > MAX_PAYLOAD_SIZE:
        raise HTTPException(status_code=413, detail="PAYLOAD_TOO_LARGE")

    # 2. Structural Parsing (Process Pool Offload)
    try:
        extracted_data = await loop.run_in_executor(cpu_executor, _extract_worker, content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PARSER_CRASH: {str(e)}")

    return {
        "status": "SUCCESS",
        "metadata": {"url": target, "size_bytes": len(content), "count": len(extracted_data)},
        "data": extracted_data
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
