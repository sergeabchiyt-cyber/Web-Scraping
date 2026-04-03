import asyncio
import logging
import os
import re
import signal
import threading
import time
import traceback
from datetime import datetime, timezone

# ── Token sanitisation ───────────────────────────────────
_raw_token = os.environ.get("TELEGRAM_TOKEN", "").strip()
_clean_token = _raw_token.lstrip("=").strip().strip("'\"")
TELEGRAM_TOKEN = None
if re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{30,}", _clean_token):
    TELEGRAM_TOKEN = _clean_token
    print("[TELEGRAM] Valid token loaded ✓")
else:
    raise RuntimeError("Invalid or missing TELEGRAM_TOKEN")

MAX_CHARS = 4096
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)

# ── Formatting helpers ──────────────────────────────────
def _fmt_item(idx: int, item: dict) -> str:
    NAME_FIELDS = ('indicator','title','name','event','headline','product',
                   'label','item','description','exchange','symbol','pair',
                   'asset','coin','company','ticker','token','market')
    name = None
    name_key = None
    for f in NAME_FIELDS:
        if item.get(f):
            name = str(item[f]).strip()
            name_key = f
            break
    if not name:
        for k, v in item.items():
            if isinstance(v, str) and len(v.strip()) >= 2:
                name = v.strip()
                name_key = k
                break
    if not name:
        name = f"Item {idx}"
    lines = [f"*{idx}. {name}*"]
    SKIP = {'is_past'}
    if name_key:
        SKIP.add(name_key)
    for k, v in item.items():
        if k in SKIP or v is None or str(v).strip() == '':
            continue
        label = k.replace('_', ' ').title()
        lines.append(f"  {label}: {v}")
    return '\n'.join(lines)

def _build_batches(items: list, url: str) -> list[str]:
    messages = []
    total = len(items)
    current = ""
    batch_num = 1
    first_idx = 1
    def make_header(start_idx: int) -> str:
        short_url = url[:55] + '…' if len(url) > 55 else url
        return (f"📊 *AUDITOR* — `{short_url}`\n"
                f"Msg {batch_num} · items from #{start_idx} · {total} total\n"
                f"{'─' * 28}\n")
    current = make_header(1)
    for i, item in enumerate(items, start=1):
        block = _fmt_item(i, item) + '\n\n'
        if len(block) > MAX_CHARS - 100:
            block = block[:MAX_CHARS - 103] + '…\n\n'
        if len(current) + len(block) > MAX_CHARS:
            messages.append(current.rstrip())
            batch_num += 1
            first_idx = i
            current = make_header(i) + block
        else:
            current += block
    if current.strip():
        messages.append(current.rstrip())
    return messages

# ── Command handlers ─────────────────────────────────────
async def _handle_start(update, context):
    await update.message.reply_text(
        "👋 *Welcome to AUDITOR Bot*\n\n"
        "Available commands:\n"
        "• `/start` — Show this welcome message\n"
        "• `/help` — Show detailed help\n"
        "• `/ping` — Check if bot is online\n"
        "• `/scrape <url> [js]` — Scrape a webpage\n\n"
        "Example: `/scrape https://example.com`\n"
        "Add `js` at the end for JavaScript‑rendered pages.",
        parse_mode='Markdown'
    )

async def _handle_help(update, context):
    await update.message.reply_text(
        "📚 *AUDITOR Bot Help*\n\n"
        "*Commands:*\n"
        "• `/start` — Show welcome message\n"
        "• `/help` — Show this help\n"
        "• `/ping` — Check if bot is online\n"
        "• `/scrape <url> [js]` — Scrape a webpage\n\n"
        "*Scrape usage:*\n"
        "`/scrape https://tradingeconomics.com/calendar`\n"
        "`/scrape https://coinglass.com/open-interest/BTC js`\n\n"
        "The bot extracts all tables from the page and sends them in batched messages.",
        parse_mode='Markdown'
    )

async def _handle_ping(update, context):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    text = ("✅ *AUDITOR is online*\n"
            f"🕐 `{now}`\n"
            "🤖 Scraping engine ready")
    await update.message.reply_text(text, parse_mode='Markdown')

async def _handle_scrape(update, context):
    # Import the correct scraping function from command_center
    from command_center import _scrape_url

    args = context.args
    if not args:
        await update.message.reply_text(
            "❌ Usage: `/scrape <url> [js]`\n"
            "Example: `/scrape https://tradingeconomics.com/united-states/calendar`\n"
            "Add `js` at the end for JS-rendered pages.",
            parse_mode='Markdown'
        )
        return

    url = args[0]
    use_js = len(args) > 1 and args[1].lower() == 'js'

    # Normalise URL – add https if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    await update.message.reply_text(
        f"⏳ Scraping `{url}`...\n"
        f"{'🌐 JS rendering ON' if use_js else '⚡ Fast mode (no JS)'}\n"
        "This may take 20–40s — the scraping engine is reading the page.",
        parse_mode='Markdown'
    )

    try:
        # _scrape_url returns (rows, raw_bytes)
        items, raw_bytes = await _scrape_url(url, js=use_js)

        if not items:
            await update.message.reply_text(
                f"⚠️ No items extracted from `{url}`\n"
                f"Raw bytes received: {raw_bytes}\n"
                "Try adding `js` if the page is JavaScript-rendered.",
                parse_mode='Markdown'
            )
            return

        batches = _build_batches(items, url)
        n_msgs = len(batches)
        for msg in batches:
            await update.message.reply_text(msg, parse_mode='Markdown')

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        await update.message.reply_text(
            f"✅ *Done*\n"
            f"📊 {len(items)} items extracted\n"
            f"📨 {n_msgs} message(s) sent\n"
            f"🕐 `{now}`",
            parse_mode='Markdown'
        )

    except Exception as e:
        # _scrape_url may raise HTTPException or other errors
        tb = traceback.format_exc()
        print(f"[TELEGRAM] /scrape error:\n{tb}")
        short = str(e)[:300] if str(e) else repr(e)[:300]
        await update.message.reply_text(
            f"❌ *Scrape failed*\n`{short}`",
            parse_mode='Markdown'
        )

async def _handle_message(update, context):
    await update.message.reply_text(
        "💬 I'm an AUDITOR bot. Use `/help` for available commands.",
        parse_mode='Markdown'
    )

async def _handle_unknown_command(update, context):
    await update.message.reply_text(
        "❓ Unknown command.\n"
        "Available commands:\n"
        "  /start — welcome\n"
        "  /ping — check status\n"
        "  /scrape <url> [js] — scrape a URL\n"
        "  /help — show help",
        parse_mode='Markdown'
    )

# ── Bot startup with graceful shutdown ──────────────────
_bot_started = False
_bot_lock = threading.Lock()
_shutdown_event = threading.Event()

def start_bot():
    global _bot_started
    with _bot_lock:
        if _bot_started:
            print("[TELEGRAM] Bot already running — skipping duplicate start.")
            return
        _bot_started = True

    try:
        from telegram.ext import (
            ApplicationBuilder, CommandHandler, MessageHandler, filters
        )
    except ImportError:
        print("[TELEGRAM] python-telegram-bot not installed.")
        print("[TELEGRAM] Run: pip install python-telegram-bot")
        return

    async def _run():
        app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
        app.add_handler(CommandHandler("start",  _handle_start))
        app.add_handler(CommandHandler("help",   _handle_help))
        app.add_handler(CommandHandler("ping",   _handle_ping))
        app.add_handler(CommandHandler("scrape", _handle_scrape))
        app.add_handler(MessageHandler(filters.COMMAND, _handle_unknown_command))
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, _handle_message))

        print("[TELEGRAM] Bot starting — listening for commands...")
        await app.initialize()
        await app.start()
        await app.updater.start_polling(
            drop_pending_updates=True,
            allowed_updates=["message"],
        )

        # Wait for shutdown signal
        while not _shutdown_event.is_set():
            await asyncio.sleep(1)

        print("[TELEGRAM] Shutdown signal received – stopping bot...")
        await app.updater.stop()
        await app.stop()
        await app.shutdown()
        print("[TELEGRAM] Bot stopped.")

    def _thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_run())
        except Exception as e:
            print(f"[TELEGRAM] Bot crashed: {e}")
            traceback.print_exc()
        finally:
            loop.close()

    t = threading.Thread(target=_thread, daemon=False, name="telegram-bot")
    t.start()
    print("[TELEGRAM] Bot thread started ✓")

def stop_bot():
    _shutdown_event.set()
    print("[TELEGRAM] Stop signal sent – waiting for bot to exit...")
