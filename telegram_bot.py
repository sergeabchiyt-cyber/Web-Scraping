"""
AUDITOR Telegram Bot
────────────────────
Commands:
  /ping  — check if AUDITOR is online
  /scrape <url> [js] — scrape a URL and return results in auto-batched messages

Run alongside command_center.py — started automatically as a background thread.
Install: pip install python-telegram-bot
"""

import asyncio
import logging
import threading
import traceback
from datetime import datetime, timezone

TELEGRAM_TOKEN = "8637706429:AAGLoWYTakzM9dImrqZPjipudHkw7DxnSTs"

# Telegram hard limit per message (chars)
MAX_CHARS  = 4096

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)

# ── Formatting helpers ────────────────────────────────────────────────────────

def _fmt_item(idx: int, item: dict) -> str:
    """Format a single extracted item. Fully generic — works with any schema."""

    # Find the primary name from any reasonable identifier field
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
        # Last resort: first string value
        for k, v in item.items():
            if isinstance(v, str) and len(v.strip()) >= 2:
                name = v.strip()
                name_key = k
                break

    if not name:
        name = f"Item {idx}"

    lines = [f"*{idx}. {name}*"]

    # Show all remaining fields except the one used as name
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
    """
    Split items into Telegram messages purely by character count.
    Each message stays strictly under MAX_CHARS (4096).
    No fixed item-per-message limit — pack as many as fit.
    """
    messages   = []
    total      = len(items)
    current    = ""
    batch_num  = 1
    first_idx  = 1   # global item index of first item in current message

    def make_header(start_idx: int) -> str:
        short_url = url[:55] + '…' if len(url) > 55 else url
        return (
            f"📊 *AUDITOR* — `{short_url}`\n"
            f"Msg {batch_num} · items from #{start_idx} · {total} total\n"
            f"{'─' * 28}\n"
        )

    current = make_header(1)

    for i, item in enumerate(items, start=1):
        block = _fmt_item(i, item) + '\n\n'

        # If a single block is itself too large, truncate it
        if len(block) > MAX_CHARS - 100:
            block = block[:MAX_CHARS - 103] + '…\n\n'

        if len(current) + len(block) > MAX_CHARS:
            # Current message is full — save and start a new one
            messages.append(current.rstrip())
            batch_num += 1
            first_idx  = i
            current    = make_header(i) + block
        else:
            current += block

    if current.strip():
        messages.append(current.rstrip())

    return messages


# ── Bot handlers ──────────────────────────────────────────────────────────────

async def _handle_ping(update, context):
    from command_center import API_KEY
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    text = (
        "✅ *AUDITOR is online*\n"
        f"🕐 `{now}`\n"
        f"🔑 API Key: `{API_KEY[:8]}...`\n"
        "🤖 Kimi K2 extraction ready"
    )
    await update.message.reply_text(text, parse_mode='Markdown')


async def _handle_scrape(update, context):
    from command_center import scrape_url, _normalise_url

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

    # Normalise URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    await update.message.reply_text(
        f"⏳ Scraping `{url}`...\n"
        f"{'🌐 JS rendering ON' if use_js else '⚡ Fast mode (no JS)'}\n"
        "This may take 20–40s — Kimi K2 is reading the page.",
        parse_mode='Markdown'
    )

    try:
        result, raw_count = await scrape_url(url, adaptive=True, js=use_js)
        items = result.get('events') or result.get('flat_data') or []

        if not items:
            await update.message.reply_text(
                f"⚠️ No items extracted from `{url}`\n"
                f"Raw nodes processed: {raw_count}\n"
                "Try adding `js` if the page is JavaScript-rendered.",
                parse_mode='Markdown'
            )
            return

        total    = len(items)
        batches  = _build_batches(items, url)
        n_msgs   = len(batches)

        # Send all batches
        for msg in batches:
            await update.message.reply_text(msg, parse_mode='Markdown')

        # Summary
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        await update.message.reply_text(
            f"✅ *Done*\n"
            f"📊 {total} items extracted\n"
            f"📨 {n_msgs} message(s) sent\n"
            f"🕐 `{now}`",
            parse_mode='Markdown'
        )

    except Exception as e:
        tb = traceback.format_exc()
        print(f"[TELEGRAM] /scrape error:\n{tb}")
        short = str(e)[:300] if str(e) else repr(e)[:300]
        await update.message.reply_text(
            f"❌ *Scrape failed*\n`{short}`",
            parse_mode='Markdown'
        )


async def _handle_unknown(update, context):
    await update.message.reply_text(
        "❓ Unknown command.\n"
        "Available commands:\n"
        "  /ping — check server status\n"
        "  /scrape <url> [js] — scrape a URL"
    )


# ── Bot startup ───────────────────────────────────────────────────────────────

def start_bot():
    """
    Start the Telegram bot in a dedicated thread with its own event loop.
    Uses long polling — no webhook, no public URL needed.
    """
    try:
        from telegram.ext import (
            ApplicationBuilder, CommandHandler, MessageHandler, filters
        )
    except ImportError:
        print("[TELEGRAM] python-telegram-bot not installed.")
        print("[TELEGRAM] Run: pip install python-telegram-bot")
        return

    async def _run():
        app = (
            ApplicationBuilder()
            .token(TELEGRAM_TOKEN)
            .build()
        )

        app.add_handler(CommandHandler("ping",   _handle_ping))
        app.add_handler(CommandHandler("scrape", _handle_scrape))
        app.add_handler(
            MessageHandler(filters.COMMAND, _handle_unknown)
        )

        print("[TELEGRAM] Bot starting — listening for commands...")

        # Drive polling manually — avoids run_polling() which tries to
        # close/manage the event loop and conflicts with our thread loop.
        await app.initialize()
        await app.start()
        await app.updater.start_polling(
            drop_pending_updates=True,
            allowed_updates=["message"],
        )

        # Keep the coroutine alive indefinitely
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            await app.updater.stop()
            await app.stop()
            await app.shutdown()

    # Run in its own thread + event loop so it doesn't block uvicorn
    def _thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_run())
        except Exception as e:
            print(f"[TELEGRAM] Bot crashed: {e}")
            traceback.print_exc()

    t = threading.Thread(target=_thread, daemon=True, name="telegram-bot")
    t.start()
    print("[TELEGRAM] Bot thread started ✓")
