import asyncio
import logging
import os
import re
import threading
import traceback
from datetime import datetime, timezone
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
logger = logging.getLogger("telegram_bot")
logging.basicConfig(level=logging.INFO)
MAX_CHARS = 4096

# ──────────────────────────────────────────────
# Token handling — sanitise whatever the env var holds
# ──────────────────────────────────────────────
_raw_token = os.environ.get("TELEGRAM_TOKEN", "") or ""
_clean_token = _raw_token.strip().lstrip("=").strip().strip("'\"").strip()
TELEGRAM_TOKEN: str | None = None

if re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{30,}", _clean_token):
    TELEGRAM_TOKEN = _clean_token
else:
    if _raw_token:
        logger.error(
            "[TELEGRAM] Token found in env but looks invalid after cleanup: '%s' → '%s'. "
            "Fix the TELEGRAM_TOKEN value in your environment variables.",
            _raw_token[:20] + "...",
            _clean_token[:20] + "...",
        )
    else:
        logger.warning("[TELEGRAM] TELEGRAM_TOKEN environment variable is not set.")

# ──────────────────────────────────────────────
# Markdown helpers
# ──────────────────────────────────────────────
def _escape_md(text: str) -> str:
    """Escape characters that break Telegram Markdown v1."""
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("`", "'")
        .replace("*", "\\*")
        .replace("_", "\\_")
    )

def _fmt_item(idx: int, item: dict) -> str:
    lines = [f"*{idx}. {_escape_md(item.get('name', 'Item'))}*"]
    for k, v in item.items():
        if k == "name":
            continue
        lines.append(f" {k.replace('_', ' ').title()}: {_escape_md(v)}")
    return "\n".join(lines)

def _build_batches(items: list, url: str) -> list[str]:
    messages: list[str] = []
    batch_num = 1
    
    def header(item_idx: int) -> str:
        return (
            f"📊 *AUDITOR* — `{url[:30]}...`\n"
            f"Msg {batch_num} · #{item_idx} · {len(items)} total\n"
            f"{'─' * 20}\n"
        )
    
    current = header(1)
    for i, item in enumerate(items, start=1):
        block = _fmt_item(i, item) + "\n\n"
        if len(current) + len(block) > MAX_CHARS:
            messages.append(current.rstrip())
            batch_num += 1
            current = header(i) + block
        else:
            current += block
    if current.strip():
        messages.append(current.rstrip())
    return messages

# ──────────────────────────────────────────────
# Command handlers
# ──────────────────────────────────────────────
async def _handle_ping(update, context):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    await update.message.reply_text(
        f"✅ *AUDITOR Online*\n🕐 `{now}`",
        parse_mode="Markdown",
    )

async def _handle_scrape(update, context):
    if not context.args:
        await update.message.reply_text("❌ Usage: `/scrape <url> [js]`", parse_mode="Markdown")
        return
    
    url = context.args[0]
    js_mode = len(context.args) > 1 and context.args[1].lower() == "js"
    
    main_msg = await update.message.reply_text(f"⏳ Scraping `{url}`...", parse_mode="Markdown")
    
    try:
        # Your scrape logic here - replace with actual implementation
        # result, raw_count = await scrape_url(url, js=js_mode)
        # items = result.get("events", [])
        
        # Placeholder for demonstration:
        items = []  # Replace with actual scrape result
        
        if not items:
            await main_msg.edit_text(
                f"⏳ Scraping `{url}`...\n\n❌ No data found.",
                parse_mode="Markdown"
            )
            return
        
        for m in _build_batches(items, url):
            await update.message.reply_text(m, parse_mode="Markdown")
        
        # Success indicator
        await main_msg.edit_text(
            f"⏳ Scraping `{url}`...\n\n🎫 Scrape completed successfully!",
            parse_mode="Markdown"
        )
        
    except Exception as e:
        logger.exception("[TELEGRAM] Scrape command failed")
        error_msg = str(e)[:200]
        await main_msg.edit_text(
            f"⏳ Scraping `{url}`...\n\n❌ Error: {error_msg}",
            parse_mode="Markdown"
        )

# ──────────────────────────────────────────────
# Bot lifecycle
# ──────────────────────────────────────────────
_bot_started = False
_stop_event: threading.Event = threading.Event()

def start_bot() -> bool:
    """Start the Telegram bot in a background daemon thread."""
    global _bot_started
    if _bot_started:
        logger.info("[TELEGRAM] Already started — skipping.")
        return False
    if not TELEGRAM_TOKEN:
        logger.warning("[TELEGRAM] No valid token — bot will NOT start.")
        return False
    
    _bot_started = True
    
    async def _run():
        app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
        app.add_handler(CommandHandler("ping", _handle_ping))
        app.add_handler(CommandHandler("scrape", _handle_scrape))
        
        try:
            await app.initialize()
            await app.start()
            await app.updater.start_polling(drop_pending_updates=True)
            logger.info("[TELEGRAM] Polling started ✓")
            
            while not _stop_event.is_set():
                await asyncio.sleep(1)
        except Exception:
            logger.error("[TELEGRAM] Bot failed to start:\n%s", traceback.format_exc())
        finally:
            try:
                await app.updater.stop()
                await app.stop()
                await app.shutdown()
            except Exception:
                pass
            logger.info("[TELEGRAM] Bot shut down.")
    
    def _thread_target():
        try:
            asyncio.run(_run())
        except Exception:
            logger.error("[TELEGRAM] Thread crashed:\n%s", traceback.format_exc())
    
    threading.Thread(target=_thread_target, daemon=True, name="telegram-bot").start()
    logger.info("[TELEGRAM] Bot thread started ✓")
    return True

def stop_bot():
    """Signal the bot thread to shut down gracefully."""
    _stop_event.set()
    logger.info("[TELEGRAM] Stop signal sent.")
