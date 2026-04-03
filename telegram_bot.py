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
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
MAX_CHARS = 4096

# ──────────────────────────────────────────────
# Token handling — sanitise whatever the env var holds
# ──────────────────────────────────────────────
_raw_token = os.environ.get("TELEGRAM_TOKEN", "") or ""
_clean_token = _raw_token.strip().lstrip("=").strip().strip("'\"").strip()
TELEGRAM_TOKEN: str | None = None

if re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{30,}", _clean_token):
    TELEGRAM_TOKEN = _clean_token
    logger.info("[TELEGRAM] Valid token loaded ✓")
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
        lines.append(f" {k.replace('_', ' ').title()}: {_escape_md(str(v))}")
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
async def _handle_start(update, context):
    """Handle /start command."""
    logger.info(f"[TELEGRAM] /start from {update.effective_user.id}")
    await update.message.reply_text(
        "👋 *Welcome to AUDITOR Bot*\n\n"
        "Available commands:\n"
        "• `/ping` — Check if bot is online\n"
        "• `/scrape <url> [js]` — Scrape a URL\n"
        "• `/help` — Show this message",
        parse_mode="Markdown",
    )

async def _handle_help(update, context):
    """Handle /help command."""
    logger.info(f"[TELEGRAM] /help from {update.effective_user.id}")
    await update.message.reply_text(
        "📚 *AUDITOR Bot Help*\n\n"
        "*Commands:*\n"
        "• `/ping` — Verify bot is responding\n"
        "• `/scrape <url> [js]` — Scrape content\n"
        "  - `url`: Target URL to scrape\n"
        "  - `js` (optional): Enable JavaScript rendering\n"
        "• `/start` — Show welcome message\n"
        "• `/help` — Show this message",
        parse_mode="Markdown",
    )

async def _handle_ping(update, context):
    """Handle /ping command."""
    try:
        logger.info(f"[TELEGRAM] /ping from {update.effective_user.id}")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        await update.message.reply_text(
            f"✅ *AUDITOR Online*\n🕐 `{now}`",
            parse_mode="Markdown",
        )
    except Exception as e:
        logger.exception("[TELEGRAM] _handle_ping failed")
        await update.message.reply_text(f"❌ Error: {str(e)[:200]}")

async def _handle_scrape(update, context):
    """Handle /scrape command."""
    try:
        logger.info(f"[TELEGRAM] /scrape from {update.effective_user.id} with args: {context.args}")
        
        if not context.args:
            await update.message.reply_text(
                "❌ Usage: `/scrape <url> [js]`\n\n"
                "Example:\n"
                "• `/scrape https://example.com`\n"
                "• `/scrape https://example.com js`",
                parse_mode="Markdown"
            )
            return
        
        url = context.args[0]
        js_mode = len(context.args) > 1 and context.args[1].lower() == "js"
        
        logger.info(f"[TELEGRAM] Scraping {url} (js_mode={js_mode})")
        
        main_msg = await update.message.reply_text(
            f"⏳ Scraping `{url}`...\n(JavaScript: {'enabled' if js_mode else 'disabled'})",
            parse_mode="Markdown"
        )
        
        try:
            # ⚠️ REPLACE THIS WITH YOUR ACTUAL SCRAPE LOGIC ⚠️
            # Example placeholder:
            # from your_scraper_module import scrape_url
            # result, raw_count = await scrape_url(url, js=js_mode)
            # items = result.get("events", [])
            
            # For now, this is a demo that shows success:
            items = []  # Replace with actual scrape result
            
            if not items:
                await main_msg.edit_text(
                    f"⏳ Scraping `{url}`...\n\n"
                    f"⚠️ *No data found* (or scraper not implemented yet).",
                    parse_mode="Markdown"
                )
                logger.warning(f"[TELEGRAM] Scrape returned no items for {url}")
                return
            
            # Send batched results
            batch_messages = _build_batches(items, url)
            for batch_idx, msg_text in enumerate(batch_messages, start=1):
                await update.message.reply_text(msg_text, parse_mode="Markdown")
                logger.info(f"[TELEGRAM] Sent batch {batch_idx}/{len(batch_messages)}")
            
            # Mark as complete
            await main_msg.edit_text(
                f"✅ Scraping `{url}`...\n\n"
                f"🎫 Completed! Sent {len(batch_messages)} message(s).",
                parse_mode="Markdown"
            )
            logger.info(f"[TELEGRAM] Scrape completed for {url}")
            
        except Exception as e:
            logger.exception(f"[TELEGRAM] Scrape logic failed")
            error_msg = str(e)[:200]
            await main_msg.edit_text(
                f"⏳ Scraping `{url}`...\n\n"
                f"❌ Error: {error_msg}",
                parse_mode="Markdown"
            )
            
    except Exception as e:
        logger.exception("[TELEGRAM] _handle_scrape outer exception")
        await update.message.reply_text(f"❌ Handler error: {str(e)[:200]}")

async def _handle_message(update, context):
    """Catch-all handler for all text messages."""
    try:
        user_id = update.effective_user.id
        user_name = update.effective_user.first_name or "User"
        text = update.message.text or "(no text)"
        
        logger.info(f"[TELEGRAM] Message from {user_name} (ID: {user_id}): {text[:50]}")
        
        # Only respond if it's not a command (commands are handled separately)
        if not text.startswith("/"):
            await update.message.reply_text(
                "💬 I'm an AUDITOR bot. Use `/help` for available commands.",
                parse_mode="Markdown"
            )
    except Exception as e:
        logger.exception("[TELEGRAM] _handle_message failed")

async def _handle_error(update, context):
    """Handle errors in handlers."""
    logger.error(f"[TELEGRAM] Update {update} caused error {context.error}")
    logger.exception(context.error)
    
    if update and update.message:
        try:
            await update.message.reply_text(
                "❌ An error occurred. Please try again later.",
                parse_mode="Markdown"
            )
        except Exception as e:
            logger.exception("[TELEGRAM] Could not send error message")

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
        logger.info("[TELEGRAM] Initializing ApplicationBuilder...")
        app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
        
        # Register command handlers
        app.add_handler(CommandHandler("start", _handle_start))
        app.add_handler(CommandHandler("help", _handle_help))
        app.add_handler(CommandHandler("ping", _handle_ping))
        app.add_handler(CommandHandler("scrape", _handle_scrape))
        
        # Register catch-all message handler (must be last)
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, _handle_message))
        
        # Register error handler
        app.add_error_handler(_handle_error)
        
        try:
            logger.info("[TELEGRAM] Initializing app...")
            await app.initialize()
            logger.info("[TELEGRAM] Starting app...")
            await app.start()
            logger.info("[TELEGRAM] Starting polling...")
            await app.updater.start_polling(
                drop_pending_updates=True,
                allowed_updates=["message", "callback_query"]
            )
            logger.info("[TELEGRAM] ✅ Polling started successfully!")
            
            # Keep running until stop signal
            while not _stop_event.is_set():
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"[TELEGRAM] Bot failed to start:\n{traceback.format_exc()}")
        finally:
            try:
                logger.info("[TELEGRAM] Stopping updater...")
                await app.updater.stop()
                logger.info("[TELEGRAM] Stopping app...")
                await app.stop()
                logger.info("[TELEGRAM] Shutting down app...")
                await app.shutdown()
            except Exception as e:
                logger.exception("[TELEGRAM] Error during shutdown")
            logger.info("[TELEGRAM] Bot shut down completely.")
    
    def _thread_target():
        try:
            asyncio.run(_run())
        except Exception as e:
            logger.error(f"[TELEGRAM] Thread crashed:\n{traceback.format_exc()}")
    
    thread = threading.Thread(
        target=_thread_target,
        daemon=True,
        name="telegram-bot-daemon"
    )
    thread.start()
    logger.info("[TELEGRAM] 🚀 Bot thread started (daemon)")
    return True

def stop_bot():
    """Signal the bot thread to shut down gracefully."""
    _stop_event.set()
    logger.info("[TELEGRAM] Stop signal sent.")

# ──────────────────────────────────────────────
# Main entry point (for testing)
# ──────────────────────────────────────────────
if __name__ == "__main__":
    logger.info("[TELEGRAM] Starting bot...")
    start_bot()
    try:
        while True:
            asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("[TELEGRAM] KeyboardInterrupt received.")
        stop_bot()
