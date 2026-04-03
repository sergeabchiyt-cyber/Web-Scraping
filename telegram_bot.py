import asyncio
import logging
import os
import re
import signal
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from telegram import Update
from telegram.ext import (
    Application, ApplicationBuilder, CommandHandler, MessageHandler,
    filters, CallbackContext
)

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
logger = logging.getLogger("telegram_bot")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
MAX_CHARS = 4096

# ──────────────────────────────────────────────
# Token sanitising
# ──────────────────────────────────────────────
_raw_token = os.environ.get("TELEGRAM_TOKEN", "").strip()
_clean_token = _raw_token.lstrip("=").strip().strip("'\"")
TELEGRAM_TOKEN = None

if re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{30,}", _clean_token):
    TELEGRAM_TOKEN = _clean_token
    logger.info("[TELEGRAM] Valid token loaded ✓")
else:
    if _raw_token:
        logger.error(
            "[TELEGRAM] Invalid token after cleaning: '%s'. "
            "Fix your TELEGRAM_TOKEN environment variable.",
            _clean_token[:20]
        )
    else:
        logger.warning("[TELEGRAM] TELEGRAM_TOKEN not set.")

# ──────────────────────────────────────────────
# Markdown helpers (same as your original)
# ──────────────────────────────────────────────
def _escape_md(text: str) -> str:
    return (str(text)
            .replace("\\", "\\\\")
            .replace("`", "'")
            .replace("*", "\\*")
            .replace("_", "\\_"))

def _fmt_item(idx: int, item: dict) -> str:
    lines = [f"*{idx}. {_escape_md(item.get('name', 'Item'))}*"]
    for k, v in item.items():
        if k == "name":
            continue
        lines.append(f" {k.replace('_', ' ').title()}: {_escape_md(str(v))}")
    return "\n".join(lines)

def _build_batches(items: list, url: str) -> list[str]:
    messages = []
    batch_num = 1
    def header(item_idx: int) -> str:
        return (f"📊 *AUDITOR* — `{url[:30]}...`\n"
                f"Msg {batch_num} · #{item_idx} · {len(items)} total\n"
                f"{'─' * 20}\n")
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
# Command handlers (same as your original)
# ──────────────────────────────────────────────
async def _handle_start(update: Update, context: CallbackContext):
    logger.info(f"/start from {update.effective_user.id}")
    await update.message.reply_text(
        "👋 *Welcome to AUDITOR Bot*\n\n"
        "Available commands:\n"
        "• `/ping` — Check if bot is online\n"
        "• `/scrape <url> [js]` — Scrape a URL\n"
        "• `/help` — Show this message",
        parse_mode="Markdown"
    )

async def _handle_help(update: Update, context: CallbackContext):
    logger.info(f"/help from {update.effective_user.id}")
    await update.message.reply_text(
        "📚 *AUDITOR Bot Help*\n\n"
        "*Commands:*\n"
        "• `/ping` — Verify bot is responding\n"
        "• `/scrape <url> [js]` — Scrape content\n"
        "  - `url`: Target URL to scrape\n"
        "  - `js` (optional): Enable JavaScript rendering\n"
        "• `/start` — Show welcome message\n"
        "• `/help` — Show this message",
        parse_mode="Markdown"
    )

async def _handle_ping(update: Update, context: CallbackContext):
    logger.info(f"/ping from {update.effective_user.id}")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    await update.message.reply_text(
        f"✅ *AUDITOR Online*\n🕐 `{now}`",
        parse_mode="Markdown"
    )

async def _handle_scrape(update: Update, context: CallbackContext):
    """Your actual scraping logic goes here – this is a placeholder."""
    try:
        logger.info(f"/scrape from {update.effective_user.id} args={context.args}")
        if not context.args:
            await update.message.reply_text(
                "❌ Usage: `/scrape <url> [js]`", parse_mode="Markdown"
            )
            return
        url = context.args[0]
        js_mode = len(context.args) > 1 and context.args[1].lower() == "js"

        main_msg = await update.message.reply_text(
            f"⏳ Scraping `{url}`... (JS={'enabled' if js_mode else 'disabled'})",
            parse_mode="Markdown"
        )

        # --------------------------------------------------
        # 🔁 REPLACE THIS BLOCK WITH YOUR REAL SCRAPER
        # Example: items = await your_scraper_function(url, js=js_mode)
        # --------------------------------------------------
        items = []   # <-- replace with actual scraped data
        # --------------------------------------------------

        if not items:
            await main_msg.edit_text(f"⚠️ No data found at `{url}`", parse_mode="Markdown")
            return

        batch_messages = _build_batches(items, url)
        for batch in batch_messages:
            await update.message.reply_text(batch, parse_mode="Markdown")
        await main_msg.edit_text(f"✅ Sent {len(batch_messages)} message(s).", parse_mode="Markdown")

    except Exception as e:
        logger.exception("Scrape handler failed")
        await update.message.reply_text(f"❌ Error: {str(e)[:200]}")

async def _handle_message(update: Update, context: CallbackContext):
    logger.info(f"Message from {update.effective_user.id}: {update.message.text[:50]}")
    await update.message.reply_text(
        "💬 I'm an AUDITOR bot. Use `/help` for available commands.",
        parse_mode="Markdown"
    )

async def _handle_error(update: Update, context: CallbackContext):
    logger.error(f"Update {update} caused error {context.error}")
    if update and update.message:
        await update.message.reply_text("❌ An error occurred. Please try again later.")

# ──────────────────────────────────────────────
# Bot runner (single event loop, handles signals)
# ──────────────────────────────────────────────
_shutdown_event = asyncio.Event()

async def run_bot():
    """Main bot coroutine – starts polling and waits for shutdown signal."""
    if not TELEGRAM_TOKEN:
        logger.error("No valid token – bot will not start.")
        return

    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", _handle_start))
    app.add_handler(CommandHandler("help", _handle_help))
    app.add_handler(CommandHandler("ping", _handle_ping))
    app.add_handler(CommandHandler("scrape", _handle_scrape))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, _handle_message))
    app.add_error_handler(_handle_error)

    # Start polling (drop pending updates to clean stale ones)
    await app.initialize()
    await app.start()
    await app.updater.start_polling(
        drop_pending_updates=True,
        allowed_updates=["message", "callback_query"]
    )
    logger.info("✅ Bot polling started")

    # Wait for shutdown signal (SIGTERM / SIGINT)
    await _shutdown_event.wait()

    # Graceful shutdown
    logger.info("Stopping bot...")
    await app.updater.stop()
    await app.stop()
    await app.shutdown()
    logger.info("Bot stopped.")

def handle_shutdown_signal():
    """Called when SIGTERM or SIGINT is received."""
    logger.info("Shutdown signal received – stopping bot...")
    _shutdown_event.set()

# ──────────────────────────────────────────────
# FastAPI lifespan integration (use this in your main app)
# ──────────────────────────────────────────────
@asynccontextmanager
async def telegram_lifespan(app):
    """Lifespan context manager for FastAPI."""
    # Startup
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_shutdown_signal)
    asyncio.create_task(run_bot())
    yield
    # Shutdown (triggered by FastAPI when the app stops)
    handle_shutdown_signal()  # ensures bot stops

# ──────────────────────────────────────────────
# Standalone execution (for testing)
# ──────────────────────────────────────────────
if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_shutdown_signal)
    try:
        loop.run_until_complete(run_bot())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
