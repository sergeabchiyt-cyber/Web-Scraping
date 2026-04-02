import asyncio
import os
import threading
import traceback
from datetime import datetime, timezone
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
MAX_CHARS = 4096

def _escape_md(text: str) -> str:
    return str(text).replace('\\', '\\\\').replace('`', "'").replace('*', '\\*').replace('_', '\\_')

def _fmt_item(idx: int, item: dict) -> str:
    lines = [f"*{idx}. {_escape_md(item.get('name', 'Item'))}*"]
    for k, v in item.items():
        if k == 'name': continue
        lines.append(f"  {k.replace('_', ' ').title()}: {_escape_md(v)}")
    return '\n'.join(lines)

def _build_batches(items: list, url: str) -> list[str]:
    messages, current, batch_num = [], "", 1
    header = lambda i: f"📊 *AUDITOR* — `{url[:30]}...`\nMsg {batch_num} · #{i} · {len(items)} total\n{'─' * 20}\n"
    current = header(1)
    for i, item in enumerate(items, start=1):
        block = _fmt_item(i, item) + '\n\n'
        if len(current) + len(block) > MAX_CHARS:
            messages.append(current.rstrip())
            batch_num += 1
            current = header(i) + block
        else:
            current += block
    if current.strip(): messages.append(current.rstrip())
    return messages

async def _handle_ping(update, context):
    from command_center import API_KEY
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    await update.message.reply_text(f"✅ *AUDITOR Online*\n🕐 `{now}`\n🔑 Key: `{API_KEY[:8]}...`", parse_mode='Markdown')

async def _handle_scrape(update, context):
    from command_center import scrape_url
    if not context.args:
        await update.message.reply_text("❌ Usage: `/scrape <url> [js]`")
        return
    url = context.args[0]
    js_mode = len(context.args) > 1 and context.args[1].lower() == 'js'
    msg = await update.message.reply_text(f"⏳ Scraping `{url}`...")
    try:
        result, raw_count = await scrape_url(url, js=js_mode)
        items = result.get('events', [])
        if not items:
            await update.message.reply_text("⚠️ No data found.")
            return
        for m in _build_batches(items, url):
            await update.message.reply_text(m, parse_mode='Markdown')
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)[:200]}")

_bot_started = False
def start_bot():
    global _bot_started
    if _bot_started or not TELEGRAM_TOKEN:
        print("[TELEGRAM] Token missing or already started.")
        return
    _bot_started = True

    async def _run():
        app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
        app.add_handler(CommandHandler("ping", _handle_ping))
        app.add_handler(CommandHandler("scrape", _handle_scrape))
        await app.initialize()
        await app.start()
        await app.updater.start_polling(drop_pending_updates=True)
        while True: await asyncio.sleep(3600)

    threading.Thread(target=lambda: asyncio.run(_run()), daemon=True).start()
    print("[TELEGRAM] Bot thread started ✓")
