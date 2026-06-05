#!/usr/bin/env python3
"""
Telegram Bot - Advanced Multi-Port Network Scanner
Professional Edition | Admin Panel | Interactive | High Compression ZIP Output
"""

import os
import sys
import asyncio
import logging
import tempfile
import zipfile
import socket
import ipaddress
import concurrent.futures
import time
import random
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Set, Tuple, Optional

# Telegram Bot
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ConversationHandler,
    ContextTypes,
    filters
)
from telegram.constants import ParseMode

# --------------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------------
# Environment & Configuration
# --------------------------------------------------------------------------------
BOT_TOKEN = os.getenv("BOT_TOKEN")
admin_ids_raw = os.getenv("ADMIN_IDS", "8187239222,5914346958")
ADMIN_IDS = [int(x.strip()) for x in admin_ids_raw.split(",") if x.strip()]
AUTH_REQUIRED = os.getenv("AUTH_REQUIRED", "False").lower() == "true"

# --------------------------------------------------------------------------------
# Database (SQLite via thread executor for async safety)
# --------------------------------------------------------------------------------
DB_PATH = "bot_scanner.db"

class Database:
    def __init__(self):
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    username TEXT,
                    first_name TEXT,
                    is_authorized INTEGER DEFAULT 1,
                    is_banned INTEGER DEFAULT 0,
                    scan_count INTEGER DEFAULT 0,
                    last_scan TIMESTAMP
                )
            """)
            conn.commit()

    async def get_user(self, user_id: int) -> Optional[Dict]:
        def _sync():
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.execute(
                    "SELECT * FROM users WHERE user_id = ?", (user_id,)
                )
                row = cursor.fetchone()
                if row:
                    return {
                        "user_id": row[0],
                        "username": row[1],
                        "first_name": row[2],
                        "is_authorized": bool(row[3]),
                        "is_banned": bool(row[4]),
                        "scan_count": row[5],
                        "last_scan": row[6],
                    }
                return None
        return await asyncio.to_thread(_sync)

    async def add_or_update_user(self, user_id: int, username: str, first_name: str) -> None:
        def _sync():
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO users (user_id, username, first_name)
                    VALUES (?, ?, ?)
                """, (user_id, username, first_name))
                conn.commit()
        await asyncio.to_thread(_sync)

    async def increment_scan(self, user_id: int) -> None:
        def _sync():
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("""
                    UPDATE users SET scan_count = scan_count + 1,
                    last_scan = ?
                    WHERE user_id = ?
                """, (datetime.now().isoformat(), user_id))
                conn.commit()
        await asyncio.to_thread(_sync)

    async def set_authorized(self, user_id: int, authorized: bool) -> None:
        def _sync():
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "UPDATE users SET is_authorized = ? WHERE user_id = ?",
                    (int(authorized), user_id)
                )
                conn.commit()
        await asyncio.to_thread(_sync)

    async def set_banned(self, user_id: int, banned: bool) -> None:
        def _sync():
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "UPDATE users SET is_banned = ? WHERE user_id = ?",
                    (int(banned), user_id)
                )
                conn.commit()
        await asyncio.to_thread(_sync)

    async def get_all_users(self) -> List[Dict]:
        def _sync():
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.execute("SELECT * FROM users")
                rows = cursor.fetchall()
                return [
                    {
                        "user_id": row[0],
                        "username": row[1],
                        "first_name": row[2],
                        "is_authorized": bool(row[3]),
                        "is_banned": bool(row[4]),
                        "scan_count": row[5],
                        "last_scan": row[6],
                    }
                    for row in rows
                ]
        return await asyncio.to_thread(_sync)

    async def get_stats(self) -> Dict:
        def _sync():
            with sqlite3.connect(DB_PATH) as conn:
                total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                active_today = conn.execute(
                    "SELECT COUNT(*) FROM users WHERE last_scan > ?",
                    (datetime.now().strftime("%Y-%m-%d"),)
                ).fetchone()[0]
                total_scans = conn.execute("SELECT SUM(scan_count) FROM users").fetchone()[0] or 0
                return {
                    "total_users": total_users,
                    "active_today": active_today,
                    "total_scans": total_scans,
                }
        return await asyncio.to_thread(_sync)

db = Database()

# --------------------------------------------------------------------------------
# IP Range Parsing Utilities (same as previous)
# --------------------------------------------------------------------------------
def parse_ip_range(range_str: str) -> List[ipaddress.IPv4Address]:
    range_str = range_str.strip()
    if not range_str:
        return []
    if '/' in range_str:
        try:
            network = ipaddress.ip_network(range_str, strict=False)
            return list(network.hosts())
        except ValueError:
            return []
    if '-' in range_str:
        parts = range_str.split('-')
        if len(parts) != 2:
            return []
        try:
            start = ipaddress.IPv4Address(parts[0].strip())
            end = ipaddress.IPv4Address(parts[1].strip())
        except ipaddress.AddressValueError:
            return []
        if start > end:
            start, end = end, start
        return [ipaddress.IPv4Address(i) for i in range(int(start), int(end)+1)]
    try:
        return [ipaddress.IPv4Address(range_str)]
    except ipaddress.AddressValueError:
        return []

def load_ranges_from_text(text: str) -> Set[ipaddress.IPv4Address]:
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        ips.update(parse_ip_range(line))
    return ips

# --------------------------------------------------------------------------------
# Scanner (Sequential, Threaded, same core as before)
# --------------------------------------------------------------------------------
class SequentialPortScanner:
    def __init__(self, target_ips: List[ipaddress.IPv4Address], ports: List[int],
                 threads: int = 200, timeout: float = 0.8, shuffle: bool = False):
        self.target_ips = target_ips
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.shuffle = shuffle
        self.all_open_pairs: List[str] = []

    def scan_port(self, port: int) -> Set[str]:
        open_ips = set()
        total = len(self.target_ips)
        scanned = 0
        ips_to_scan = self.target_ips.copy()
        if self.shuffle:
            random.shuffle(ips_to_scan)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {executor.submit(self._check_port, ip, port): ip for ip in ips_to_scan}
            for future in concurrent.futures.as_completed(future_to_ip):
                scanned += 1
                ip, is_open = future.result()
                if is_open:
                    open_ips.add(str(ip))
        return open_ips

    def _check_port(self, ip: ipaddress.IPv4Address, port: int) -> Tuple[ipaddress.IPv4Address, bool]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((str(ip), port))
                return ip, (result == 0)
        except:
            return ip, False

    def run(self):
        for port in self.ports:
            open_ips = self.scan_port(port)
            for ip in sorted(open_ips):
                self.all_open_pairs.append(f"{ip}:{port}")
        self.all_open_pairs.sort()

# --------------------------------------------------------------------------------
# Helper to create compressed ZIP
# --------------------------------------------------------------------------------
def create_zip_from_text(text: str, filename: str = "scan_results.txt") -> str:
    """Create a highly compressed ZIP file containing the text, return temp file path."""
    tmp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(tmp_dir, "scan_results.zip")
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr(filename, text)
    return zip_path

# --------------------------------------------------------------------------------
# Bot Conversation States
# --------------------------------------------------------------------------------
TARGET, PORTS = range(2)

# --------------------------------------------------------------------------------
# Admin check decorator
# --------------------------------------------------------------------------------
def admin_only(func):
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        if user_id not in ADMIN_IDS:
            await update.message.reply_text("⛔ شما دسترسی ادمین ندارید.")
            return
        return await func(update, context)
    return wrapper

# --------------------------------------------------------------------------------
# Command Handlers
# --------------------------------------------------------------------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    await db.add_or_update_user(user.id, user.username, user.first_name)

    # Check if banned
    user_data = await db.get_user(user.id)
    if user_data and user_data["is_banned"]:
        await update.message.reply_text("⛔ شما از ربات مسدود شده‌اید.")
        return ConversationHandler.END

    # Authorization check (if required)
    if AUTH_REQUIRED and not (user_data and user_data["is_authorized"]):
        await update.message.reply_text("⛔ شما مجاز به استفاده از ربات نیستید.")
        return ConversationHandler.END

    await update.message.reply_text(
        "🔍 *اسکنر پیشرفته پورت*\n\n"
        "📌 یک محدوده IP (مثل `192.168.1.1 - 192.168.100.100` یا `10.0.0.0/24`)\n"
        "📎 یا یک فایل txt حاوی چندین محدوده را ارسال کنید.\n\n"
        "برای لغو، /cancel را بفرستید.",
        parse_mode=ParseMode.MARKDOWN
    )
    return TARGET

async def receive_target(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Handle text (IP range) or document (txt file)
    if update.message.document:
        # It's a file
        if not update.message.document.file_name.lower().endswith('.txt'):
            await update.message.reply_text("❌ لطفاً فقط فایل txt ارسال کنید.")
            return TARGET
        try:
            file = await update.message.document.get_file()
            # Save to temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
                await file.download_to_drive(tmp.name)
                with open(tmp.name, 'r', encoding='utf-8') as f:
                    content = f.read()
            os.unlink(tmp.name)
        except Exception as e:
            await update.message.reply_text(f"❌ خطا در خواندن فایل: {e}")
            return TARGET
    elif update.message.text:
        content = update.message.text.strip()
    else:
        await update.message.reply_text("❌ فقط متن یا فایل txt پشتیبانی می‌شود.")
        return TARGET

    # Parse IPs
    ip_set = load_ranges_from_text(content)
    if not ip_set:
        await update.message.reply_text("❌ هیچ IP معتبری در ورودی پیدا نشد. دوباره تلاش کنید.")
        return TARGET

    # Store in context
    context.user_data['target_ips'] = list(ip_set)
    await update.message.reply_text(
        f"✅ {len(ip_set)} IP معتبر دریافت شد.\n\n"
        "⚙️ حالا پورت‌های مورد نظر را با کاما جدا کنید (مثال: `21,443`)",
        parse_mode=ParseMode.MARKDOWN
    )
    return PORTS

async def receive_ports(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message.text:
        await update.message.reply_text("❌ متن وارد کنید.")
        return PORTS

    ports_str = update.message.text.strip()
    ports = []
    try:
        for part in ports_str.split(','):
            p = int(part.strip())
            if 1 <= p <= 65535:
                ports.append(p)
            else:
                raise ValueError
    except ValueError:
        await update.message.reply_text("❌ پورت‌های نامعتبر. فقط اعداد 1-65535 با کاما.")
        return PORTS

    if not ports:
        await update.message.reply_text("❌ حداقل یک پورت وارد کنید.")
        return PORTS

    # Store ports
    context.user_data['ports'] = ports

    # Start scan
    await update.message.reply_text(
        f"🚀 اسکن آغاز شد... ({len(context.user_data['target_ips'])} IP برای پورت‌های {ports})\n"
        "⏳ ممکن است کمی طول بکشد. لطفاً منتظر بمانید."
    )

    # Run scanner in thread
    scanner = SequentialPortScanner(
        target_ips=context.user_data['target_ips'],
        ports=ports,
        threads=200,
        timeout=0.8
    )
    try:
        await asyncio.to_thread(scanner.run)
    except Exception as e:
        await update.message.reply_text(f"❌ خطا در اسکن: {e}")
        return ConversationHandler.END

    # Update scan count
    await db.increment_scan(update.effective_user.id)

    # Generate output
    output_text = "\n".join(scanner.all_open_pairs) if scanner.all_open_pairs else "No open ports found."

    # Decide delivery method
    if len(output_text) <= 4096:
        await update.message.reply_text(f"✅ اسکن کامل شد.\n\n{output_text}")
    else:
        # Create compressed zip
        zip_path = create_zip_from_text(output_text)
        await update.message.reply_document(
            document=open(zip_path, 'rb'),
            filename="scan_results.zip",
            caption=f"📦 نتایج اسکن ({len(scanner.all_open_pairs)} باز)"
        )
        os.unlink(zip_path)

    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("❌ عملیات لغو شد.")
    return ConversationHandler.END

# --------------------------------------------------------------------------------
# Admin Commands
# --------------------------------------------------------------------------------
@admin_only
async def admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    stats = await db.get_stats()
    text = (
        "📊 *پنل مدیریت*\n\n"
        f"👥 کاربران کل: {stats['total_users']}\n"
        f"📅 کاربران فعال امروز: {stats['active_today']}\n"
        f"🔢 تعداد کل اسکن‌ها: {stats['total_scans']}\n\n"
        "دستورات:\n"
        "/broadcast <پیام> - ارسال به همه\n"
        "/adduser <user_id>\n"
        "/removeuser <user_id>\n"
        "/ban <user_id>\n"
        "/unban <user_id>"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)

@admin_only
async def broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ لطفاً پیام را وارد کنید. مثال: `/broadcast سلام`")
        return
    message = ' '.join(context.args)
    users = await db.get_all_users()
    success = 0
    for user in users:
        try:
            await context.bot.send_message(chat_id=user['user_id'], text=message)
            success += 1
        except:
            pass
    await update.message.reply_text(f"✅ پیام به {success}/{len(users)} کاربر ارسال شد.")

@admin_only
async def add_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ استفاده: /adduser <user_id>")
        return
    try:
        uid = int(context.args[0])
    except:
        await update.message.reply_text("❌ user_id نامعتبر.")
        return
    await db.set_authorized(uid, True)
    await update.message.reply_text(f"✅ کاربر {uid} مجاز شد.")

@admin_only
async def remove_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ استفاده: /removeuser <user_id>")
        return
    try:
        uid = int(context.args[0])
    except:
        await update.message.reply_text("❌ user_id نامعتبر.")
        return
    await db.set_authorized(uid, False)
    await update.message.reply_text(f"✅ کاربر {uid} غیرمجاز شد.")

@admin_only
async def ban_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ استفاده: /ban <user_id>")
        return
    try:
        uid = int(context.args[0])
    except:
        await update.message.reply_text("❌ user_id نامعتبر.")
        return
    await db.set_banned(uid, True)
    await update.message.reply_text(f"🚫 کاربر {uid} مسدود شد.")

@admin_only
async def unban_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ استفاده: /unban <user_id>")
        return
    try:
        uid = int(context.args[0])
    except:
        await update.message.reply_text("❌ user_id نامعتبر.")
        return
    await db.set_banned(uid, False)
    await update.message.reply_text(f"✅ کاربر {uid} رفع مسدودیت شد.")

# --------------------------------------------------------------------------------
# Main Application
# --------------------------------------------------------------------------------
def main():
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN is missing!")
        sys.exit(1)

    app = Application.builder().token(BOT_TOKEN).build()

    # Conversation handler for scan flow
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            TARGET: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_target),
                MessageHandler(filters.Document.ALL, receive_target),
            ],
            PORTS: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_ports)],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
    )

    app.add_handler(conv_handler)

    # Admin commands
    app.add_handler(CommandHandler("admin", admin_panel))
    app.add_handler(CommandHandler("broadcast", broadcast))
    app.add_handler(CommandHandler("adduser", add_user))
    app.add_handler(CommandHandler("removeuser", remove_user))
    app.add_handler(CommandHandler("ban", ban_user))
    app.add_handler(CommandHandler("unban", unban_user))

    logger.info("Bot started...")
    app.run_polling()

if __name__ == "__main__":
    main()