#!/usr/bin/env python3
"""
Ultimate Telegram Bot - Advanced Multi-Port Network Scanner
Professional Admin Panel | Rate Limiter | Export Tools | Inline Menus
Version 2.0
"""

import os, sys, asyncio, logging, tempfile, zipfile, socket, ipaddress
import concurrent.futures, time, random, sqlite3, csv, io
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Set, Tuple, Optional, Any

# Telegram Bot
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    ConversationHandler, ContextTypes, filters
)
from telegram.constants import ParseMode

# --------------------------------------------------------------------------------
# ⚙️ تنظیمات اصلی - بدون نیاز به .env (فقط این‌جا تغییر دهید)
# --------------------------------------------------------------------------------
BOT_TOKEN = "8986138877:AAE-b5XiSWSeYnV95_gK2Uj6bDG0HghUKkE"                           # توکن ربات
ADMIN_IDS = [8187239222, 5914346958]                       # آیدی عددی ادمین‌ها
AUTH_REQUIRED = False                                      # اگر True فقط کاربران مجاز اسکن کنند
DB_PATH = "scanner_bot.db"                                 # مسیر دیتابیس
RATE_LIMIT_SECONDS = 0                                     # فاصله زمانی اجباری بین اسکن‌ها (0 = بدون محدودیت)

# --------------------------------------------------------------------------------
# راه‌اندازی لاگر
# --------------------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------------
# لایه دیتابیس
# --------------------------------------------------------------------------------
class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
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

    async def _execute(self, query, *args, fetch=False):
        def _sync():
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.execute(query, args)
                if fetch:
                    return [dict(row) for row in cur.fetchall()]
                conn.commit()
        return await asyncio.to_thread(_sync)

    async def get_user(self, user_id: int) -> Optional[Dict]:
        rows = await self._execute("SELECT * FROM users WHERE user_id = ?", user_id, fetch=True)
        return rows[0] if rows else None

    async def add_or_update_user(self, user_id: int, username: str, first_name: str) -> None:
        await self._execute(
            "INSERT OR REPLACE INTO users (user_id, username, first_name) VALUES (?, ?, ?)",
            user_id, username, first_name
        )

    async def increment_scan(self, user_id: int) -> None:
        await self._execute(
            "UPDATE users SET scan_count = scan_count + 1, last_scan = ? WHERE user_id = ?",
            datetime.now(timezone.utc).isoformat(), user_id
        )

    async def set_authorized(self, user_id: int, status: bool) -> None:
        await self._execute(
            "UPDATE users SET is_authorized = ? WHERE user_id = ?",
            int(status), user_id
        )

    async def set_banned(self, user_id: int, status: bool) -> None:
        await self._execute(
            "UPDATE users SET is_banned = ? WHERE user_id = ?",
            int(status), user_id
        )

    async def get_all_users(self) -> List[Dict]:
        return await self._execute("SELECT * FROM users", fetch=True)

    async def get_stats(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        today = now.strftime("%Y-%m-%d")
        week_ago = (now - timedelta(days=7)).strftime("%Y-%m-%d")
        month_ago = (now - timedelta(days=30)).strftime("%Y-%m-%d")

        total = await self._execute("SELECT COUNT(*) as c FROM users", fetch=True)
        active_today = await self._execute("SELECT COUNT(*) as c FROM users WHERE last_scan > ?", today, fetch=True)
        active_week = await self._execute("SELECT COUNT(*) as c FROM users WHERE last_scan > ?", week_ago, fetch=True)
        active_month = await self._execute("SELECT COUNT(*) as c FROM users WHERE last_scan > ?", month_ago, fetch=True)
        total_scans = await self._execute("SELECT SUM(scan_count) as c FROM users", fetch=True)
        banned = await self._execute("SELECT COUNT(*) as c FROM users WHERE is_banned = 1", fetch=True)
        authorized = await self._execute("SELECT COUNT(*) as c FROM users WHERE is_authorized = 1", fetch=True)

        return {
            "total_users": total[0]['c'],
            "active_today": active_today[0]['c'],
            "active_week": active_week[0]['c'],
            "active_month": active_month[0]['c'],
            "total_scans": total_scans[0]['c'] or 0,
            "banned_users": banned[0]['c'],
            "authorized_users": authorized[0]['c'],
        }

    async def reset_user_scans(self, user_id: int) -> None:
        await self._execute(
            "UPDATE users SET scan_count = 0, last_scan = NULL WHERE user_id = ?",
            user_id
        )

    async def clear_all(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM users")
            conn.commit()

    async def auth_all(self, status: bool) -> None:
        await self._execute("UPDATE users SET is_authorized = ?", int(status))

    async def export_csv(self) -> str:
        rows = await self.get_all_users()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["user_id", "username", "first_name", "is_authorized", "is_banned", "scan_count", "last_scan"])
        for r in rows:
            writer.writerow([r["user_id"], r["username"], r["first_name"], r["is_authorized"], r["is_banned"], r["scan_count"], r["last_scan"]])
        return output.getvalue()

db = Database()

# --------------------------------------------------------------------------------
# مدیریت محدودیت نرخ (Rate Limiter)
# --------------------------------------------------------------------------------
rate_limit_seconds = RATE_LIMIT_SECONDS
last_scan_times: Dict[int, float] = {}

def check_rate_limit(user_id: int) -> Tuple[bool, int]:
    """بررسی محدودیت زمانی. (مجاز است یا خیر, ثانیه‌های باقی‌مانده)"""
    if rate_limit_seconds <= 0 or user_id in ADMIN_IDS:
        return True, 0
    now = time.time()
    last = last_scan_times.get(user_id, 0)
    diff = now - last
    if diff >= rate_limit_seconds:
        return True, 0
    return False, int(rate_limit_seconds - diff)

def update_rate_limit(user_id: int):
    last_scan_times[user_id] = time.time()

# --------------------------------------------------------------------------------
# ابزارهای آی‌پی و اسکن
# --------------------------------------------------------------------------------
def parse_ip_range(range_str: str) -> List[ipaddress.IPv4Address]:
    range_str = range_str.strip()
    if not range_str:
        return []
    if '/' in range_str:
        try:
            return list(ipaddress.ip_network(range_str, strict=False).hosts())
        except:
            return []
    if '-' in range_str:
        parts = range_str.split('-')
        if len(parts) != 2:
            return []
        try:
            s = ipaddress.IPv4Address(parts[0].strip())
            e = ipaddress.IPv4Address(parts[1].strip())
        except:
            return []
        if s > e:
            s, e = e, s
        return [ipaddress.IPv4Address(i) for i in range(int(s), int(e)+1)]
    try:
        return [ipaddress.IPv4Address(range_str)]
    except:
        return []

def load_ranges(text: str) -> Set[ipaddress.IPv4Address]:
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            ips.update(parse_ip_range(line))
    return ips

class SequentialPortScanner:
    def __init__(self, ips: List[ipaddress.IPv4Address], ports: List[int],
                 threads=200, timeout=0.8, shuffle=False):
        self.ips = ips
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.shuffle = shuffle
        self.results: List[str] = []

    def scan_port(self, port: int) -> Set[str]:
        open_set = set()
        ips = self.ips.copy()
        if self.shuffle:
            random.shuffle(ips)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            fut = {executor.submit(self._check, ip, port): ip for ip in ips}
            for future in concurrent.futures.as_completed(fut):
                ip, ok = future.result()
                if ok:
                    open_set.add(str(ip))
        return open_set

    def _check(self, ip: ipaddress.IPv4Address, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                return ip, (s.connect_ex((str(ip), port)) == 0)
        except:
            return ip, False

    def run(self):
        for port in self.ports:
            for ip in sorted(self.scan_port(port)):
                self.results.append(f"{ip}:{port}")

# --------------------------------------------------------------------------------
# فشرده‌سازی در ZIP
# --------------------------------------------------------------------------------
def create_zip(text: str, fname="results.txt") -> str:
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "scan_results.zip")
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr(fname, text)
    return path

# --------------------------------------------------------------------------------
# دستیارهای inline
# --------------------------------------------------------------------------------
def admin_keyboard():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📊 آمار کلی", callback_data="admin_stats"),
         InlineKeyboardButton("👤 اطلاعات کاربر", callback_data="admin_userinfo")],
        [InlineKeyboardButton("📨 پیام همگانی", callback_data="admin_broadcast"),
         InlineKeyboardButton("⏱ تنظیم نرخ", callback_data="admin_setrate")],
        [InlineKeyboardButton("📂 خروجی CSV", callback_data="admin_exportcsv"),
         InlineKeyboardButton("🗑 پاکسازی دیتابیس", callback_data="admin_cleardb")],
        [InlineKeyboardButton("✅ مجاز کردن همه", callback_data="admin_authall"),
         InlineKeyboardButton("❌ غیرمجاز کردن همه", callback_data="admin_deauthall")],
    ])

# --------------------------------------------------------------------------------
# Stateهای مکالمه
# --------------------------------------------------------------------------------
TARGET, PORTS = range(2)

# --------------------------------------------------------------------------------
# Check user authorization and ban
# --------------------------------------------------------------------------------
async def authorize_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    await db.add_or_update_user(user.id, user.username, user.first_name)
    data = await db.get_user(user.id)
    if data and data["is_banned"]:
        await update.message.reply_text("⛔ شما از ربات مسدود شده‌اید.")
        return False
    if AUTH_REQUIRED and not (data and data["is_authorized"]):
        await update.message.reply_text("⛔ شما مجاز به استفاده از ربات نیستید.")
        return False
    return True

# --------------------------------------------------------------------------------
# Command: /start
# --------------------------------------------------------------------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await authorize_user(update, context):
        return ConversationHandler.END

    # Rate limit check
    ok, remaining = check_rate_limit(update.effective_user.id)
    if not ok:
        await update.message.reply_text(f"⏳ لطفاً {remaining} ثانیه دیگر صبر کنید.")
        return ConversationHandler.END

    await update.message.reply_text(
        "🔍 *اسکنر پیشرفته پورت*\n\n"
        "📌 یک محدوده IP ارسال کنید:\n"
        "مثال: `192.168.1.1 - 192.168.100.100`\n"
        "یا `10.0.0.0/24`\n\n"
        "📎 یا فایل txt شامل چندین محدوده.\n"
        "برای لغو /cancel",
        parse_mode=ParseMode.MARKDOWN
    )
    return TARGET

# --------------------------------------------------------------------------------
# دریافت هدف
# --------------------------------------------------------------------------------
async def receive_target(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.document:
        doc = update.message.document
        if not doc.file_name.lower().endswith('.txt'):
            await update.message.reply_text("❌ فقط فایل txt پشتیبانی می‌شود.")
            return TARGET
        try:
            file = await doc.get_file()
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
                await file.download_to_drive(tmp.name)
                with open(tmp.name, 'r', encoding='utf-8') as f:
                    content = f.read()
            os.unlink(tmp.name)
        except Exception as e:
            await update.message.reply_text(f"❌ خطا: {e}")
            return TARGET
    elif update.message.text:
        content = update.message.text.strip()
    else:
        return TARGET

    ips = load_ranges(content)
    if not ips:
        await update.message.reply_text("❌ هیچ IP معتبری یافت نشد.")
        return TARGET

    context.user_data['target_ips'] = list(ips)
    await update.message.reply_text(
        f"✅ {len(ips)} IP دریافت شد.\n\n"
        "⚙️ حالا پورت‌ها را وارد کنید (مثال: `21,443`)\n"
        "/cancel برای لغو",
        parse_mode=ParseMode.MARKDOWN
    )
    return PORTS

# --------------------------------------------------------------------------------
# دریافت پورت‌ها و اجرای اسکن
# --------------------------------------------------------------------------------
async def receive_ports(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message.text:
        await update.message.reply_text("❌ متن وارد کنید.")
        return PORTS

    ports_str = update.message.text.strip()
    try:
        ports = [int(p.strip()) for p in ports_str.split(',') if 1 <= int(p.strip()) <= 65535]
    except:
        await update.message.reply_text("❌ پورت نامعتبر.")
        return PORTS
    if not ports:
        await update.message.reply_text("❌ حداقل یک پورت معتبر وارد کنید.")
        return PORTS

    context.user_data['ports'] = ports

    # Rate limit update
    update_rate_limit(update.effective_user.id)

    await update.message.reply_text(
        f"🚀 اسکن {len(context.user_data['target_ips'])} IP روی پورت‌های {ports} آغاز شد...\n"
        "⏳ لطفاً منتظر بمانید."
    )

    scanner = SequentialPortScanner(context.user_data['target_ips'], ports)
    try:
        await asyncio.to_thread(scanner.run)
    except Exception as e:
        await update.message.reply_text(f"❌ خطا در اسکن: {e}")
        return ConversationHandler.END

    # بروزرسانی آمار
    await db.increment_scan(update.effective_user.id)

    if not scanner.results:
        await update.message.reply_text("❌ هیچ پورت بازی پیدا نشد.")
        return ConversationHandler.END

    output = "\n".join(scanner.results)

    # ارسال هوشمند
    if len(output) <= 4096:
        await update.message.reply_text(f"✅ اسکن کامل شد:\n\n{output}")
    else:
        zip_path = create_zip(output)
        with open(zip_path, 'rb') as f:
            await update.message.reply_document(
                document=f,
                filename="scan_results.zip",
                caption=f"📦 نتایج ({len(scanner.results)} آیتم)"
            )
        os.unlink(zip_path)

    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("❌ عملیات لغو شد.")
    return ConversationHandler.END

# --------------------------------------------------------------------------------
# پنل مدیریت
# --------------------------------------------------------------------------------
async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS:
        await update.message.reply_text("⛔ دسترسی محدود.")
        return
    await update.message.reply_text(
        "⚙️ *پنل مدیریت پیشرفته*\nیک گزینه را انتخاب کنید:",
        reply_markup=admin_keyboard(),
        parse_mode=ParseMode.MARKDOWN
    )

# --------------------------------------------------------------------------------
# Callback handler مدیریت
# --------------------------------------------------------------------------------
async def admin_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id not in ADMIN_IDS:
        await query.edit_message_text("⛔ دسترسی غیرمجاز.")
        return

    data = query.data

    if data == "admin_stats":
        stats = await db.get_stats()
        text = (
            "📊 *آمار کلی*\n\n"
            f"👥 کل کاربران: {stats['total_users']}\n"
            f"📅 فعال امروز: {stats['active_today']}\n"
            f"📆 فعال این هفته: {stats['active_week']}\n"
            f"📆 فعال این ماه: {stats['active_month']}\n"
            f"🔢 کل اسکن‌ها: {stats['total_scans']}\n"
            f"🚫 کاربران مسدود: {stats['banned_users']}\n"
            f"✅ کاربران مجاز: {stats['authorized_users']}\n"
            f"⏱ محدودیت نرخ: {rate_limit_seconds} ثانیه"
        )
        await query.edit_message_text(text, parse_mode=ParseMode.MARKDOWN, reply_markup=admin_keyboard())

    elif data == "admin_userinfo":
        await query.edit_message_text(
            "👤 لطفاً آیدی عددی کاربر را با دستور `/userinfo <id>` وارد کنید.",
            parse_mode=ParseMode.MARKDOWN
        )

    elif data == "admin_broadcast":
        await query.edit_message_text(
            "📨 برای ارسال پیام همگانی از دستور `/broadcast <پیام>` استفاده کنید.",
            parse_mode=ParseMode.MARKDOWN
        )

    elif data == "admin_setrate":
        await query.edit_message_text(
            "⏱ برای تنظیم محدودیت نرخ از `/setrate <ثانیه>` استفاده کنید.",
            parse_mode=ParseMode.MARKDOWN
        )

    elif data == "admin_exportcsv":
        csv_data = await db.export_csv()
        buf = io.BytesIO(csv_data.encode('utf-8'))
        buf.name = "users.csv"
        await context.bot.send_document(chat_id=query.message.chat_id, document=buf)
        await query.edit_message_text("📂 فایل CSV ارسال شد.", reply_markup=admin_keyboard())

    elif data == "admin_cleardb":
        await query.edit_message_text(
            "⚠️ *اخطار:* با `/cleardb confirm` کل دیتابیس پاک می‌شود.",
            parse_mode=ParseMode.MARKDOWN
        )

    elif data == "admin_authall":
        await db.auth_all(True)
        await query.edit_message_text("✅ همه کاربران مجاز شدند.", reply_markup=admin_keyboard())

    elif data == "admin_deauthall":
        await db.auth_all(False)
        await query.edit_message_text("❌ همه کاربران غیرمجاز شدند.", reply_markup=admin_keyboard())

# --------------------------------------------------------------------------------
# دستورات متنی مدیریت
# --------------------------------------------------------------------------------
async def userinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS:
        return
    if not context.args:
        await update.message.reply_text("استفاده: /userinfo <user_id>")
        return
    try:
        uid = int(context.args[0])
    except:
        await update.message.reply_text("user_id نامعتبر.")
        return
    user = await db.get_user(uid)
    if not user:
        await update.message.reply_text("❌ کاربر یافت نشد.")
        return
    text = (
        f"👤 *اطلاعات کاربر*\n\n"
        f"🆔 آیدی: `{user['user_id']}`\n"
        f"📛 نام: {user['first_name']}\n"
        f"🏷 یوزرنیم: @{user['username']}\n"
        f"🔢 تعداد اسکن: {user['scan_count']}\n"
        f"📅 آخرین اسکن: {user['last_scan'] or 'ندارد'}\n"
        f"✅ مجاز: {'بله' if user['is_authorized'] else 'خیر'}\n"
        f"🚫 مسدود: {'بله' if user['is_banned'] else 'خیر'}"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)

async def broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS:
        return
    if not context.args:
        await update.message.reply_text("استفاده: /broadcast <پیام>")
        return
    msg = ' '.join(context.args)
    users = await db.get_all_users()
    ok = 0
    for u in users:
        try:
            await context.bot.send_message(chat_id=u['user_id'], text=msg)
            ok += 1
        except:
            pass
    await update.message.reply_text(f"✅ پیام به {ok}/{len(users)} کاربر ارسال شد.")

async def adduser(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS: return
    if not context.args: await update.message.reply_text("/adduser <id>"); return
    try: uid = int(context.args[0])
    except: await update.message.reply_text("id نامعتبر"); return
    await db.set_authorized(uid, True)
    await update.message.reply_text(f"✅ کاربر {uid} مجاز شد.")

async def removeuser(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS: return
    if not context.args: await update.message.reply_text("/removeuser <id>"); return
    try: uid = int(context.args[0])
    except: await update.message.reply_text("id نامعتبر"); return
    await db.set_authorized(uid, False)
    await update.message.reply_text(f"❌ کاربر {uid} غیرمجاز شد.")

async def ban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS: return
    if not context.args: await update.message.reply_text("/ban <id>"); return
    try: uid = int(context.args[0])
    except: await update.message.reply_text("id نامعتبر"); return
    await db.set_banned(uid, True)
    await update.message.reply_text(f"🚫 کاربر {uid} مسدود شد.")

async def unban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS: return
    if not context.args: await update.message.reply_text("/unban <id>"); return
    try: uid = int(context.args[0])
    except: await update.message.reply_text("id نامعتبر"); return
    await db.set_banned(uid, False)
    await update.message.reply_text(f"✅ کاربر {uid} رفع مسدودیت شد.")

async def setrate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS: return
    if not context.args: await update.message.reply_text("/setrate <ثانیه>"); return
    try: sec = int(context.args[0])
    except: await update.message.reply_text("عدد وارد کنید"); return
    global rate_limit_seconds
    rate_limit_seconds = max(0, sec)
    await update.message.reply_text(f"⏱ محدودیت نرخ روی {rate_limit_seconds} ثانیه تنظیم شد.")

async def resetuser(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS: return
    if not context.args: await update.message.reply_text("/resetuser <id>"); return
    try: uid = int(context.args[0])
    except: await update.message.reply_text("id نامعتبر"); return
    await db.reset_user_scans(uid)
    await update.message.reply_text(f"🔄 شمارنده کاربر {uid} صفر شد.")

async def cleardb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in ADMIN_IDS: return
    if not context.args or context.args[0].lower() != "confirm":
        await update.message.reply_text("⚠️ برای پاکسازی کامل، `/cleardb confirm` را بفرستید.")
        return
    await db.clear_all()
    last_scan_times.clear()
    await update.message.reply_text("🗑 تمام داده‌ها حذف شدند.")

# --------------------------------------------------------------------------------
# اجرای اصلی
# --------------------------------------------------------------------------------
def main():

    app = Application.builder().token(BOT_TOKEN).build()

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
    app.add_handler(CommandHandler("admin", admin_command))
    app.add_handler(CallbackQueryHandler(admin_callback, pattern="^admin_"))
    app.add_handler(CommandHandler("userinfo", userinfo))
    app.add_handler(CommandHandler("broadcast", broadcast))
    app.add_handler(CommandHandler("adduser", adduser))
    app.add_handler(CommandHandler("removeuser", removeuser))
    app.add_handler(CommandHandler("ban", ban))
    app.add_handler(CommandHandler("unban", unban))
    app.add_handler(CommandHandler("setrate", setrate))
    app.add_handler(CommandHandler("resetuser", resetuser))
    app.add_handler(CommandHandler("cleardb", cleardb))

    print("✅ ربات آماده سرویس‌دهی است...")
    app.run_polling()

if __name__ == "__main__":
    main()