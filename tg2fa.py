#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import time
import sqlite3
import logging
from functools import wraps
from typing import Optional

from cryptography.fernet import Fernet
import pyotp
from flask import Flask, request

from telegram import Update, Bot, InputFile
from telegram.ext import Dispatcher, CommandHandler, ContextTypes

try:
    import qrcode
    from io import BytesIO
    QR_LIB_AVAILABLE = True
except Exception:
    QR_LIB_AVAILABLE = False

# ---------------- Config ----------------
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
FERNET_KEY = os.environ.get("FERNET_KEY")
DB_PATH = "secrets_multi_whitelist.db"
CODE_INTERVAL = 30
RATE_LIMIT_SECONDS = 20
OWNER_ID = 1632859637

if not TELEGRAM_TOKEN or not FERNET_KEY:
    raise RuntimeError("Set TELEGRAM_TOKEN and FERNET_KEY environment variables.")

fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------- Database ----------------
def init_db(path=DB_PATH):
    conn = sqlite3.connect(path, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        label TEXT NOT NULL,
        encrypted_secret BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        UNIQUE(user_id, label)
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        username TEXT,
        added_at INTEGER NOT NULL
    )""")
    conn.commit()
    return conn

db = init_db()

def ensure_owner_whitelisted():
    cur = db.cursor()
    cur.execute("SELECT 1 FROM whitelist WHERE user_id = ?", (OWNER_ID,))
    if not cur.fetchone():
        cur.execute("INSERT INTO whitelist (user_id, username, added_at) VALUES (?, ?, ?)",
                    (OWNER_ID, None, int(time.time())))
        db.commit()
ensure_owner_whitelisted()

# ---------------- Helpers ----------------
def add_secret(user_id: int, label: str, secret: str) -> bool:
    enc = fernet.encrypt(secret.encode())
    cur = db.cursor()
    try:
        cur.execute(
            "INSERT INTO secrets (user_id, label, encrypted_secret, created_at) VALUES (?, ?, ?, ?)",
            (user_id, label, enc, int(time.time()))
        )
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def update_secret(user_id: int, label: str, secret: str) -> None:
    enc = fernet.encrypt(secret.encode())
    cur = db.cursor()
    cur.execute(
        "UPDATE secrets SET encrypted_secret = ?, created_at = ? WHERE user_id = ? AND label = ?",
        (enc, int(time.time()), user_id, label)
    )
    db.commit()

def get_encrypted_secret(user_id: int, label: str) -> Optional[bytes]:
    cur = db.cursor()
    cur.execute("SELECT encrypted_secret FROM secrets WHERE user_id = ? AND label = ?", (user_id, label))
    row = cur.fetchone()
    return row[0] if row else None

def delete_secret(user_id: int, label: str) -> bool:
    cur = db.cursor()
    cur.execute("DELETE FROM secrets WHERE user_id = ? AND label = ?", (user_id, label))
    db.commit()
    return cur.rowcount > 0

def list_labels(user_id: int):
    cur = db.cursor()
    cur.execute("SELECT label, created_at FROM secrets WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    return cur.fetchall()

def decrypt_secret(enc: bytes) -> Optional[str]:
    try:
        return fernet.decrypt(enc).decode()
    except Exception:
        logger.exception("Decrypt failed")
        return None

def is_whitelisted(user_id: int) -> bool:
    cur = db.cursor()
    cur.execute("SELECT 1 FROM whitelist WHERE user_id = ?", (user_id,))
    return cur.fetchone() is not None

def add_whitelist(user_id: int, username: Optional[str] = None) -> bool:
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO whitelist (user_id, username, added_at) VALUES (?, ?, ?)",
                    (user_id, username, int(time.time())))
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def remove_whitelist(user_id: int) -> bool:
    cur = db.cursor()
    cur.execute("DELETE FROM whitelist WHERE user_id = ?", (user_id,))
    db.commit()
    return cur.rowcount > 0

def get_whitelist():
    cur = db.cursor()
    cur.execute("SELECT user_id, username, added_at FROM whitelist ORDER BY added_at DESC")
    return cur.fetchall()

# ---------------- Authorization decorators ----------------
def owner_only(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        uid = update.effective_user.id if update.effective_user else None
        if uid != OWNER_ID:
            await update.message.reply_text("এই কমান্ডটি কেবল Bot Owner ব্যবহার করতে পারবেন।")
            return
        return await func(update, context, *args, **kwargs)
    return wrapper

def authorized(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user = update.effective_user
        if not user:
            return
        uid = user.id
        if uid == OWNER_ID or is_whitelisted(uid):
            return await func(update, context, *args, **kwargs)
        else:
            await update.message.reply_text("Unauthorized user ❌\nআপনি এই বট ব্যবহার করার অনুমতি পাননি।")
            return
    return wrapper

# ---------------- Rate limiting ----------------
_last_request = {}
def rate_limited(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user = update.effective_user
        if not user:
            return
        label = None
        if context.args:
            label = context.args[0].lower()
        key = (user.id, label)
        now = time.time()
        last = _last_request.get(key, 0)
        if now - last < RATE_LIMIT_SECONDS:
            await update.message.reply_text(f"অনুগ্রহ করে অপেক্ষা করুন — {RATE_LIMIT_SECONDS} সেকেন্ড পরে চেষ্টা করুন।")
            return
        _last_request[key] = now
        return await func(update, context, *args, **kwargs)
    return wrapper

# ---------------- Bot Commands ----------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = (
        "2FA Multi-Bot (Webhook + Owner Whitelist)\n\n"
        "Commands (if authorized):\n"
        "/add <label> <BASE32_SECRET>\n"
        "/get <label>\n"
        "/list\n"
        "/delete <label>\n"
        "/qr <label>\n\n"
        "Owner commands:\n"
        "/allow <chat_id|@username>\n"
        "/deny <chat_id|@username>\n"
        "/users\n"
    )
    await update.message.reply_text(txt)

@authorized
async def add_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if len(args) < 2:
        await update.message.reply_text("ব্যবহার: /add <label> <BASE32_SECRET>")
        return
    label = args[0].strip().lower()
    secret = args[1].strip().replace(" ", "")
    try:
        totp = pyotp.TOTP(secret)
        _ = totp.now()
    except Exception:
        await update.message.reply_text("দেওয়া secretটি সম্ভবত বৈধ BASE32 secret নয়।")
        return
    user_id = update.effective_user.id
    added = add_secret(user_id, label, secret)
    if not added:
        update_secret(user_id, label, secret)
        await update.message.reply_text(f"Label `{label}` আগে থেকেই ছিল — secret আপডেট করা হয়েছে।")
    else:
        await update.message.reply_text(f"Label `{label}` সফলভাবে যোগ হয়েছে।")

@authorized
@rate_limited
async def get_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args:
        await update.message.reply_text("ব্যবহার: /get <label>")
        return
    label = args[0].strip().lower()
    user_id = update.effective_user.id
    enc = get_encrypted_secret(user_id, label)
    if not enc:
        await update.message.reply_text("Label খুঁজে পাওয়া যায়নি। /list চেক করুন।")
        return
    secret = decrypt_secret(enc)
    totp = pyotp.TOTP(secret)
    code = totp.now()
    remaining = CODE_INTERVAL - (int(time.time()) % CODE_INTERVAL)
    await update.message.reply_text(f"`{label}` কোড: `{code}`\nভ্যালিড: {remaining} সেকেন্ড")

@authorized
async def list_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    rows = list_labels(user_id)
    if not rows:
        await update.message.reply_text("আপনি এখনও কোনো account যোগ করেন নি। /add ব্যবহার করুন।")
        return
    text_lines = ["আপনার accounts:"]
    for label, created_at in rows:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(created_at))
        text_lines.append(f"- {label} (added: {ts})")
    await update.message.reply_text("\n".join(text_lines))

@authorized
async def delete_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args:
        await update.message.reply_text("ব্যবহার: /delete <label>")
        return
    label = args[0].strip().lower()
    user_id = update.effective_user.id
    ok = delete_secret(user_id, label)
    if ok:
        await update.message.reply_text(f"`{label}` মুছে ফেলা হয়েছে।")
    else:
        await update.message.reply_text("Label পাওয়া যায়নি। /list দিয়ে চেক করুন।")

@authorized
async def qr_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args:
        await update.message.reply_text("ব্যবহার: /qr <label>")
        return
    label = args[0].strip().lower()
    user = update.effective_user
    enc = get_encrypted_secret(user.id, label)
    if not enc:
        await update.message.reply_text("Label পাওয়া যায়নি। /list চেক করুন।")
        return
    secret = decrypt_secret(enc)
    issuer = "2FA-Multi-Bot"
    username = user.username or str(user.id)
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=f"{username}:{label}", issuer_name=issuer)
    await update.message.reply_text(f"otpauth URI:\n{uri}")

# ---------------- Owner commands ----------------
async def resolve_user_arg(arg: str, context: ContextTypes.DEFAULT_TYPE):
    arg = arg.strip()
    if arg.startswith("@"):
        try:
            chat = await context.bot.get_chat(arg)
            return (chat.id, chat.username if hasattr(chat, "username") else None)
        except Exception:
            return None
    else:
        try:
            uid = int(arg)
            return (uid, None)
        except Exception:
            return None

@owner_only
async def allow_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args:
        await update.message.reply_text("ব্যবহার: /allow <chat_id|@username>")
        return
    resolved = await resolve_user_arg(args[0], context)
    if not resolved:
        await update.message.reply_text("User resolve করা যায়নি।")
        return
    uid, uname = resolved
    added = add_whitelist(uid, uname)
    if added:
        await update.message.reply_text(f"User `{uid}` অনুমোদিত।")
    else:
        await update.message.reply_text("User আগেই অনুমোদিত।")

@owner_only
async def deny_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args:
        await update.message.reply_text("ব্যবহার: /deny <chat_id|@username>")
        return
    resolved = await resolve_user_arg(args[0], context)
    if not resolved:
        await update.message.reply_text("User resolve করা যায়নি।")
        return
    uid, _ = resolved
    if uid == OWNER_ID:
        await update.message.reply_text("Owner অপসারণ করা যাবে না।")
        return
    removed = remove_whitelist(uid)
    if removed:
        await update.message.reply_text(f"User `{uid}`-এর অনুমোদন বাতিল করা হয়েছে।")
    else:
        await update.message.reply_text("User টি whitelist এ নেই।")

@owner_only
async def users_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    rows = get_whitelist()
    if not rows:
        await update.message.reply_text("Whitelist খালি।")
        return
    lines = ["Whitelist users:"]
    for uid, uname, added_at in rows:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(added_at))
        lines.append(f"- {uid} ({uname}) added: {ts}")
    await update.message.reply_text("\n".join(lines))

# ---------------- Flask App / Webhook ----------------
app = Flask(__name__)
bot = Bot(token=TELEGRAM_TOKEN)
dp = Dispatcher(bot, None, workers=0)

dp.add_handler(CommandHandler("start", start))
dp.add_handler(CommandHandler("add", add_cmd))
dp.add_handler(CommandHandler("get", get_cmd))
dp.add_handler(CommandHandler("list", list_cmd))
dp.add_handler(CommandHandler("delete", delete_cmd))
dp.add_handler(CommandHandler("qr", qr_cmd))
dp.add_handler(CommandHandler("allow", allow_cmd))
dp.add_handler(CommandHandler("deny", deny_cmd))
dp.add_handler(CommandHandler("users", users_cmd))

@app.route(f"/webhook/{TELEGRAM_TOKEN}", methods=["POST"])
def webhook():
    update = Update.de_json(request.get_json(force=True), bot)
    dp.process_update(update)
    return "ok"

@app.route("/")
def index():
    return "2FA Telegram Bot is running ✅"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
