from fastapi import FastAPI, HTTPException, Query, Request, Response, Depends
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import secrets
import json
import os
import hashlib
import hmac
import time
from collections import defaultdict
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters
from contextlib import asynccontextmanager
from asyncio import Lock
import plistlib
import uuid
import re

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "PUT_YOUR_TOKEN_HERE")
ADMIN_CHAT_IDS = os.getenv("ADMIN_CHAT_IDS", "").split(",")
DB_FILE = "keys.json"
db_lock = Lock()

# --- Rate Limiting ---
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_WINDOW = 30
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 300

rate_limit_store = defaultdict(list)
failed_attempts_store = defaultdict(list)
locked_out_ips = {}


def check_rate_limit(client_ip: str) -> bool:
    now = time.time()
    if client_ip in locked_out_ips:
        if now < locked_out_ips[client_ip]:
            return False
        del locked_out_ips[client_ip]

    timestamps = rate_limit_store[client_ip]
    rate_limit_store[client_ip] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(rate_limit_store[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
        return False
    rate_limit_store[client_ip].append(now)
    return True


def record_failed_attempt(client_ip: str):
    now = time.time()
    failed_attempts_store[client_ip] = [
        t for t in failed_attempts_store[client_ip] if now - t < RATE_LIMIT_WINDOW
    ]
    failed_attempts_store[client_ip].append(now)
    if len(failed_attempts_store[client_ip]) >= MAX_FAILED_ATTEMPTS:
        locked_out_ips[client_ip] = now + LOCKOUT_DURATION
        failed_attempts_store[client_ip] = []


# --- Input Validation ---
API_KEY_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,200}$')
DEVICE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9\-]{1,128}$')


def validate_api_key_format(key: str) -> bool:
    return bool(API_KEY_PATTERN.match(key))


def validate_device_id_format(device_id: str) -> bool:
    return bool(DEVICE_ID_PATTERN.match(device_id))


# --- Database ---
def load_keys():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                if "packages" not in data:
                    data["packages"] = {}
                if "global_banned_devices" not in data:
                    data["global_banned_devices"] = []
                for key, val in data.items():
                    if key not in ["packages", "global_banned_devices"] and isinstance(val, dict):
                        val.setdefault("banned_devices", [])
                return data
            except Exception:
                return {"packages": {}, "global_banned_devices": []}

    default = {
        "packages": {},
        "global_banned_devices": [],
        "skam_admin_key": {
            "role": "admin",
            "duration": None,
            "delta_seconds": None,
            "activation_time": None,
            "expiry": "2099-12-31 23:59:59",
            "bound_devices": [],
            "max_users": 999,
            "package": None,
            "banned_devices": []
        }
    }
    save_keys(default)
    return default


def save_keys(data):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


async def save_keys_safe(data):
    async with db_lock:
        save_keys(data)


API_KEYS = load_keys()


def parse_duration(duration_str: str):
    if not duration_str:
        return None
    unit = duration_str[-1].lower()
    try:
        value = int(duration_str[:-1])
        if value <= 0:
            return None
        if unit == 'm': return timedelta(minutes=value)
        if unit == 'h': return timedelta(hours=value)
        if unit == 'd': return timedelta(days=value)
        if unit == 'w': return timedelta(weeks=value)
    except (ValueError, IndexError):
        pass
    return None


# --- Default Security Config ---
DEFAULT_SECURITY_CONFIG = {
    "anti_inject": True
}


def get_package_security(pkg_name: str) -> dict:
    pkg_data = API_KEYS.get("packages", {}).get(pkg_name, {})
    sec = pkg_data.get("security", dict(DEFAULT_SECURITY_CONFIG))
    if "anti_inject" not in sec:
        sec["anti_inject"] = True
    return sec


# --- Telegram Bot Handlers ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    keyboard = [
        [InlineKeyboardButton("Create New Package", callback_data="create_package")],
        [InlineKeyboardButton("Create New Key", callback_data="create_key")],
        [InlineKeyboardButton("Delete Package", callback_data="delete_package")],
        [InlineKeyboardButton("Show Status + Manage Devices", callback_data="status")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "**Welcome to the API Panel**\nChoose an option:\n\nSecurity commands:\n/enableinject <package>\n/disabledinject <package>",
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )


async def show_packages_for_manage(query, context, edit=True):
    if not API_KEYS.get("packages"):
        text = "No packages exist yet."
        if edit:
            await query.edit_message_text(text)
        return
    keyboard = []
    for pkg_name in sorted(API_KEYS["packages"].keys()):
        keyboard.append([InlineKeyboardButton(pkg_name, callback_data=f"status_pkg_{pkg_name}")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    text = "**Select a package to view its keys:**"
    if edit:
        await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')
    else:
        await query.message.reply_text(text, reply_markup=reply_markup, parse_mode='Markdown')


async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = str(query.from_user.id)
    if user_id not in ADMIN_CHAT_IDS:
        await query.edit_message_text("You are not authorized.")
        return

    data = query.data

    if data == "create_package":
        await query.edit_message_text("Enter the name of the new package:")
        context.user_data["state"] = "awaiting_package_name"

    elif data == "create_key":
        if not API_KEYS.get("packages"):
            await query.edit_message_text("No packages exist yet. Create one first.")
            return
        keyboard = []
        for pkg_name in API_KEYS["packages"]:
            keyboard.append([InlineKeyboardButton(pkg_name, callback_data=f"select_pkg_{pkg_name}")])
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("Select package:", reply_markup=reply_markup)

    elif data.startswith("select_pkg_"):
        pkg_name = data.replace("select_pkg_", "")
        context.user_data["selected_package"] = pkg_name
        await query.edit_message_text(f"Selected package: **{pkg_name}**\nEnter duration (e.g. 30d, 1h, 7d, 1w):")
        context.user_data["state"] = "awaiting_duration"

    elif data == "delete_package":
        if not API_KEYS.get("packages"):
            await query.edit_message_text("No packages to delete.")
            return
        keyboard = []
        for pkg_name in API_KEYS["packages"]:
            keyboard.append([InlineKeyboardButton(pkg_name, callback_data=f"del_pkg_{pkg_name}")])
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("Select package to delete:", reply_markup=reply_markup)

    elif data.startswith("del_pkg_"):
        pkg_name = data.replace("del_pkg_", "")
        keys_to_delete = [
            k for k, d in API_KEYS.items()
            if k not in ["packages", "global_banned_devices"]
            and isinstance(d, dict) and d.get("package") == pkg_name
        ]
        for k in keys_to_delete:
            del API_KEYS[k]
        if pkg_name in API_KEYS.get("packages", {}):
            del API_KEYS["packages"][pkg_name]
        await save_keys_safe(API_KEYS)
        await query.edit_message_text(f"Package **{pkg_name}** and {len(keys_to_delete)} key(s) deleted.")

    elif data == "status":
        await show_packages_for_manage(query, context, edit=True)

    elif data.startswith("status_pkg_"):
        pkg_name = data.replace("status_pkg_", "")
        context.user_data["selected_package_status"] = pkg_name

        matching_keys = []
        for k, d in API_KEYS.items():
            if k in ["packages", "global_banned_devices"]:
                continue
            if not isinstance(d, dict):
                continue
            if d.get("package") == pkg_name:
                matching_keys.append(k)

        if not matching_keys:
            await query.edit_message_text(
                f"**{pkg_name}**\nNo keys in this package.",
                parse_mode='Markdown'
            )
            return

        keyboard = []
        for key in sorted(matching_keys):
            keyboard.append([InlineKeyboardButton(key, callback_data=f"manage_key_{key}")])
        keyboard.append([InlineKeyboardButton("Back", callback_data="status")])
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(
            f"**Package: {pkg_name}** ({len(matching_keys)} keys)\nSelect a key to view details:",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )

    elif data.startswith("manage_key_"):
        key = data.replace("manage_key_", "")
        if key not in API_KEYS or not isinstance(API_KEYS[key], dict):
            await query.edit_message_text("Key not found or invalid.")
            return

        key_data = API_KEYS[key]
        now = datetime.now()

        if key_data.get("expiry") is None and key_data.get("activation_time") is None:
            status = "Not activated yet"
        elif key_data.get("expiry"):
            try:
                expiry = datetime.strptime(key_data["expiry"], "%Y-%m-%d %H:%M:%S")
                status = "Expired" if now > expiry else "Active"
            except ValueError:
                status = "Date error"
        else:
            status = "Not activated"

        lines = [
            f"**Key:** `{key}`",
            f"**Status:** {status}",
            f"Devices: {len(key_data.get('bound_devices', []))} / {key_data.get('max_users', 1)}",
            f"Package: {key_data.get('package', '---')}",
            f"Duration: {key_data.get('duration', '---')}",
        ]
        if key_data.get("activation_time"):
            lines.append(f"Activated at: {key_data['activation_time']}")
        if key_data.get("expiry"):
            lines.append(f"Expires at: {key_data['expiry']}")

        bound_devices = key_data.get("bound_devices", [])
        if bound_devices:
            lines.append("---")
            lines.append("Bound devices:")
            global_banned = API_KEYS.get("global_banned_devices", [])
            banned = key_data.get("banned_devices", [])
            for dev_id in bound_devices:
                if dev_id in global_banned:
                    st = "Globally banned"
                elif dev_id in banned:
                    st = "Locally banned"
                else:
                    st = "Active"
                lines.append(f"- `{dev_id}` -> {st}")

        keyboard = [[InlineKeyboardButton("Back", callback_data=f"status_pkg_{key_data.get('package', '---')}")]]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text("\n".join(lines), reply_markup=reply_markup, parse_mode='Markdown')


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    text = update.message.text.strip()
    state = context.user_data.get("state")

    if state == "awaiting_package_name":
        pkg_name = text
        if not re.match(r'^[a-zA-Z0-9_\-. ]{1,50}$', pkg_name):
            await update.message.reply_text("Invalid package name. Use only letters, numbers, dashes, underscores, dots, and spaces (max 50 chars).")
            return
        if pkg_name in API_KEYS.get("packages", {}):
            await update.message.reply_text(f"Package **{pkg_name}** already exists.")
        else:
            API_KEYS["packages"][pkg_name] = {
                "owner": str(update.effective_chat.id),
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            await save_keys_safe(API_KEYS)
            await update.message.reply_text(f"Package **{pkg_name}** created successfully.")
        context.user_data.pop("state", None)

    elif state == "awaiting_duration":
        delta = parse_duration(text)
        if not delta:
            await update.message.reply_text("Invalid duration! Examples: 30d 1h 15m 7d 1w")
            return
        context.user_data["duration"] = text
        context.user_data["delta_seconds"] = int(delta.total_seconds())
        await update.message.reply_text("Enter max number of devices allowed (e.g. 1, 3, 999):")
        context.user_data["state"] = "awaiting_max_devices"

    elif state == "awaiting_max_devices":
        try:
            max_users = int(text)
            if max_users < 1:
                raise ValueError
        except (ValueError, TypeError):
            await update.message.reply_text("Invalid number (must be >= 1)")
            return

        pkg_name = context.user_data.get("selected_package")
        duration_input = context.user_data.get("duration")

        random_part = secrets.token_hex(10)
        new_key = f"{pkg_name}-{duration_input}-{random_part}"

        API_KEYS[new_key] = {
            "role": "user",
            "duration": duration_input,
            "delta_seconds": context.user_data["delta_seconds"],
            "activation_time": None,
            "expiry": None,
            "bound_devices": [],
            "max_users": max_users,
            "package": pkg_name,
            "banned_devices": []
        }
        await save_keys_safe(API_KEYS)

        user_type = "Unlimited" if max_users >= 999 else f"{max_users} device(s)"
        await update.message.reply_text(
            f"**Key created successfully!**\n\n"
            f"`{new_key}`\n"
            f"Duration: **{duration_input}**\n"
            f"Max devices: {user_type}\n"
            f"Package: **{pkg_name}**",
            parse_mode='Markdown'
        )
        context.user_data.clear()


async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    await update.message.reply_text("Use the 'Show Status' button from the main menu.")


async def stop_key_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    if not context.args:
        await update.message.reply_text("Usage: `/stop <key>`")
        return
    key = context.args[0].strip()
    if key == "skam_admin_key":
        await update.message.reply_text("Cannot delete admin key.")
        return
    if key in API_KEYS and key not in ["packages", "global_banned_devices"]:
        del API_KEYS[key]
        await save_keys_safe(API_KEYS)
        await update.message.reply_text(f"Key `{key}` deleted.")
    else:
        await update.message.reply_text("Key not found.")


async def ban_device_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    if not context.args:
        await update.message.reply_text("Usage: `/ban <DEVICE_ID>`")
        return
    dev_id = context.args[0].strip()
    if not validate_device_id_format(dev_id):
        await update.message.reply_text("Invalid device ID format.")
        return
    global_banned = API_KEYS.setdefault("global_banned_devices", [])
    if dev_id not in global_banned:
        global_banned.append(dev_id)
        await save_keys_safe(API_KEYS)
    for key_data in API_KEYS.values():
        if isinstance(key_data, dict) and "bound_devices" in key_data:
            if dev_id in key_data.get("bound_devices", []):
                banned = key_data.setdefault("banned_devices", [])
                if dev_id not in banned:
                    banned.append(dev_id)
    await update.message.reply_text(f"Device ID banned: {dev_id}")


async def unban_device_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    if not context.args:
        await update.message.reply_text("Usage: `/unban <DEVICE_ID>`")
        return
    dev_id = context.args[0].strip()
    global_banned = API_KEYS.get("global_banned_devices", [])
    was_banned = dev_id in global_banned
    if was_banned:
        global_banned.remove(dev_id)
        await save_keys_safe(API_KEYS)
    for key_data in API_KEYS.values():
        if isinstance(key_data, dict) and "banned_devices" in key_data:
            if dev_id in key_data["banned_devices"]:
                key_data["banned_devices"].remove(dev_id)
    if was_banned:
        await update.message.reply_text(f"Device ID unbanned: {dev_id}")
    else:
        await update.message.reply_text(f"{dev_id} was not banned")


async def reset_key_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    if not context.args:
        await update.message.reply_text("Usage: `/reset <key>`")
        return
    key = context.args[0].strip()
    if key not in API_KEYS or key in ["packages", "global_banned_devices"]:
        await update.message.reply_text("Key not found or invalid.")
        return
    if not isinstance(API_KEYS[key], dict):
        await update.message.reply_text("Invalid key data.")
        return

    key_data = API_KEYS[key]
    old_devices = len(key_data.get("bound_devices", []))
    key_data["bound_devices"] = []
    await save_keys_safe(API_KEYS)
    await update.message.reply_text(
        f"Key `{key}` reset successfully!\n"
        f"{old_devices} device(s) removed.\n"
        f"Activation time and expiry remain unchanged.\n"
        f"You can activate again now on this device."
    )


async def enableinject_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    if not context.args:
        await update.message.reply_text("Usage: `/enableinject <package>`", parse_mode='Markdown')
        return

    pkg_name = context.args[0].strip()
    if pkg_name not in API_KEYS.get("packages", {}):
        await update.message.reply_text(f"Package `{pkg_name}` not found.")
        return

    pkg_data = API_KEYS["packages"][pkg_name]
    pkg_data["security"] = {"anti_inject": True}
    await save_keys_safe(API_KEYS)
    await update.message.reply_text(
        f"Anti-Inject protection **ENABLED** for **{pkg_name}**\n"
        f"(dylib, deb, framework, debugger, jailbreak, integrity)",
        parse_mode='Markdown'
    )


async def disabledinject_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if str(update.effective_chat.id) not in ADMIN_CHAT_IDS:
        return
    if not context.args:
        await update.message.reply_text("Usage: `/disabledinject <package>`", parse_mode='Markdown')
        return

    pkg_name = context.args[0].strip()
    if pkg_name not in API_KEYS.get("packages", {}):
        await update.message.reply_text(f"Package `{pkg_name}` not found.")
        return

    pkg_data = API_KEYS["packages"][pkg_name]
    pkg_data["security"] = {"anti_inject": False}
    await save_keys_safe(API_KEYS)
    await update.message.reply_text(
        f"Anti-Inject protection **DISABLED** for **{pkg_name}**\n"
        f"(dylib, deb, framework, debugger, jailbreak, integrity)",
        parse_mode='Markdown'
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    application = (
        ApplicationBuilder()
        .token(TELEGRAM_TOKEN)
        .get_updates_read_timeout(30)
        .get_updates_write_timeout(30)
        .get_updates_connect_timeout(30)
        .build()
    )

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("status", status_cmd))
    application.add_handler(CommandHandler("stop", stop_key_cmd))
    application.add_handler(CommandHandler("ban", ban_device_cmd))
    application.add_handler(CommandHandler("unban", unban_device_cmd))
    application.add_handler(CommandHandler("reset", reset_key_cmd))
    application.add_handler(CommandHandler("enableinject", enableinject_cmd))
    application.add_handler(CommandHandler("disabledinject", disabledinject_cmd))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    await application.initialize()
    await application.start()
    await application.updater.start_polling(
        allowed_updates=Update.ALL_TYPES,
        drop_pending_updates=True,
    )
    print("Telegram bot polling started successfully")

    yield

    await application.updater.stop()
    await application.stop()
    await application.shutdown()


app = FastAPI(title="API Server", lifespan=lifespan)


# --- Security Middleware ---
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"

    if not check_rate_limit(client_ip):
        return Response(
            content=json.dumps({"detail": "Too many requests. Try again later."}),
            status_code=429,
            media_type="application/json"
        )

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"

    return response


@app.get("/validate")
async def validate(request: Request, api_key: str = Query(...), device_id: str = Query(...)):
    client_ip = request.client.host if request.client else "unknown"

    if not validate_api_key_format(api_key):
        record_failed_attempt(client_ip)
        raise HTTPException(403, "Invalid key format")

    if not validate_device_id_format(device_id):
        record_failed_attempt(client_ip)
        raise HTTPException(403, "Invalid device ID format")

    if api_key not in API_KEYS or api_key in ["packages", "global_banned_devices"]:
        record_failed_attempt(client_ip)
        raise HTTPException(403, "Invalid key")

    key_data = API_KEYS[api_key]
    now = datetime.now()

    if key_data.get("activation_time") is None:
        key_data["activation_time"] = now.strftime("%Y-%m-%d %H:%M:%S")
        delta_sec = key_data.get("delta_seconds")
        if delta_sec is not None:
            expiry_dt = now + timedelta(seconds=delta_sec)
            key_data["expiry"] = expiry_dt.strftime("%Y-%m-%d %H:%M:%S")
        await save_keys_safe(API_KEYS)

    expiry_str = key_data.get("expiry")
    if not expiry_str:
        raise HTTPException(500, "Expiry date missing")

    expiry_date = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
    if now > expiry_date:
        raise HTTPException(403, "Key expired")

    bound_devices = key_data.setdefault("bound_devices", [])
    banned_devices = key_data.get("banned_devices", [])
    global_banned = API_KEYS.get("global_banned_devices", [])
    max_users = key_data.get("max_users", 1)

    if device_id in global_banned or device_id in banned_devices:
        raise HTTPException(403, "This device is banned")

    if device_id not in bound_devices:
        if len(bound_devices) >= max_users:
            raise HTTPException(403, f"Max devices reached ({max_users})")
        bound_devices.append(device_id)
        await save_keys_safe(API_KEYS)

    remaining = expiry_date - now
    days = remaining.days
    hours, rem = divmod(remaining.seconds, 3600)
    minutes, _seconds = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    remaining_str = " ".join(parts) or "less than 1 minute"

    pkg_name = key_data.get("package", "Standard")

    nice_message = (
        f"Welcome to {pkg_name}!\n\n"
        f"Package: {pkg_name}\n"
        f"Expires at: {expiry_str}\n"
        f"Time left: {remaining_str}\n"
        f"Devices: {len(bound_devices)} / {max_users}"
    )

    return {
        "status": "valid",
        "role": key_data["role"],
        "activated_at": key_data.get("activation_time"),
        "expires_at": expiry_str,
        "remaining": remaining_str,
        "devices": f"{len(bound_devices)} / {max_users}",
        "package": pkg_name,
        "message": nice_message
    }


@app.get("/get-udid.mobileconfig")
async def generate_udid_profile(api_key: str = Query(...)):
    if not validate_api_key_format(api_key):
        raise HTTPException(403, "Invalid key format")
    if api_key not in API_KEYS or api_key in ["packages", "global_banned_devices"]:
        raise HTTPException(403, "Invalid or unauthorized key")

    key_data = API_KEYS[api_key]
    pkg_name = key_data.get("package", "App")

    profile_uuid = str(uuid.uuid4()).upper()

    plist_dict = {
        "PayloadContent": {
            "URL": f"https://a4552-5cdb.c.jrnm.app/receive-udid?api_key={api_key}",
            "DeviceAttributes": ["UDID", "SERIAL", "PRODUCT", "VERSION"]
        },
        "PayloadDescription": f"{pkg_name} Device Registration - Used for device activation",
        "PayloadDisplayName": f"{pkg_name} Device Registration",
        "PayloadIdentifier": f"com.app.udid.{profile_uuid}",
        "PayloadOrganization": pkg_name,
        "PayloadType": "Profile Service",
        "PayloadUUID": profile_uuid,
        "PayloadVersion": 1
    }

    plist_bytes = plistlib.dumps(plist_dict, fmt=plistlib.FMT_XML)

    return Response(
        content=plist_bytes,
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": f'attachment; filename="{pkg_name}-udid.mobileconfig"'}
    )


@app.post("/receive-udid")
async def receive_udid(request: Request, api_key: str = Query(...)):
    if not validate_api_key_format(api_key):
        raise HTTPException(403, "Invalid key format")
    if api_key not in API_KEYS:
        raise HTTPException(403, "Invalid key")

    try:
        body_bytes = await request.body()
        if len(body_bytes) > 10 * 1024:
            raise HTTPException(400, "Request body too large")

        xml_match = re.search(b'(<\\?xml.*?</plist>)', body_bytes, re.DOTALL)
        if not xml_match:
            raise HTTPException(400, "No plist XML found in response")

        xml_bytes = xml_match.group(1)
        received_plist = plistlib.loads(xml_bytes)

        udid = received_plist.get("UDID")
        if not udid:
            raise HTTPException(400, "UDID not found in plist")

        if not re.match(r'^[a-zA-Z0-9\-]{1,128}$', udid):
            raise HTTPException(400, "Invalid UDID format")

        key_data = API_KEYS[api_key]
        bound_devices = key_data.setdefault("bound_devices", [])
        if udid not in bound_devices:
            if len(bound_devices) >= key_data.get("max_users", 1):
                raise HTTPException(403, "Max devices reached for this key")
            bound_devices.append(udid)
            await save_keys_safe(API_KEYS)

        return Response(status_code=200, content=b"")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f"Processing error: {str(e)}")


@app.get("/security-config")
async def get_security_config(request: Request, api_key: str = Query(...)):
    client_ip = request.client.host if request.client else "unknown"

    if not validate_api_key_format(api_key):
        record_failed_attempt(client_ip)
        raise HTTPException(403, "Invalid key format")

    if api_key not in API_KEYS or api_key in ["packages", "global_banned_devices"]:
        record_failed_attempt(client_ip)
        raise HTTPException(403, "Invalid key")

    key_data = API_KEYS[api_key]
    pkg_name = key_data.get("package")

    if not pkg_name or pkg_name not in API_KEYS.get("packages", {}):
        return {"security": dict(DEFAULT_SECURITY_CONFIG)}

    sec_config = get_package_security(pkg_name)
    return {"security": sec_config, "package": pkg_name}


@app.get("/health")
async def health_check():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


if __name__ == "__main__":
    import uvicorn
    print("Starting API server on port 8000 ...")
    uvicorn.run("main_server:app", host="0.0.0.0", port=8000, reload=False)
