"""
خادم طلبات الطباعة للمقهى (ServiceZone)
التشغيل:  start.bat   (أو:  python app.py)

للزبائن :  http://IP-الحاسوب:8000        أو رابط Cloudflare
للمحل   :  http://localhost:8000/admin   (من حاسوب المحل فقط)
"""
import os
import re
import io
import csv
import json
import time
import sqlite3
import shutil
import secrets
import hmac
import threading
from datetime import datetime, timedelta
from flask import (Flask, request, jsonify, render_template_string, Response,
                   abort, send_from_directory)

# ---------------- الإعدادات ----------------
SHOP_NAME = "ServiceZone"
PORT = 8000
ACCESS_CODE = "1234"             # غيّره! اتركه فارغا "" لإلغاء كلمة السر
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
MAX_FILE_MB = 50
MAX_FILES_PER_UPLOAD = 20
KEEP_HOURS = 48                  # حذف الطلبات تلقائيا بعد هذه المدة
RATE_LIMIT = 8                   # أقصى عدد طلبات من نفس الجهاز ...
RATE_WINDOW_MIN = 10             # ... خلال هذه المدة (بالدقائق)
ALLOWED = {"jpg", "jpeg", "png", "webp", "heic", "gif",
           "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt"}
PAPER_SIZES = ["A4", "A5", "A3", "10x15 (صورة)", "13x18 (صورة)"]

# أسعار الطباعة: سعر الصفحة الواحدة (كل وجه = صفحة). غيّر الأرقام حسب أسعارك!
CURRENCY = "دج"
PRICES = {
    "A4":            {"أبيض وأسود": 10, "ألوان": 30},
    "A5":            {"أبيض وأسود": 6,  "ألوان": 20},
    "A3":            {"أبيض وأسود": 30, "ألوان": 80},
    "10x15 (صورة)":  {"أبيض وأسود": 30, "ألوان": 40},
    "13x18 (صورة)":  {"أبيض وأسود": 60, "ألوان": 80},
}
# --------------------------------------------

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")   # دفتر الحسابات (لا يُحذف تلقائيا)
LEDGER = os.path.join(DATA_DIR, "ledger.db")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_MB * MAX_FILES_PER_UPLOAD * 1024 * 1024

_hits = {}
_lock = threading.Lock()


# ---------- أدوات ----------
def clean_name(name: str) -> str:
    name = os.path.basename(name).strip()
    out = "".join(c if (c.isalnum() or c in "._- ") else "_" for c in name)
    return out[:100] or "file"


def magic_ok(ext: str, head: bytes) -> bool:
    """فحص بسيط أن محتوى الملف يطابق امتداده."""
    if ext in ("jpg", "jpeg"):
        return head.startswith(b"\xff\xd8\xff")
    if ext == "png":
        return head.startswith(b"\x89PNG")
    if ext == "gif":
        return head.startswith(b"GIF8")
    if ext == "webp":
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    if ext == "heic":
        return head[4:8] == b"ftyp"
    if ext == "pdf":
        return head.startswith(b"%PDF")
    if ext in ("docx", "xlsx", "pptx"):
        return head.startswith(b"PK")
    if ext in ("doc", "xls", "ppt"):
        return head.startswith(b"\xd0\xcf\x11\xe0")
    return True  # txt


def client_ip() -> str:
    return request.headers.get("CF-Connecting-IP") or request.remote_addr or "?"


def rate_limited(ip: str) -> bool:
    now = time.time()
    with _lock:
        recent = [t for t in _hits.get(ip, []) if now - t < RATE_WINDOW_MIN * 60]
        if len(recent) >= RATE_LIMIT:
            _hits[ip] = recent
            return True
        recent.append(now)
        _hits[ip] = recent
    return False


def folder_time(folder: str):
    try:
        return datetime.strptime(folder[:15], "%Y%m%d-%H%M%S").timestamp()
    except ValueError:
        return None


def cleanup_loop():
    while True:
        limit = time.time() - KEEP_HOURS * 3600
        for folder in os.listdir(UPLOAD_DIR):
            path = os.path.join(UPLOAD_DIR, folder)
            t = folder_time(folder)
            if os.path.isdir(path) and t and t < limit:
                shutil.rmtree(path, ignore_errors=True)
        time.sleep(3600)


threading.Thread(target=cleanup_loop, daemon=True).start()


def read_order(folder: str):
    try:
        with open(os.path.join(UPLOAD_DIR, folder, "order.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def write_order(folder: str, data: dict):
    path = os.path.join(UPLOAD_DIR, folder, "order.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)


def valid_folder(folder: str) -> bool:
    return folder in os.listdir(UPLOAD_DIR) and os.path.isdir(os.path.join(UPLOAD_DIR, folder))


def local_only(write: bool = False):
    """صفحات المحل: فقط من حاسوب المحل نفسه، وليس عبر النفق/الإنترنت."""
    via_tunnel = any(h in request.headers for h in
                     ("X-Forwarded-For", "CF-Connecting-IP", "X-Forwarded-Host"))
    host = (request.host or "").lower()
    local_host = host in ("localhost", "127.0.0.1", "[::1]") or host.startswith(
        ("localhost:", "127.0.0.1:", "[::1]:"))
    # الطلب لازم يصل لـ localhost مباشرة: أي نفق (Cloudflare/ngrok/Tailscale) يحمل اسم نطاق آخر
    if via_tunnel or not local_host or request.remote_addr not in ("127.0.0.1", "::1"):
        abort(403)
    if write and request.headers.get("X-Admin") != "1":
        abort(403)


# ---------- الصفحات والأسعار ودفتر الحسابات ----------
IMAGE_EXTS = {"jpg", "jpeg", "png", "webp", "heic", "gif"}


def count_pages(path: str, ext: str):
    """عدد صفحات الملف إن أمكن معرفته، وإلا None (الصور = 1)."""
    if ext in IMAGE_EXTS:
        return 1
    if ext == "pdf":
        try:
            from pypdf import PdfReader          # اختياري: pip install pypdf
            return len(PdfReader(path).pages)
        except Exception:
            pass
        try:
            with open(path, "rb") as f:
                n = len(re.findall(rb"/Type\s*/Page(?![s\w])", f.read()))
            return n or None
        except OSError:
            return None
    return None


def unit_price(size: str, color: str) -> int:
    return int(PRICES.get(size, {}).get(color, 0))


def calc_price(pages, copies, size, color) -> int:
    return max(0, int(pages)) * max(1, int(copies)) * unit_price(size, color)


def order_defaults(o: dict) -> dict:
    o.setdefault("pages", 0)
    o.setdefault("pages_known", False)
    o.setdefault("price", 0)
    o.setdefault("price_manual", False)
    o.setdefault("paid", False)
    o.setdefault("stock_used", 0)
    o.setdefault("method", "cash")
    o.setdefault("paid_day", "")
    return o


_db_lock = threading.Lock()


def ledger_exec(sql, args=()):
    with _db_lock:
        con = sqlite3.connect(LEDGER, timeout=10)
        try:
            con.execute(sql, args)
            con.commit()
        finally:
            con.close()


def ledger_query(sql, args=()):
    con = sqlite3.connect(LEDGER, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute(sql, args).fetchall()]
    finally:
        con.close()


ledger_exec("""CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY, ts TEXT, day TEXT, code TEXT, name TEXT, nfiles INTEGER,
    copies INTEGER, size TEXT, color TEXT, sides TEXT, pages INTEGER, pages_known INTEGER,
    price INTEGER, paid INTEGER, status TEXT)""")


def ledger_upsert(o: dict):
    o = order_defaults(dict(o))
    ledger_exec("""INSERT OR REPLACE INTO orders
        (id, ts, day, code, name, nfiles, copies, size, color, sides, pages, pages_known, price, paid, status, method, paid_day)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
        o["id"], o["time"], o["time"][:10], o["code"], o.get("name", ""), len(o.get("files", [])),
        o["copies"], o["size"], o["color"], o["sides"], int(o["pages"]), int(bool(o["pages_known"])),
        int(o["price"]), int(bool(o["paid"])), o.get("status", "new"), o.get("method", "cash"),
        o.get("paid_day") or None))


def ledger_delete(folder: str):
    ledger_exec("DELETE FROM orders WHERE id = ?", (folder,))


# ---------- المصاريف والمخزون ----------
EXP_CATS = ["مخزون", "كهرباء", "إنترنت", "إيجار", "صيانة", "رواتب", "أخرى"]

ledger_exec("""CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, day TEXT, category TEXT, amount INTEGER, note TEXT)""")
ledger_exec("""CREATE TABLE IF NOT EXISTS stock_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, unit TEXT, qty INTEGER,
    low_at INTEGER, size TEXT)""")
ledger_exec("""CREATE TABLE IF NOT EXISTS stock_moves (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, item_id INTEGER, delta INTEGER, reason TEXT)""")

if not ledger_query("SELECT id FROM stock_items LIMIT 1"):
    for _size in PAPER_SIZES:                       # ورق كل حجم يُخصم تلقائيا من الطلبات
        ledger_exec("INSERT OR IGNORE INTO stock_items (name, unit, qty, low_at, size) VALUES (?,?,?,?,?)",
                    ("ورق " + _size, "ورقة", 0, 200 if _size == "A4" else 50, _size))
    for _ink in ("حبر أسود", "حبر ألوان"):          # الحبر يُسجَّل يدويا
        ledger_exec("INSERT OR IGNORE INTO stock_items (name, unit, qty, low_at, size) VALUES (?,?,?,?,?)",
                    (_ink, "علبة", 0, 1, ""))


# ---------- الصندوق وسحوبات المالك ----------
DRAW_KINDS = ["مصروف شخصي", "للعائلة", "ادخار / تحويل لحسابي", "سلفة", "أخرى"]

ledger_exec("""CREATE TABLE IF NOT EXISTS drawings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, day TEXT, kind TEXT, amount INTEGER, note TEXT)""")
ledger_exec("""CREATE TABLE IF NOT EXISTS cash_closes (
    day TEXT PRIMARY KEY, ts TEXT, opening INTEGER, cash_sales INTEGER, exp_till INTEGER, drawings INTEGER,
    expected INTEGER, counted INTEGER, diff INTEGER, note TEXT)""")


def ensure_col(table: str, col: str, ddl: str):
    """يضيف عمودا جديدا لقاعدة قديمة دون فقدان بياناتها."""
    cols = [r["name"] for r in ledger_query(f"PRAGMA table_info({table})")]
    if col not in cols:
        ledger_exec(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")


ensure_col("expenses", "from_till", "INTEGER DEFAULT 1")      # هل دُفع من الصندوق نقدا
ensure_col("orders", "method", "TEXT DEFAULT 'cash'")          # طريقة الدفع: cash / transfer
ensure_col("orders", "paid_day", "TEXT")                       # يوم القبض (قد يختلف عن يوم الطلب عند الدين)


def day_cash(day: str) -> dict:
    def q(sql, args=()):
        return ledger_query(sql, args)[0]["v"]
    paid_day = "COALESCE(NULLIF(paid_day, ''), day) = ?"
    return {
        "cash_sales": q(f"SELECT COALESCE(SUM(price),0) AS v FROM orders WHERE paid = 1 AND COALESCE(method,'cash') = 'cash' AND {paid_day}", (day,)),
        "transfers": q(f"SELECT COALESCE(SUM(price),0) AS v FROM orders WHERE paid = 1 AND COALESCE(method,'cash') <> 'cash' AND {paid_day}", (day,)),
        "orders": q("SELECT COUNT(*) AS v FROM orders WHERE day = ?", (day,)),
        "value": q("SELECT COALESCE(SUM(price),0) AS v FROM orders WHERE day = ?", (day,)),
        "unpaid": q("SELECT COALESCE(SUM(price),0) AS v FROM orders WHERE day = ? AND paid = 0", (day,)),
        "exp_till": q("SELECT COALESCE(SUM(amount),0) AS v FROM expenses WHERE day = ? AND COALESCE(from_till,1) = 1", (day,)),
        "exp_other": q("SELECT COALESCE(SUM(amount),0) AS v FROM expenses WHERE day = ? AND COALESCE(from_till,1) = 0", (day,)),
        "drawings": q("SELECT COALESCE(SUM(amount),0) AS v FROM drawings WHERE day = ?", (day,)),
    }


def cash_unclosed() -> int:
    """عدد الأيام (آخر 7) التي فيها طلبات ولم يُغلق صندوقها."""
    today = datetime.now()
    n = 0
    for k in range(1, 8):
        day = (today - timedelta(days=k)).strftime("%Y-%m-%d")
        if ledger_query("SELECT 1 AS v FROM orders WHERE day = ? LIMIT 1", (day,)) and \
                not ledger_query("SELECT 1 AS v FROM cash_closes WHERE day = ?", (day,)):
            n += 1
    return n


def stock_move(item_id: int, delta: int, reason: str):
    """تغيير كمية صنف وتسجيل الحركة في عملية واحدة."""
    with _db_lock:
        con = sqlite3.connect(LEDGER, timeout=10)
        try:
            con.execute("UPDATE stock_items SET qty = qty + ? WHERE id = ?", (delta, item_id))
            con.execute("INSERT INTO stock_moves (ts, item_id, delta, reason) VALUES (?,?,?,?)",
                        (datetime.now().isoformat(timespec="seconds"), item_id, delta, reason))
            con.commit()
        finally:
            con.close()


def sheets_needed(o: dict) -> int:
    faces = int(o.get("pages", 0)) * int(o.get("copies", 1))
    return (faces + 1) // 2 if o.get("sides") == "وجهان" else faces


def sync_stock(o: dict, active: bool) -> dict:
    """يخصم ورق الطلب من المخزون عند اكتماله (تمّ)، ويعيده إذا أُرجع أو حُذف أو تغيّر عدد صفحاته."""
    want = sheets_needed(o) if active else 0
    have = int(o.get("stock_used", 0))
    if want == have:
        return o
    rows = ledger_query("SELECT id FROM stock_items WHERE size = ? ORDER BY id LIMIT 1", (o["size"],))
    if rows:
        stock_move(rows[0]["id"], have - want, "طلب " + str(o.get("code", "")))
        o["stock_used"] = want
    return o


def low_items():
    # لا ننبّه إلا للأصناف التي سُجّلت لها كمية (أي جُرد أو شراء)، حتى لا يُزعجك التنبيه قبل الإعداد
    return ledger_query("""SELECT * FROM stock_items WHERE low_at > 0 AND qty <= low_at
                           AND id IN (SELECT DISTINCT item_id FROM stock_moves) ORDER BY name""")


def month_bounds(s):
    try:
        d = datetime.strptime(s or "", "%Y-%m")
    except ValueError:
        d = datetime.now().replace(day=1)
    d = d.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    nxt = d.replace(year=d.year + 1, month=1) if d.month == 12 else d.replace(month=d.month + 1)
    prev = (d - timedelta(days=1)).replace(day=1)
    return d, nxt, prev


@app.template_filter("money")
def _money(v):
    return f"{int(v):,}".replace(",", " ")


def parse_day(s):
    try:
        return datetime.strptime(s or "", "%Y-%m-%d")
    except ValueError:
        return datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)


def report_range(rng, day):
    d = parse_day(day)
    if rng == "week":
        start, end = d - timedelta(days=6), d + timedelta(days=1)
        prev, nxt = d - timedelta(days=7), d + timedelta(days=7)
    elif rng == "month":
        start = d.replace(day=1)
        end = (start.replace(year=start.year + 1, month=1) if start.month == 12
               else start.replace(month=start.month + 1))
        prev, nxt = start - timedelta(days=1), end
    else:
        rng, start, end = "day", d, d + timedelta(days=1)
        prev, nxt = d - timedelta(days=1), d + timedelta(days=1)
    return rng, d, start, end, prev, nxt


def report_rows(rng, day):
    rng, d, start, end, prev, nxt = report_range(rng, day)
    rows = ledger_query("SELECT * FROM orders WHERE ts >= ? AND ts < ? ORDER BY ts",
                        (start.isoformat(), end.isoformat()))
    for r in rows:
        r["printed"] = r["pages"] * r["copies"]
    return rng, d, start, end, prev, nxt, rows


# ---------- صفحة الزبون ----------
PAGE = """<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#1A3A5C">
<title>{{ shop }} - طلب طباعة</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800&display=swap" rel="stylesheet">
<style>
  :root{
    --navy:#1A3A5C; --orange:#FF6B35; --on-orange:#10253B;
    --bg:#EEF2F6; --surface:#FFFFFF; --soft:#F5F8FB; --ink:#142235; --muted:#5E6E80;
    --line:#D9E1EA; --err:#C23A2B; --num:#1A3A5C; --tint:rgba(255,107,53,.12);
    --band:#1A3A5C; --band-ink:#FFFFFF;
  }
  @media (prefers-color-scheme: dark){
    :root{
      --bg:#0C1520; --surface:#14212F; --soft:#0F1B28; --ink:#E8EEF5; --muted:#93A3B6;
      --line:#263648; --err:#FF8F80; --num:#2F5683; --tint:rgba(255,107,53,.16);
      --band:#102338; --band-ink:#FFFFFF;
    }
  }
  *{box-sizing:border-box}
  html{-webkit-text-size-adjust:100%}
  body{margin:0;background:var(--bg);color:var(--ink);
       font-family:"Tajawal","Segoe UI",Tahoma,Arial,sans-serif;font-size:16px;line-height:1.65}
  .shell{max-width:560px;margin:0 auto;min-height:100vh;display:flex;flex-direction:column}

  /* ---- شريط العنوان ---- */
  .top{background:var(--band);color:var(--band-ink);padding:calc(18px + env(safe-area-inset-top,0px)) 20px 52px}
  .brand{display:flex;align-items:center;gap:12px}
  .brand strong{font-size:1.35rem;font-weight:800;letter-spacing:.2px}
  .top p{margin:10px 0 0;color:rgba(255,255,255,.78);font-size:.98rem}

  main{flex:1;padding:0 14px calc(120px + env(safe-area-inset-bottom,0px));margin-top:-34px}
  .step{background:var(--surface);border:1px solid var(--line);border-radius:18px;padding:16px;margin-bottom:12px}
  .step h2{display:flex;align-items:center;gap:10px;font-size:1.05rem;font-weight:700;margin:0 0 14px}
  .num{width:26px;height:26px;border-radius:50%;background:var(--num);color:#fff;font-size:.85rem;
       font-weight:700;display:grid;place-items:center;flex:none}
  .lbl{display:block;font-weight:500;font-size:.92rem;margin:16px 0 7px;color:var(--muted)}
  .lbl:first-of-type{margin-top:0}

  /* ---- رفع الملفات ---- */
  .drop{display:flex;align-items:center;gap:14px;border:2px dashed var(--line);border-radius:14px;
        background:var(--soft);padding:18px 16px;cursor:pointer;position:relative}
  .drop:hover,.drop.over{border-color:var(--orange);background:var(--tint)}
  .drop:has(input:focus-visible){outline:3px solid var(--orange);outline-offset:2px}
  .drop .ico{width:46px;height:46px;border-radius:12px;background:var(--orange);color:var(--on-orange);
             display:grid;place-items:center;flex:none}
  .drop strong{display:block;font-size:1.05rem}
  .drop small{color:var(--muted);font-size:.86rem;line-height:1.5;display:block}
  input[type=file]{position:absolute;opacity:0;inset:0;width:100%;height:100%;cursor:pointer}
  #list{list-style:none;padding:0;margin:12px 0 0}
  #list li{display:flex;align-items:center;gap:10px;padding:9px 0;border-top:1px solid var(--line)}
  #list li:first-child{border-top:0}
  .badge{width:38px;height:38px;border-radius:9px;color:#fff;font-size:.68rem;font-weight:800;
         display:grid;place-items:center;flex:none;letter-spacing:.3px}
  .t-pdf{background:#D64545}.t-img{background:#2F7CD6}.t-doc{background:#2B5CB8}
  .t-xls{background:#1C8A5A}.t-ppt{background:#D9692A}.t-txt{background:#6B7A8C}
  .fn{flex:1;min-width:0}
  .fn b{display:block;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:ltr;text-align:right}
  .fn span{color:var(--muted);font-size:.82rem;direction:ltr;display:block;text-align:right}
  .rm{border:0;background:none;color:var(--muted);width:36px;height:36px;border-radius:50%;cursor:pointer;font-size:1.1rem}
  .rm:hover{background:var(--tint);color:var(--err)}

  /* ---- خيارات الطباعة ---- */
  .stepper{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:12px;
           background:var(--soft);overflow:hidden}
  .stepper button{width:46px;height:44px;border:0;background:none;color:var(--ink);font-size:1.4rem;cursor:pointer}
  .stepper button:hover{background:var(--tint)}
  .stepper input{width:56px;height:44px;border:0;background:var(--surface);color:var(--ink);text-align:center;
                 font-weight:700;font-size:1.1rem;font-family:inherit;-moz-appearance:textfield;
                 border-inline:1px solid var(--line)}
  .stepper input::-webkit-outer-spin-button,.stepper input::-webkit-inner-spin-button{-webkit-appearance:none}
  .chips{display:flex;flex-wrap:wrap;gap:8px}
  .chips label,.seg label{position:relative;cursor:pointer}
  .chips input,.seg input{position:absolute;opacity:0;inset:0;width:100%;height:100%;cursor:pointer}
  .chips span{display:block;padding:8px 14px;border:1px solid var(--line);border-radius:99px;
              background:var(--soft);font-weight:500}
  .chips label:has(input:checked) span{border-color:var(--orange);background:var(--tint);font-weight:700}
  .chips label:has(input:focus-visible) span,.seg label:has(input:focus-visible) span{outline:3px solid var(--orange);outline-offset:2px}
  .seg{display:grid;grid-auto-flow:column;grid-auto-columns:1fr;gap:4px;padding:4px;
       background:var(--soft);border:1px solid var(--line);border-radius:13px}
  .seg span{display:block;text-align:center;padding:10px 6px;border-radius:9px;font-weight:500;color:var(--muted)}
  .seg label:has(input:checked) span{background:var(--surface);color:var(--ink);font-weight:700;
                                     box-shadow:0 0 0 2px var(--orange)}

  /* ---- بياناتك ---- */
  input[type=text]{width:100%;height:48px;padding:0 14px;border:1px solid var(--line);border-radius:12px;
                   background:var(--soft);color:var(--ink);font-size:1rem;font-family:inherit}
  input[type=text]:focus{outline:3px solid var(--orange);outline-offset:1px;background:var(--surface)}

  /* ---- رسائل ---- */
  #msg{display:none;margin:0 0 12px;padding:13px 15px;border-radius:14px;font-weight:500;
       border:1px solid var(--err);color:var(--err);background:var(--surface)}
  #msg.bad{display:block}

  /* ---- شريط الإرسال ---- */
  .dock{position:fixed;inset-inline:0;bottom:0;z-index:5;background:var(--surface);
        border-top:1px solid var(--line);padding:10px 14px calc(10px + env(safe-area-inset-bottom,0px))}
  .dock .in{max-width:560px;margin:0 auto;display:flex;align-items:center;gap:12px}
  .sum{flex:1;font-size:.9rem;color:var(--muted);line-height:1.4}
  .sum b{color:var(--ink);display:block;font-size:.98rem}
  .send{height:50px;padding:0 24px;border:0;border-radius:14px;background:var(--orange);color:var(--on-orange);
        font-weight:800;font-size:1.05rem;font-family:inherit;cursor:pointer;white-space:nowrap}
  .send:disabled{background:var(--line);color:var(--muted);cursor:not-allowed}
  .send:focus-visible{outline:3px solid var(--ink);outline-offset:2px}
  .bar{position:absolute;top:-1px;inset-inline:0;height:4px;background:transparent;display:none}
  .bar div{height:100%;width:0;background:var(--orange);transition:width .15s}

  /* ---- شاشة النجاح ---- */
  #done{display:none;padding:0 14px 40px;margin-top:-34px}
  .ticket{background:var(--surface);border:1px solid var(--line);border-radius:20px;padding:28px 20px;text-align:center}
  .ticket .ok{width:56px;height:56px;border-radius:50%;background:var(--tint);color:var(--orange);
              display:grid;place-items:center;margin:0 auto 12px}
  .ticket h2{margin:0 0 4px;font-size:1.3rem}
  .ticket p{margin:0;color:var(--muted)}
  .codebox{margin:20px auto 6px;padding:14px;border:2px dashed var(--orange);border-radius:16px;max-width:260px}
  .codebox b{display:block;font-size:2.8rem;font-weight:800;letter-spacing:.25em;direction:ltr;
             padding-inline-start:.25em;line-height:1.2}
  .again{margin-top:20px;height:48px;padding:0 22px;border-radius:13px;border:1px solid var(--line);
         background:var(--soft);color:var(--ink);font-weight:700;font-size:1rem;font-family:inherit;cursor:pointer}
  @media (prefers-reduced-motion: reduce){ *{transition:none!important} }
</style>
</head>
<body>
<div class="shell">
  <header class="top">
    <div class="brand">
      <svg width="40" height="40" viewBox="0 0 40 40" aria-hidden="true">
        <rect width="40" height="40" rx="11" fill="#FF6B35"/>
        <path d="M9 17a16 16 0 0 1 22 0M13 22a10 10 0 0 1 14 0M17 27a4 4 0 0 1 6 0" fill="none" stroke="#1A3A5C" stroke-width="3" stroke-linecap="round"/>
        <circle cx="20" cy="32" r="2.2" fill="#1A3A5C"/>
      </svg>
      <strong>{{ shop }}</strong>
    </div>
    <p>أرسل ملفاتك من هاتفك، وتجدها مطبوعة عند وصولك.</p>
  </header>

  <main id="wizard">
    <section class="step">
      <h2><span class="num">1</span>اختر ملفاتك</h2>
      <label class="drop" id="drop">
        <span class="ico">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 16V4M7 9l5-5 5 5M4 20h16"/></svg>
        </span>
        <span>
          <strong>اضغط لاختيار الملفات</strong>
          <small>صور، PDF، Word، Excel، PowerPoint<br>حتى {{ max_mb }} ميغا للملف</small>
        </span>
        <input type="file" id="files" multiple aria-label="اختيار الملفات"
               accept="image/*,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt">
      </label>
      <ul id="list"></ul>
    </section>

    <section class="step">
      <h2><span class="num">2</span>خيارات الطباعة</h2>

      <span class="lbl">عدد النسخ</span>
      <div class="stepper">
        <button type="button" id="plus" aria-label="زيادة">+</button>
        <input type="number" id="copies" min="1" max="99" value="1" inputmode="numeric" aria-label="عدد النسخ">
        <button type="button" id="minus" aria-label="إنقاص">−</button>
      </div>

      <span class="lbl">حجم الورق</span>
      <div class="chips">
        {% for s in sizes %}<label><input type="radio" name="size" value="{{ s }}"{% if loop.first %} checked{% endif %}><span>{{ s }}</span></label>{% endfor %}
      </div>

      <span class="lbl">اللون</span>
      <div class="seg">
        <label><input type="radio" name="color" value="أبيض وأسود" checked><span>أبيض وأسود</span></label>
        <label><input type="radio" name="color" value="ألوان"><span>ألوان</span></label>
      </div>

      <span class="lbl">الوجه</span>
      <div class="seg">
        <label><input type="radio" name="sides" value="وجه واحد" checked><span>وجه واحد</span></label>
        <label><input type="radio" name="sides" value="وجهان"><span>وجهان</span></label>
      </div>
    </section>

    <section class="step">
      <h2><span class="num">3</span>بياناتك</h2>
      <label class="lbl" for="name">اسمك أو رقم هاتفك (اختياري)</label>
      <input type="text" id="name" maxlength="40" autocomplete="off">
      <div id="codeBox" style="display:none">
        <label class="lbl" for="access" style="margin-top:16px">رمز المحل</label>
        <input type="text" id="access" maxlength="20" autocomplete="off" inputmode="numeric">
      </div>
    </section>

    <div id="msg" role="alert"></div>
  </main>

  <section id="done" aria-live="polite">
    <div class="ticket">
      <div class="ok">
        <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>
      </div>
      <h2>تم إرسال طلبك</h2>
      <p id="doneCount"></p>
      <div class="codebox"><b id="doneCode"></b></div>
      <p>أعطِ هذا الرقم لعامل المحل</p>
      <button class="again" id="again">طلب جديد</button>
    </div>
  </section>

  <div class="dock" id="dock">
    <div class="bar" id="bar"><div id="fill"></div></div>
    <div class="in">
      <div class="sum" id="sum"><b>لم تختر ملفات بعد</b>ابدأ بالخطوة الأولى</div>
      <button class="send" id="send" disabled>إرسال الطلب</button>
    </div>
  </div>
</div>

<script>
const MAX = {{ max_mb }} * 1024 * 1024, MAXN = {{ max_n }};
const ALLOWED = {{ allowed|tojson }};
const NEED_CODE = {{ need_code|tojson }};
const urlKey = new URLSearchParams(location.search).get("k") || "";
let chosen = [];
const $ = id => document.getElementById(id);
if (NEED_CODE && !urlKey) $("codeBox").style.display = "block";

function size(b){ return b > 1048576 ? (b/1048576).toFixed(1)+" MB" : Math.ceil(b/1024)+" KB"; }
function radio(n){ return document.querySelector('input[name="'+n+'"]:checked').value; }
function fail(t){ const m=$("msg"); m.textContent=t; m.className="bad"; m.scrollIntoView({block:"center",behavior:"smooth"}); }
function clearMsg(){ $("msg").className=""; }
function kind(ext){
  if (["jpg","jpeg","png","gif","webp","heic"].includes(ext)) return ["img","IMG"];
  if (ext==="pdf") return ["pdf","PDF"];
  if (["doc","docx"].includes(ext)) return ["doc","DOC"];
  if (["xls","xlsx"].includes(ext)) return ["xls","XLS"];
  if (["ppt","pptx"].includes(ext)) return ["ppt","PPT"];
  return ["txt","TXT"];
}
function copies(){ const n = parseInt($("copies").value,10); return isNaN(n) ? 1 : Math.min(99, Math.max(1, n)); }

function summary(){
  const n = chosen.length;
  const s = $("sum");
  s.innerHTML = "";
  const b = document.createElement("b");
  if (!n) { b.textContent = "لم تختر ملفات بعد"; s.append(b, "ابدأ بالخطوة الأولى"); }
  else {
    b.textContent = n + (n === 1 ? " ملف" : " ملفات") + " • " + copies() + " نسخة";
    s.append(b, radio("color") + " • " + radio("size") + " • " + radio("sides"));
  }
  $("send").disabled = n === 0;
}

function render(){
  const ul = $("list"); ul.innerHTML = "";
  chosen.forEach((f,i)=>{
    const ext = f.name.split(".").pop().toLowerCase();
    const [cls, label] = kind(ext);
    const li = document.createElement("li");
    const bd = document.createElement("span"); bd.className = "badge t-"+cls; bd.textContent = label;
    const fn = document.createElement("span"); fn.className = "fn";
    const nm = document.createElement("b"); nm.textContent = f.name;
    const sz = document.createElement("span"); sz.textContent = size(f.size);
    fn.append(nm, sz);
    const rm = document.createElement("button"); rm.className = "rm"; rm.textContent = "✕"; rm.setAttribute("aria-label","حذف الملف");
    rm.onclick = () => { chosen.splice(i,1); render(); };
    li.append(bd, fn, rm); ul.appendChild(li);
  });
  summary();
}

function add(fileList){
  clearMsg();
  for (const f of fileList){
    const ext = f.name.split(".").pop().toLowerCase();
    if (!ALLOWED.includes(ext)) { fail("النوع غير مسموح: "+f.name); continue; }
    if (f.size > MAX) { fail("الملف كبير جدا: "+f.name); continue; }
    if (chosen.length >= MAXN) { fail("الحد الأقصى "+MAXN+" ملفا في المرة الواحدة"); break; }
    chosen.push(f);
  }
  render();
}

$("files").onchange = e => { add(e.target.files); e.target.value = ""; };
["dragover","dragenter"].forEach(ev=>$("drop").addEventListener(ev,e=>{e.preventDefault();$("drop").classList.add("over")}));
["dragleave","drop"].forEach(ev=>$("drop").addEventListener(ev,e=>{e.preventDefault();$("drop").classList.remove("over")}));
$("drop").addEventListener("drop", e => add(e.dataTransfer.files));
$("plus").onclick = () => { $("copies").value = Math.min(99, copies()+1); summary(); };
$("minus").onclick = () => { $("copies").value = Math.max(1, copies()-1); summary(); };
document.addEventListener("change", summary);
$("copies").addEventListener("input", summary);
$("again").onclick = () => { $("done").style.display="none"; $("wizard").style.display="block"; $("dock").style.display="block"; window.scrollTo(0,0); };

$("send").onclick = () => {
  const fd = new FormData();
  chosen.forEach(f => fd.append("files", f));
  fd.append("name", $("name").value);
  fd.append("access", urlKey || $("access").value);
  fd.append("copies", copies());
  fd.append("size", radio("size"));
  fd.append("color", radio("color"));
  fd.append("sides", radio("sides"));
  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/upload");
  $("send").disabled = true; $("bar").style.display = "block"; clearMsg();
  xhr.upload.onprogress = e => { if (e.lengthComputable) $("fill").style.width = (e.loaded/e.total*100)+"%"; };
  xhr.onload = () => {
    $("bar").style.display = "none"; $("fill").style.width = "0";
    let r = {}; try { r = JSON.parse(xhr.responseText); } catch(e){}
    if (xhr.status === 200 && r.ok) {
      $("doneCode").textContent = r.code;
      $("doneCount").textContent = r.count + (r.count === 1 ? " ملف وصل للمحل" : " ملفات وصلت للمحل");
      $("wizard").style.display = "none"; $("dock").style.display = "none"; $("done").style.display = "block";
      chosen = []; render(); window.scrollTo(0,0);
    } else {
      fail(r.error || "حدث خطأ، حاول مرة أخرى");
      $("send").disabled = chosen.length === 0;
    }
  };
  xhr.onerror = () => { $("bar").style.display = "none"; fail("انقطع الاتصال بالشبكة، حاول مرة أخرى"); $("send").disabled = false; };
  xhr.send(fd);
};
summary();
</script>
</body>
</html>
"""

# ---------- صفحة لوحة التحكم ----------
ADMIN = """<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>لوحة الطلبات - {{ shop }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800&display=swap" rel="stylesheet">
<style>
  :root{
    --navy:#1A3A5C; --orange:#FF6B35; --on-orange:#10253B;
    --bg:#EEF2F6; --surface:#FFFFFF; --soft:#F5F8FB; --ink:#142235; --muted:#5E6E80;
    --line:#D9E1EA; --err:#C23A2B; --ok:#1C8A5A; --tint:rgba(255,107,53,.12);
    --band:#1A3A5C;
  }
  @media (prefers-color-scheme: dark){
    :root{
      --bg:#0C1520; --surface:#14212F; --soft:#0F1B28; --ink:#E8EEF5; --muted:#93A3B6;
      --line:#263648; --err:#FF8F80; --ok:#5BD39B; --tint:rgba(255,107,53,.16); --band:#102338;
    }
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);line-height:1.6;
       font-family:"Tajawal","Segoe UI",Tahoma,Arial,sans-serif;font-size:16px}
  button{font-family:inherit;font-size:.95rem;cursor:pointer}
  :focus-visible{outline:3px solid var(--orange);outline-offset:2px}

  header{background:var(--band);color:#fff;padding:14px 22px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
  header .brand{display:flex;align-items:center;gap:12px;flex:1;min-width:200px}
  header h1{margin:0;font-size:1.2rem;font-weight:800}
  header small{display:block;color:rgba(255,255,255,.7);font-weight:400;font-size:.85rem}
  .live{display:flex;align-items:center;gap:7px;color:rgba(255,255,255,.8);font-size:.85rem}
  .live i{width:8px;height:8px;border-radius:50%;background:#5BD39B;display:inline-block}
  .snd{border:1px solid rgba(255,255,255,.35);background:transparent;color:#fff;border-radius:10px;padding:8px 14px}
  .snd.on{background:#fff;color:var(--navy);border-color:#fff;font-weight:700}
  a.snd{text-decoration:none;display:inline-block}
  a.snd.warn{background:#fff;color:var(--err);border-color:#fff;font-weight:700}

  .wrap{max-width:1120px;margin:0 auto;padding:18px 18px 50px}
  .stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px}
  .stat{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:12px 16px}
  .stat b{display:block;font-size:1.9rem;font-weight:800;line-height:1.2}
  .stat span{color:var(--muted);font-size:.92rem}
  .stat.hot{border-color:var(--orange)}
  .stat.hot b{color:var(--orange)}

  .tabs{display:flex;gap:6px;margin-bottom:14px}
  .tabs button{border:1px solid var(--line);background:var(--surface);color:var(--muted);border-radius:99px;padding:7px 18px;font-weight:500}
  .tabs button.on{background:var(--navy);color:#fff;border-color:var(--navy);font-weight:700}
  @media (prefers-color-scheme: dark){ .tabs button.on{background:var(--orange);color:var(--on-orange);border-color:var(--orange)} }

  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(440px,1fr));gap:14px}
  @media (max-width:520px){ .grid{grid-template-columns:1fr} .stats{gap:8px} }
  .order{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:16px;
         border-inline-start:6px solid var(--line)}
  .order.new{border-inline-start-color:var(--orange)}
  .order.done{opacity:.62}
  .head{display:flex;align-items:center;gap:12px}
  .code{font-size:2rem;font-weight:800;letter-spacing:.12em;direction:ltr;line-height:1}
  .who{flex:1;min-width:0}
  .who b{display:block;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .who span{color:var(--muted);font-size:.85rem}
  .pill{font-size:.82rem;padding:3px 12px;border-radius:99px;font-weight:700}
  .pill.n{background:var(--tint);color:var(--orange)}
  .pill.d{background:var(--soft);color:var(--ok);border:1px solid var(--line)}

  .specs{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:14px 0}
  .spec{background:var(--soft);border:1px solid var(--line);border-radius:10px;padding:6px 10px}
  .spec span{display:block;color:var(--muted);font-size:.76rem}
  .spec b{font-size:.95rem;font-weight:700}
  @media (max-width:520px){ .specs{grid-template-columns:repeat(2,1fr)} }

  .files{display:flex;flex-direction:column;gap:6px}
  .file{display:flex;align-items:center;gap:10px;text-decoration:none;color:var(--ink);
        border:1px solid var(--line);border-radius:10px;padding:6px 10px;background:var(--surface)}
  .file:hover{border-color:var(--orange);background:var(--tint)}
  .badge{width:34px;height:34px;border-radius:8px;color:#fff;font-size:.64rem;font-weight:800;display:grid;place-items:center;flex:none}
  .t-pdf{background:#D64545}.t-img{background:#2F7CD6}.t-doc{background:#2B5CB8}
  .t-xls{background:#1C8A5A}.t-ppt{background:#D9692A}.t-txt{background:#6B7A8C}
  .file span.n{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:ltr;text-align:right}

  .acts{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px;padding-top:14px;border-top:1px solid var(--line)}
  .acts button{height:40px;padding:0 16px;border-radius:10px;border:1px solid var(--line);background:var(--surface);color:var(--ink);font-weight:500}
  .acts button:hover{background:var(--soft)}
  .acts .p{background:var(--orange);border-color:var(--orange);color:var(--on-orange);font-weight:800}
  .acts .p:hover{filter:brightness(.95);background:var(--orange)}
  .acts .d{margin-inline-start:auto;color:var(--err);border-color:transparent;background:none}
  .money{display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;margin:12px 0 0;padding:10px;
         border:1px dashed var(--line);border-radius:12px;background:var(--soft)}
  .money label{display:block;font-size:.76rem;color:var(--muted)}
  .money input{width:92px;height:38px;border:1px solid var(--line);border-radius:9px;padding:0 8px;
               background:var(--surface);color:var(--ink);font-size:1rem;font-family:inherit}
  .money .warn{flex-basis:100%;color:var(--orange);font-size:.85rem}
  .money select{height:38px;border:1px solid var(--line);border-radius:9px;padding:0 8px;background:var(--surface);color:var(--ink);font-family:inherit;font-size:.95rem}
  .money .pay{margin-inline-start:auto;height:38px;padding:0 14px;border-radius:9px;border:1px solid var(--line);
              background:var(--surface);color:var(--ink);font-weight:700}
  .money .pay.yes{background:var(--ok);border-color:var(--ok);color:#fff}
  .money + .files{margin-top:12px}

  .empty{text-align:center;color:var(--muted);padding:70px 20px;background:var(--surface);
         border:1px dashed var(--line);border-radius:16px}
  .empty b{display:block;color:var(--ink);font-size:1.15rem;margin-bottom:4px}
  #toast{position:fixed;bottom:18px;inset-inline:0;margin:auto;width:max-content;max-width:90vw;
         background:var(--ink);color:var(--bg);padding:10px 20px;border-radius:99px;display:none;z-index:9}
</style>
</head>
<body>
<header>
  <div class="brand">
    <svg width="38" height="38" viewBox="0 0 40 40" aria-hidden="true">
      <rect width="40" height="40" rx="11" fill="#FF6B35"/>
      <path d="M9 17a16 16 0 0 1 22 0M13 22a10 10 0 0 1 14 0M17 27a4 4 0 0 1 6 0" fill="none" stroke="#1A3A5C" stroke-width="3" stroke-linecap="round"/>
      <circle cx="20" cy="32" r="2.2" fill="#1A3A5C"/>
    </svg>
    <h1>طلبات الطباعة<small>{{ shop }}</small></h1>
  </div>
  <span class="live"><i></i>يتحدّث تلقائيا</span>
  <button class="snd" id="snd">تفعيل صوت التنبيه</button>
  <a class="snd" href="/admin/report">التقرير</a>
  <a class="snd" href="/admin/expenses">المصاريف</a>
  <a class="snd" href="/admin/stock" id="stockLink">المخزون</a>
  <a class="snd" href="/admin/cash" id="cashLink">الصندوق</a>
</header>

<div class="wrap">
  <div class="stats">
    <div class="stat hot"><b id="sNew">0</b><span>طلبات جديدة</span></div>
    <div class="stat"><b id="sDone">0</b><span>تمّت</span></div>
    <div class="stat"><b id="sAll">0</b><span>المجموع</span></div>
  </div>
  <div class="tabs" role="tablist">
    <button class="on" data-f="all">الكل</button>
    <button data-f="new">الجديدة</button>
    <button data-f="done">المنتهية</button>
  </div>
  <div class="grid" id="list"></div>
</div>
<div id="toast" role="status"></div>

<script>
const CUR = {{ cur|tojson }};
let soundOn = false, known = null, filter = "all", data = [];
const $ = id => document.getElementById(id);

function h(tag, cls, text){ const e=document.createElement(tag); if(cls) e.className=cls; if(text!==undefined) e.textContent=text; return e; }
function toast(t){ const el=$("toast"); el.textContent=t; el.style.display="block"; setTimeout(()=>el.style.display="none",2400); }
function kind(name){
  const ext = name.split(".").pop().toLowerCase();
  if (["jpg","jpeg","png","gif","webp","heic"].includes(ext)) return ["img","IMG"];
  if (ext==="pdf") return ["pdf","PDF"];
  if (["doc","docx"].includes(ext)) return ["doc","DOC"];
  if (["xls","xlsx"].includes(ext)) return ["xls","XLS"];
  if (["ppt","pptx"].includes(ext)) return ["ppt","PPT"];
  return ["txt","TXT"];
}

function beep(){
  try{
    const c = new (window.AudioContext||window.webkitAudioContext)();
    [880, 1175].forEach((fq,i)=>{
      const o=c.createOscillator(), g=c.createGain();
      o.connect(g); g.connect(c.destination); o.frequency.value=fq; g.gain.value=.25;
      o.start(c.currentTime+i*.22); o.stop(c.currentTime+i*.22+.18);
    });
  }catch(e){}
}
$("snd").onclick = () => { soundOn = true; $("snd").textContent = "الصوت مفعّل ✓"; $("snd").classList.add("on"); beep(); };
document.querySelectorAll(".tabs button").forEach(b => b.onclick = () => {
  filter = b.dataset.f;
  document.querySelectorAll(".tabs button").forEach(x => x.classList.toggle("on", x === b));
  draw();
});

async function alerts(){
  try {
    const j = await (await fetch("/admin/api/alerts")).json();
    const a = $("stockLink");
    a.textContent = j.low ? "المخزون ⚠ " + j.low : "المخزون";
    a.classList.toggle("warn", j.low > 0);
    const c = $("cashLink");
    c.textContent = j.unclosed ? "الصندوق ⚠" : "الصندوق";
    c.classList.toggle("warn", j.unclosed > 0);
  } catch(e){}
}

async function save(id, body){
  const r = await fetch("/admin/api/set/"+encodeURIComponent(id), {method:"POST",
        headers:{"X-Admin":"1","Content-Type":"application/json"}, body: JSON.stringify(body)});
  const j = await r.json().catch(()=>({}));
  toast(r.ok && j.ok ? "تم الحفظ" : (j.error || "تعذّر الحفظ"));
  load(true);
}

async function act(id, action){
  if (action === "delete" && !confirm("حذف هذا الطلب وملفاته نهائيا؟")) return;
  const r = await fetch("/admin/api/order/"+encodeURIComponent(id)+"/"+action,
                        {method:"POST", headers:{"X-Admin":"1"}});
  const j = await r.json().catch(()=>({}));
  if (!r.ok || !j.ok) toast(j.error || "تعذّر تنفيذ الأمر");
  else if (action === "print") toast("أُرسل أمر الطباعة");
  load();
}

function card(o){
  const d = h("article", "order " + o.status);

  const head = h("div","head");
  head.append(h("span","code",o.code));
  const who = h("div","who");
  who.append(h("b","",o.name || "بدون اسم"));
  who.append(h("span","", new Date(o.time).toLocaleTimeString("ar-DZ",{hour:"2-digit",minute:"2-digit"})));
  head.append(who);
  head.append(h("span","pill "+(o.status==="new"?"n":"d"), o.status==="new" ? "جديد" : "تمّ"));
  d.append(head);

  const specs = h("div","specs");
  [["النسخ",o.copies],["الورق",o.size],["اللون",o.color],["الوجه",o.sides]].forEach(([k,v])=>{
    const s = h("div","spec"); s.append(h("span","",k)); s.append(h("b","",String(v))); specs.append(s);
  });
  d.append(specs);

  const money = h("div","money");
  const field = (label, value, key) => {
    const w = h("div"); const i = h("input");
    i.type = "number"; i.min = "0"; i.value = value; i.inputMode = "numeric";
    i.onchange = () => save(o.id, {[key]: Number(i.value)});
    w.append(h("label","",label), i); money.append(w);
  };
  field("الصفحات", o.pages || 0, "pages");
  field("السعر (" + CUR + ")", o.price || 0, "price");
  const sel = h("select");
  [["cash","نقدا"],["transfer","تحويل / بريدي موب"]].forEach(([v,t]) => {
    const op = h("option","",t); op.value = v; if ((o.method || "cash") === v) op.selected = true; sel.append(op);
  });
  sel.setAttribute("aria-label", "طريقة الدفع");
  sel.onchange = () => save(o.id, {method: sel.value});
  money.append(sel);
  const pay = h("button", "pay" + (o.paid ? " yes" : ""), o.paid ? "مدفوع ✓" : "غير مدفوع");
  pay.onclick = () => save(o.id, {paid: !o.paid});
  money.append(pay);
  if (!o.pages_known) money.append(h("div","warn","⚠ عدد الصفحات غير معروف، أدخله ليُحسب السعر"));
  d.append(money);

  const files = h("div","files");
  o.files.forEach(f=>{
    const [cls,label] = kind(f);
    const a = h("a","file"); a.href = "/admin/file/"+encodeURIComponent(o.id)+"/"+encodeURIComponent(f); a.target="_blank";
    a.append(h("span","badge t-"+cls,label)); a.append(h("span","n",f));
    files.append(a);
  });
  d.append(files);

  const acts = h("div","acts");
  const mk = (txt, action, cls) => { const b=h("button",cls||"",txt); b.onclick=()=>act(o.id,action); acts.append(b); };
  mk("طباعة", "print", "p");
  mk("فتح المجلد", "open");
  if (o.status === "new") mk("تمّ", "done"); else mk("إرجاع", "reopen");
  mk("حذف", "delete", "d");
  d.append(acts);
  return d;
}

function draw(){
  const nNew = data.filter(o=>o.status==="new").length;
  $("sNew").textContent = nNew; $("sDone").textContent = data.length - nNew; $("sAll").textContent = data.length;
  const box = $("list"); box.innerHTML = "";
  const list = data.filter(o => filter==="all" || o.status===filter);
  if (!list.length) {
    const e = h("div","empty"); e.style.gridColumn = "1 / -1";
    e.append(h("b","", data.length ? "لا توجد طلبات هنا" : "لا توجد طلبات بعد"));
    e.append(document.createTextNode(data.length ? "جرّب تبويبا آخر." : "ستظهر هنا فور وصولها من الزبائن."));
    box.append(e); return;
  }
  list.forEach(o => box.append(card(o)));
}

async function load(force){
  alerts();
  try { data = await (await fetch("/admin/api/orders")).json(); } catch(e){ return; }
  const ids = new Set(data.filter(o=>o.status==="new").map(o=>o.id));
  if (known !== null && soundOn) { for (const id of ids) if (!known.has(id)) { beep(); break; } }
  known = ids;
  const ae = document.activeElement;
  if (!force && ae && ae.tagName === "INPUT" && ae.closest("#list")) return;   // لا نقاطع الكتابة
  draw();
}
load(); setInterval(load, 5000);
</script>
</body>
</html>
"""


# ---------- مسارات الزبون ----------
@app.get("/")
def index():
    return render_template_string(PAGE, shop=SHOP_NAME, max_mb=MAX_FILE_MB,
                                  max_n=MAX_FILES_PER_UPLOAD, allowed=sorted(ALLOWED),
                                  sizes=PAPER_SIZES, need_code=bool(ACCESS_CODE))


@app.post("/upload")
def upload():
    if ACCESS_CODE and not hmac.compare_digest(
            request.form.get("access", "").strip().encode(), ACCESS_CODE.encode()):
        return jsonify(ok=False, error="رمز المحل غير صحيح"), 403
    if rate_limited(client_ip()):
        return jsonify(ok=False, error="طلبات كثيرة، حاول بعد قليل"), 429

    files = request.files.getlist("files")
    if not files or not files[0].filename:
        return jsonify(ok=False, error="لم تختر أي ملف"), 400
    if len(files) > MAX_FILES_PER_UPLOAD:
        return jsonify(ok=False, error="عدد الملفات كبير"), 400

    try:
        copies = max(1, min(99, int(request.form.get("copies", "1"))))
    except ValueError:
        copies = 1
    size = request.form.get("size", "A4")
    size = size if size in PAPER_SIZES else "A4"
    color = "ألوان" if request.form.get("color") == "ألوان" else "أبيض وأسود"
    sides = "وجهان" if request.form.get("sides") == "وجهان" else "وجه واحد"
    name = request.form.get("name", "").strip()[:40]

    code = str(secrets.randbelow(9000) + 1000)
    now = datetime.now()
    folder = f"{now.strftime('%Y%m%d-%H%M%S')}_{code}"
    target = os.path.join(UPLOAD_DIR, folder)
    os.makedirs(target, exist_ok=True)

    saved = []
    for f in files:
        fname = clean_name(f.filename)
        ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
        if ext not in ALLOWED:
            continue
        head = f.stream.read(16)
        f.stream.seek(0)
        if not magic_ok(ext, head):
            continue
        base, n = fname, 1
        while fname in saved:       # تفادي تكرار الأسماء
            n += 1
            fname = f"{n}_{base}"
        f.save(os.path.join(target, fname))
        saved.append(fname)

    if not saved:
        shutil.rmtree(target, ignore_errors=True)
        return jsonify(ok=False, error="لا يوجد ملف صالح بنوع مسموح"), 400

    pages, known = 0, True
    for fname in saved:
        n = count_pages(os.path.join(target, fname), fname.rsplit(".", 1)[-1].lower())
        if n is None:
            known = False
        else:
            pages += n
    order = {
        "id": folder, "code": code, "name": name, "time": now.isoformat(),
        "copies": copies, "size": size, "color": color, "sides": sides,
        "files": saved, "status": "new",
        "pages": pages, "pages_known": known, "price_manual": False, "paid": False,
        "price": calc_price(pages, copies, size, color),
    }
    write_order(folder, order)
    ledger_upsert(order)
    return jsonify(ok=True, count=len(saved), code=code)


# ---------- مسارات المحل (محلية فقط) ----------
@app.get("/admin")
def admin():
    local_only()
    return render_template_string(ADMIN, shop=SHOP_NAME, cur=CURRENCY)


@app.get("/admin/api/orders")
def admin_orders():
    local_only()
    orders = []
    for folder in os.listdir(UPLOAD_DIR):
        o = read_order(folder)
        if o:
            orders.append(order_defaults(o))
    # الجديد أولا، ثم الأحدث
    orders.sort(key=lambda o: o["time"], reverse=True)
    orders.sort(key=lambda o: o["status"] != "new")
    return jsonify(orders)


@app.get("/admin/file/<folder>/<name>")
def admin_file(folder, name):
    local_only()
    if not valid_folder(folder):
        abort(404)
    path = os.path.join(UPLOAD_DIR, folder)
    if name not in os.listdir(path) or name == "order.json":
        abort(404)
    return send_from_directory(path, name)


REPORT = """<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>تقرير - {{ shop }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800&display=swap" rel="stylesheet">
<style>
  :root{ --navy:#1A3A5C; --orange:#FF6B35; --on-orange:#10253B;
    --bg:#EEF2F6; --surface:#FFFFFF; --soft:#F5F8FB; --ink:#142235; --muted:#5E6E80;
    --line:#D9E1EA; --err:#C23A2B; --ok:#1C8A5A; --tint:rgba(255,107,53,.12); --band:#1A3A5C; }
  @media (prefers-color-scheme: dark){ :root{
    --bg:#0C1520; --surface:#14212F; --soft:#0F1B28; --ink:#E8EEF5; --muted:#93A3B6;
    --line:#263648; --err:#FF8F80; --ok:#5BD39B; --tint:rgba(255,107,53,.16); --band:#102338; } }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);line-height:1.6;
       font-family:"Tajawal","Segoe UI",Tahoma,Arial,sans-serif;font-size:16px}
  :focus-visible{outline:3px solid var(--orange);outline-offset:2px}
  header{background:var(--band);color:#fff;padding:14px 22px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
  header h1{margin:0;font-size:1.2rem;font-weight:800;flex:1;min-width:160px}
  header h1 small{display:block;color:rgba(255,255,255,.7);font-weight:400;font-size:.85rem}
  .hb{border:1px solid rgba(255,255,255,.35);background:transparent;color:#fff;border-radius:10px;padding:8px 14px;
      text-decoration:none;font-family:inherit;font-size:.95rem;cursor:pointer}
  .wrap{max-width:1100px;margin:0 auto;padding:18px 18px 50px}
  .bar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
  .tabs{display:flex;gap:6px}
  .tabs a{border:1px solid var(--line);background:var(--surface);color:var(--muted);border-radius:99px;
          padding:7px 18px;font-weight:500;text-decoration:none}
  .tabs a.on{background:var(--navy);color:#fff;border-color:var(--navy);font-weight:700}
  @media (prefers-color-scheme: dark){ .tabs a.on{background:var(--orange);color:var(--on-orange);border-color:var(--orange)} }
  .nav{display:flex;gap:6px;align-items:center;margin-inline-start:auto}
  .nav a,.nav input{height:38px;border:1px solid var(--line);background:var(--surface);color:var(--ink);
       border-radius:10px;padding:0 12px;display:inline-flex;align-items:center;text-decoration:none;font-family:inherit;font-size:.95rem}
  .title{font-size:1.25rem;margin:4px 0 14px;font-weight:800}
  .printonly{display:none}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:16px}
  .card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:12px 14px}
  .card b{display:block;font-size:1.6rem;font-weight:800;line-height:1.25}
  .card span{color:var(--muted);font-size:.88rem}
  .card.good b{color:var(--ok)} .card.bad b{color:var(--err)} .card.hot{border-color:var(--orange)}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px;margin-bottom:14px}
  .box{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:14px 16px}
  .box h2{margin:0 0 10px;font-size:1.02rem}
  table{width:100%;border-collapse:collapse;font-size:.95rem}
  th{color:var(--muted);font-weight:500;text-align:start;font-size:.85rem}
  th,td{padding:7px 6px;border-bottom:1px solid var(--line)}
  tr:last-child td{border-bottom:0}
  .scroll{overflow-x:auto}
  .num{direction:ltr;text-align:end;white-space:nowrap}
  .hours{display:grid;grid-template-columns:repeat(24,1fr);gap:3px;align-items:end;height:128px}
  .hours div{display:flex;flex-direction:column;justify-content:flex-end;align-items:center;height:100%}
  .hours i{display:block;width:100%;background:var(--orange);border-radius:4px 4px 0 0}
  .hours small{font-size:.6rem;color:var(--muted);margin-top:3px}
  .hours span{font-size:.6rem;font-weight:700;margin-bottom:2px;min-height:12px}
  .daybar{display:grid;grid-template-columns:70px 1fr 90px;gap:8px;align-items:center;margin:5px 0;font-size:.9rem}
  .daybar i{display:block;height:12px;background:var(--orange);border-radius:6px;min-width:2px}
  .empty{color:var(--muted);padding:10px 0}
  .tag{display:inline-block;padding:1px 10px;border-radius:99px;font-size:.8rem;font-weight:700}
  .tag.ok{background:var(--soft);color:var(--ok);border:1px solid var(--line)}
  .tag.no{background:var(--tint);color:var(--err)}
  .warn{background:var(--tint);border:1px solid var(--orange);border-radius:12px;padding:10px 14px;margin-bottom:14px}
  @media print{
    body{background:#fff;color:#000}
    header,.bar,.noprint{display:none!important}
    .printonly{display:block;font-weight:800;font-size:1.3rem;margin-bottom:4px}
    .card,.box{border:1px solid #999;break-inside:avoid}
    .hours i,.daybar i{background:#555!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  }
</style>
</head>
<body>
<header>
  <h1>التقارير<small>{{ shop }}</small></h1>
  <a class="hb" href="/admin">الطلبات</a>
  <a class="hb" href="/admin/expenses">المصاريف</a>
  <a class="hb" href="/admin/stock">المخزون</a>
  <a class="hb" href="/admin/cash">الصندوق</a>
  <button class="hb" onclick="window.print()">طباعة التقرير</button>
  <a class="hb" href="/admin/report.csv?range={{ rng }}&day={{ day }}">تصدير Excel</a>
</header>

<div class="wrap">
  <div class="bar">
    <div class="tabs">
      <a href="/admin/report?range=day&day={{ day }}" class="{{ 'on' if rng=='day' }}">اليوم</a>
      <a href="/admin/report?range=week&day={{ day }}" class="{{ 'on' if rng=='week' }}">7 أيام</a>
      <a href="/admin/report?range=month&day={{ day }}" class="{{ 'on' if rng=='month' }}">الشهر</a>
    </div>
    <div class="nav">
      <a href="/admin/report?range={{ rng }}&day={{ prev_day }}" aria-label="السابق">›</a>
      <form method="get" action="/admin/report" style="margin:0">
        <input type="hidden" name="range" value="{{ rng }}">
        <input type="date" name="day" value="{{ day }}" onchange="this.form.submit()" aria-label="اختر تاريخا">
      </form>
      <a href="/admin/report?range={{ rng }}&day={{ next_day }}" aria-label="التالي">‹</a>
      <a href="/admin/report?range={{ rng }}">اليوم الحالي</a>
    </div>
  </div>

  <div class="printonly">{{ shop }} - تقرير</div>
  <h2 class="title">{{ title }}</h2>

  {% if tot.review %}
  <div class="warn"><b>{{ tot.review }}</b> طلب بدون عدد صفحات معروف، فقيمته قد تكون ناقصة. أدخل الصفحات من لوحة الطلبات.</div>
  {% endif %}

  <div class="cards">
    <div class="card hot"><b>{{ tot.orders }}</b><span>عدد الطلبات</span></div>
    <div class="card"><b>{{ tot.printed|money }}</b><span>صفحة مطبوعة (مع النسخ)</span></div>
    <div class="card"><b>{{ tot.value|money }} <small>{{ cur }}</small></b><span>قيمة الطلبات</span></div>
    <div class="card good"><b>{{ tot.paid|money }} <small>{{ cur }}</small></b><span>المحصّل (مدفوع)</span></div>
    <div class="card bad"><b>{{ tot.unpaid|money }} <small>{{ cur }}</small></b><span>غير مدفوع</span></div>
    <div class="card bad"><b>{{ exp_total|money }} <small>{{ cur }}</small></b><span>المصاريف</span></div>
    <div class="card {{ 'good' if net >= 0 else 'bad' }}"><b>{{ net|money }} <small>{{ cur }}</small></b><span>الربح الصافي (المحصّل − المصاريف)</span></div>
    <div class="card"><b>{{ draw_total|money }} <small>{{ cur }}</small></b><span>سحوباتي الشخصية</span></div>
    <div class="card {{ 'good' if left >= 0 else 'bad' }}"><b>{{ left|money }} <small>{{ cur }}</small></b><span>الباقي بعد سحوباتك</span></div>
    <div class="card"><b>{{ avg|money }} <small>{{ cur }}</small></b><span>متوسط الطلب</span></div>
  </div>

  <div class="grid">
    <section class="box">
      <h2>حسب اللون</h2>
      {% if by_color %}<table>
        <tr><th>اللون</th><th class="num">طلبات</th><th class="num">صفحات</th><th class="num">القيمة</th></tr>
        {% for k, v in by_color %}<tr><td>{{ k }}</td><td class="num">{{ v[0] }}</td><td class="num">{{ v[1]|money }}</td><td class="num">{{ v[2]|money }}</td></tr>{% endfor %}
      </table>{% else %}<div class="empty">لا توجد بيانات</div>{% endif %}
    </section>
    <section class="box">
      <h2>حسب حجم الورق</h2>
      {% if by_size %}<table>
        <tr><th>الحجم</th><th class="num">طلبات</th><th class="num">صفحات</th><th class="num">القيمة</th></tr>
        {% for k, v in by_size %}<tr><td>{{ k }}</td><td class="num">{{ v[0] }}</td><td class="num">{{ v[1]|money }}</td><td class="num">{{ v[2]|money }}</td></tr>{% endfor %}
      </table>{% else %}<div class="empty">لا توجد بيانات</div>{% endif %}
    </section>
  </div>

  <div class="grid">
    <section class="box">
      <h2>ساعات الذروة (عدد الطلبات)</h2>
      {% if tot.orders %}<div class="hours">
        {% for hh, n, px in hours %}<div><span>{{ n if n }}</span><i style="height:{{ px }}px"></i><small>{{ hh }}</small></div>{% endfor %}
      </div>{% else %}<div class="empty">لا توجد بيانات</div>{% endif %}
    </section>
    {% if days %}
    <section class="box">
      <h2>القيمة حسب اليوم</h2>
      {% for lab, n, val, pct in days %}
      <div class="daybar"><span>{{ lab }}</span><i style="width:{{ pct }}%"></i><span class="num">{{ val|money }}</span></div>
      {% endfor %}
    </section>
    {% endif %}
  </div>

  {% if exp_cats %}
  <section class="box" style="margin-bottom:14px">
    <h2>المصاريف حسب الفئة</h2>
    <table>
      <tr><th>الفئة</th><th class="num">المبلغ ({{ cur }})</th></tr>
      {% for k, v in exp_cats %}<tr><td>{{ k }}</td><td class="num">{{ v|money }}</td></tr>{% endfor %}
    </table>
  </section>
  {% endif %}

  <section class="box" style="margin-bottom:14px">
    <h2>الديون غير المسددة (كل الفترات): {{ debts_total|money }} {{ cur }}</h2>
    {% if debts %}<div class="scroll"><table>
      <tr><th>التاريخ</th><th>الرمز</th><th>الاسم</th><th class="num">المبلغ</th></tr>
      {% for r in debts %}<tr><td>{{ r.ts[:16].replace('T',' ') }}</td><td>{{ r.code }}</td><td>{{ r.name or '-' }}</td><td class="num">{{ r.price|money }}</td></tr>{% endfor %}
    </table></div>{% else %}<div class="empty">لا توجد ديون 🎉</div>{% endif %}
  </section>

  <section class="box">
    <h2>تفاصيل الطلبات ({{ rows|length }})</h2>
    {% if rows %}<div class="scroll"><table>
      <tr><th>الوقت</th><th>الرمز</th><th>الاسم</th><th>الخيارات</th><th class="num">صفحات×نسخ</th><th class="num">القيمة</th><th>الدفع</th></tr>
      {% for r in rows %}<tr>
        <td>{{ r.ts[5:16].replace('T',' ') }}</td><td>{{ r.code }}</td><td>{{ r.name or '-' }}</td>
        <td>{{ r.size }} • {{ r.color }} • {{ r.sides }}</td>
        <td class="num">{{ r.pages }}×{{ r.copies }}{{ ' ⚠' if not r.pages_known }}</td>
        <td class="num">{{ r.price|money }}</td>
        <td><span class="tag {{ 'ok' if r.paid else 'no' }}">{{ 'مدفوع' if r.paid else 'غير مدفوع' }}</span></td>
      </tr>{% endfor %}
    </table></div>{% else %}<div class="empty">لا توجد طلبات في هذه الفترة</div>{% endif %}
  </section>
</div>
</body>
</html>
"""


@app.post("/admin/api/set/<folder>")
def admin_set(folder):
    """تعديل عدد الصفحات أو السعر أو حالة الدفع لطلب."""
    local_only(write=True)
    if not valid_folder(folder):
        return jsonify(ok=False, error="الطلب غير موجود"), 404
    o = read_order(folder)
    if not o:
        return jsonify(ok=False, error="الطلب غير موجود"), 404
    o = order_defaults(o)
    body = request.get_json(silent=True) or {}
    try:
        if "pages" in body:
            o["pages"] = max(0, min(9999, int(body["pages"])))
            o["pages_known"] = True
            if not o["price_manual"]:
                o["price"] = calc_price(o["pages"], o["copies"], o["size"], o["color"])
        if "price" in body:
            o["price"] = max(0, min(10_000_000, int(body["price"])))
            o["price_manual"] = True
        if "paid" in body:
            o["paid"] = bool(body["paid"])
            o["paid_day"] = datetime.now().strftime("%Y-%m-%d") if o["paid"] else ""
        if body.get("method") in ("cash", "transfer"):
            o["method"] = body["method"]
    except (TypeError, ValueError):
        return jsonify(ok=False, error="قيمة غير صالحة"), 400
    sync_stock(o, o.get("status") == "done")
    write_order(folder, o)
    ledger_upsert(o)
    return jsonify(ok=True, order=o)


# ---------- صفحات المصاريف والمخزون ----------
HEAD = """<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} - {{ shop }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700;800&display=swap" rel="stylesheet">
<style>
  :root{ --navy:#1A3A5C; --orange:#FF6B35; --on-orange:#10253B;
    --bg:#EEF2F6; --surface:#FFFFFF; --soft:#F5F8FB; --ink:#142235; --muted:#5E6E80;
    --line:#D9E1EA; --err:#C23A2B; --ok:#1C8A5A; --tint:rgba(255,107,53,.12); --band:#1A3A5C; }
  @media (prefers-color-scheme: dark){ :root{
    --bg:#0C1520; --surface:#14212F; --soft:#0F1B28; --ink:#E8EEF5; --muted:#93A3B6;
    --line:#263648; --err:#FF8F80; --ok:#5BD39B; --tint:rgba(255,107,53,.16); --band:#102338; } }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);line-height:1.6;
       font-family:"Tajawal","Segoe UI",Tahoma,Arial,sans-serif;font-size:16px}
  :focus-visible{outline:3px solid var(--orange);outline-offset:2px}
  header{background:var(--band);color:#fff;padding:14px 22px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  header h1{margin:0;font-size:1.2rem;font-weight:800;flex:1;min-width:150px}
  header h1 small{display:block;color:rgba(255,255,255,.7);font-weight:400;font-size:.85rem}
  .hb{border:1px solid rgba(255,255,255,.35);background:transparent;color:#fff;border-radius:10px;padding:7px 14px;
      text-decoration:none;font-size:.95rem}
  .hb.on{background:#fff;color:var(--navy);border-color:#fff;font-weight:700}
  .wrap{max-width:1100px;margin:0 auto;padding:18px 18px 60px}
  .box{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:14px 16px;margin-bottom:14px}
  .box h2{margin:0 0 10px;font-size:1.05rem}
  .warn{background:var(--tint);border:1px solid var(--orange);border-radius:12px;padding:10px 14px;margin-bottom:14px}
  .muted{color:var(--muted);font-size:.88rem}
  input,select,textarea{height:42px;border:1px solid var(--line);border-radius:10px;padding:0 10px;background:var(--soft);
        color:var(--ink);font-size:1rem;font-family:inherit;max-width:100%}
  input:focus,select:focus{outline:3px solid var(--orange);outline-offset:1px;background:var(--surface)}
  button{height:42px;border-radius:10px;border:1px solid var(--line);background:var(--surface);color:var(--ink);
         font-family:inherit;font-size:.95rem;padding:0 16px;cursor:pointer;font-weight:500}
  button.p{background:var(--orange);border-color:var(--orange);color:var(--on-orange);font-weight:800}
  button.d{color:var(--err);background:none;border-color:transparent}
  .frm{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end}
  .frm label{display:block;font-size:.8rem;color:var(--muted);margin-bottom:3px}
  .num{direction:ltr;text-align:end;white-space:nowrap}
  table{width:100%;border-collapse:collapse;font-size:.95rem}
  th{color:var(--muted);font-weight:500;text-align:start;font-size:.85rem}
  th,td{padding:7px 6px;border-bottom:1px solid var(--line)}
  tr:last-child td{border-bottom:0}
  .scroll{overflow-x:auto}
  .grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px;margin-bottom:14px}
  .good{color:var(--ok)} .bad{color:var(--err)}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
  .card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:12px 14px}
  .card b{display:block;font-size:1.6rem;font-weight:800;line-height:1.25}
  .card span{color:var(--muted);font-size:.88rem}
  .card.bad b{color:var(--err)} .card.hot{border-color:var(--orange)}
  .bar{display:grid;grid-template-columns:90px 1fr 90px;gap:8px;align-items:center;margin:6px 0;font-size:.92rem}
  .bar i{display:block;height:12px;background:var(--orange);border-radius:6px;min-width:2px}
  .nav{display:flex;gap:6px;align-items:center;margin-bottom:14px;flex-wrap:wrap}
  .nav a{height:38px;border:1px solid var(--line);background:var(--surface);color:var(--ink);border-radius:10px;
         padding:0 14px;display:inline-flex;align-items:center;text-decoration:none}
  .items{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px;margin-bottom:14px}
  .item{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:14px 16px;
        border-inline-start:6px solid var(--ok)}
  .item.low{border-inline-start-color:var(--err)}
  .item .top{display:flex;align-items:baseline;gap:8px}
  .item .top b{flex:1;font-size:1.05rem}
  .item .q{font-size:2rem;font-weight:800;line-height:1.2}
  .item.low .q{color:var(--err)}
  .tag{font-size:.8rem;padding:2px 10px;border-radius:99px;font-weight:700;background:var(--soft);color:var(--ok);border:1px solid var(--line)}
  .item.low .tag{background:var(--tint);color:var(--err);border:0}
  .meter{height:8px;background:var(--soft);border:1px solid var(--line);border-radius:6px;overflow:hidden;margin:8px 0}
  .meter i{display:block;height:100%;background:var(--ok)}
  .item.low .meter i{background:var(--err)}
  .row2{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
  .row2 input{width:105px}
  #toast{position:fixed;bottom:18px;inset-inline:0;margin:auto;width:max-content;max-width:90vw;
         background:var(--ink);color:var(--bg);padding:10px 20px;border-radius:99px;display:none;z-index:9}
</style>
</head>
<body>
<header>
  <h1>{{ title }}<small>{{ shop }}</small></h1>
  <a class="hb" href="/admin">الطلبات</a>
  <a class="hb" href="/admin/report">التقرير</a>
  <a class="hb {{ 'on' if active=='exp' }}" href="/admin/expenses">المصاريف</a>
  <a class="hb {{ 'on' if active=='stock' }}" href="/admin/stock">المخزون</a>
  <a class="hb {{ 'on' if active=='cash' }}" href="/admin/cash">الصندوق</a>
</header>
<div class="wrap">
"""

FOOT = """
</div>
<div id="toast" role="status"></div>
<script>
function toast(t){ const el=document.getElementById("toast"); el.textContent=t; el.style.display="block"; setTimeout(()=>el.style.display="none",2400); }
async function post(url, body){
  const r = await fetch(url, {method:"POST", headers:{"X-Admin":"1","Content-Type":"application/json"}, body: JSON.stringify(body||{})});
  const j = await r.json().catch(()=>({}));
  if (!r.ok || !j.ok) { toast(j.error || "تعذّر التنفيذ"); return false; }
  return true;
}
async function run(url, body, confirmMsg){
  if (confirmMsg && !confirm(confirmMsg)) return;
  if (await post(url, body)) location.reload();
}
"""

EXPENSES = HEAD + """
  <div class="nav">
    <a href="/admin/expenses?month={{ prev }}" aria-label="الشهر السابق">›</a>
    <form method="get" action="/admin/expenses" style="margin:0">
      <input type="month" name="month" value="{{ month }}" onchange="this.form.submit()" aria-label="الشهر">
    </form>
    <a href="/admin/expenses?month={{ nxt }}" aria-label="الشهر التالي">‹</a>
    <a href="/admin/expenses">هذا الشهر</a>
  </div>

  <section class="box">
    <h2>إضافة مصروف</h2>
    <div class="frm">
      <div><label for="eday">التاريخ</label><input type="date" id="eday" value="{{ today }}"></div>
      <div><label for="ecat">الفئة</label>
        <select id="ecat">{% for c in cats %}<option>{{ c }}</option>{% endfor %}</select></div>
      <div><label for="eamt">المبلغ ({{ cur }})</label><input type="number" id="eamt" min="1" inputmode="numeric" style="width:130px"></div>
      <div style="flex:1;min-width:160px"><label for="enote">ملاحظة</label><input type="text" id="enote" maxlength="80" style="width:100%"></div>
      <label style="display:flex;gap:6px;align-items:center;height:42px;margin:0;color:var(--ink);font-size:.95rem"><input type="checkbox" id="etill" checked style="height:auto;width:18px"> دُفع من الصندوق</label>
      <button class="p" onclick="addExp()">إضافة</button>
    </div>
  </section>

  <div class="cards">
    <div class="card bad"><b>{{ total|money }} <small>{{ cur }}</small></b><span>مصاريف {{ month }}</span></div>
    <div class="card"><b>{{ rows|length }}</b><span>عدد العمليات</span></div>
  </div>

  {% if cats_sum %}
  <section class="box">
    <h2>حسب الفئة</h2>
    {% for k, v, pct in cats_sum %}<div class="bar"><span>{{ k }}</span><i style="width:{{ pct }}%"></i><span class="num">{{ v|money }}</span></div>{% endfor %}
  </section>
  {% endif %}

  <section class="box">
    <h2>العمليات</h2>
    {% if rows %}<div class="scroll"><table>
      <tr><th>التاريخ</th><th>الفئة</th><th>ملاحظة</th><th class="num">المبلغ</th><th>الدفع</th><th></th></tr>
      {% for r in rows %}<tr><td>{{ r.day }}</td><td>{{ r.category }}</td><td>{{ r.note or '-' }}</td>
        <td class="num">{{ r.amount|money }}</td>
        <td>{{ 'الصندوق' if r.from_till is none or r.from_till else 'خارجه' }}</td>
        <td><button class="d" onclick="run('/admin/api/expense/{{ r.id }}/delete', {}, 'حذف هذا المصروف؟')">حذف</button></td></tr>{% endfor %}
    </table></div>{% else %}<div class="muted">لا توجد مصاريف في هذا الشهر.</div>{% endif %}
  </section>
""" + FOOT + """
function addExp(){
  run("/admin/api/expense", {day: document.getElementById("eday").value, category: document.getElementById("ecat").value,
      amount: Number(document.getElementById("eamt").value), note: document.getElementById("enote").value, from_till: document.getElementById("etill").checked});
}
</script></body></html>"""

STOCK = HEAD + """
  {% if low %}<div class="warn" role="alert">⚠ أصناف على وشك النفاد: <b>{{ low|map(attribute='name')|join('، ') }}</b></div>{% endif %}

  <div class="items">
  {% for it in items %}
    <article class="item {{ 'low' if it.low }}">
      <div class="top"><b>{{ it.name }}</b><span class="tag">{{ 'قارب على النفاد' if it.low else ('متوفر' if it.ready else 'لم يُجرد بعد') }}</span></div>
      <div class="q">{{ it.qty }} <small class="muted">{{ it.unit }}</small></div>
      <div class="meter"><i style="width:{{ it.pct }}%"></i></div>
      <div class="muted">حد التنبيه: {{ it.low_at }} {{ it.unit }}{% if it.size %} • يُخصم تلقائيا عند اكتمال طلبات {{ it.size }}{% endif %}</div>
      <div class="row2">
        <input type="number" min="1" placeholder="الكمية" id="q{{ it.id }}" inputmode="numeric" aria-label="كمية الشراء">
        <input type="number" min="0" placeholder="التكلفة ({{ cur }})" id="c{{ it.id }}" inputmode="numeric" aria-label="تكلفة الشراء">
        <button class="p" onclick="addStock({{ it.id }})">+ إضافة</button>
      </div>
      <div class="row2">
        <button onclick="setQty({{ it.id }}, {{ it.qty }})">تعديل الجرد</button>
        <button onclick="setLow({{ it.id }}, {{ it.low_at }})">حد التنبيه</button>
        <button class="d" onclick="run('/admin/api/stock/{{ it.id }}/delete', {}, 'حذف هذا الصنف وسجله؟')">حذف</button>
      </div>
    </article>
  {% endfor %}
  </div>

  <section class="box">
    <h2>صنف جديد</h2>
    <div class="frm">
      <div><label for="nname">الاسم</label><input type="text" id="nname" maxlength="40"></div>
      <div><label for="nunit">الوحدة</label><input type="text" id="nunit" value="قطعة" maxlength="12" style="width:100px"></div>
      <div><label for="nqty">الكمية</label><input type="number" id="nqty" value="0" min="0" style="width:100px"></div>
      <div><label for="nlow">حد التنبيه</label><input type="number" id="nlow" value="0" min="0" style="width:100px"></div>
      <div><label for="nsize">يُخصم من طلبات (اختياري)</label>
        <select id="nsize"><option value="">لا شيء (يدوي)</option>{% for s in sizes %}<option>{{ s }}</option>{% endfor %}</select></div>
      <button class="p" onclick="newItem()">إضافة الصنف</button>
    </div>
  </section>

  <section class="box">
    <h2>آخر الحركات</h2>
    {% if moves %}<div class="scroll"><table>
      <tr><th>الوقت</th><th>الصنف</th><th class="num">التغيير</th><th>السبب</th></tr>
      {% for m in moves %}<tr><td>{{ m.ts[5:16].replace('T',' ') }}</td><td>{{ m.name }}</td>
        <td class="num" style="color:var(--{{ 'ok' if m.delta > 0 else 'err' }})">{{ '+' if m.delta > 0 }}{{ m.delta }}</td><td>{{ m.reason }}</td></tr>{% endfor %}
    </table></div>{% else %}<div class="muted">لا توجد حركات بعد. ابدأ بإدخال الكمية الحالية لكل صنف عبر «تعديل الجرد».</div>{% endif %}
  </section>
""" + FOOT + """
function addStock(id){
  const q = Number(document.getElementById("q"+id).value), c = Number(document.getElementById("c"+id).value || 0);
  if (!q || q < 1) { toast("اكتب الكمية"); return; }
  run("/admin/api/stock/"+id+"/add", {qty: q, cost: c});
}
function setQty(id, cur){
  const v = prompt("الكمية الفعلية الآن في المحل:", cur);
  if (v === null || v.trim() === "") return;
  run("/admin/api/stock/"+id+"/set", {qty: Number(v)});
}
function setLow(id, cur){
  const v = prompt("نبّهني عندما تصل الكمية إلى (أو أقل):", cur);
  if (v === null || v.trim() === "") return;
  run("/admin/api/stock/"+id+"/low", {low_at: Number(v)});
}
function newItem(){
  run("/admin/api/stock/item", {name: document.getElementById("nname").value, unit: document.getElementById("nunit").value,
      qty: Number(document.getElementById("nqty").value), low_at: Number(document.getElementById("nlow").value),
      size: document.getElementById("nsize").value});
}
</script></body></html>"""


@app.get("/admin/expenses")
def admin_expenses():
    local_only()
    start, end, prev = month_bounds(request.args.get("month"))
    rows = ledger_query("SELECT * FROM expenses WHERE day >= ? AND day < ? ORDER BY day DESC, id DESC",
                        (start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")))
    total = sum(r["amount"] for r in rows)
    acc = {}
    for r in rows:
        acc[r["category"]] = acc.get(r["category"], 0) + r["amount"]
    big = max(acc.values() or [1]) or 1
    cats_sum = [(k, v, round(v / big * 100)) for k, v in sorted(acc.items(), key=lambda kv: -kv[1])]
    return render_template_string(
        EXPENSES, shop=SHOP_NAME, title="المصاريف", active="exp", cur=CURRENCY, cats=EXP_CATS,
        month=start.strftime("%Y-%m"), prev=prev.strftime("%Y-%m"), nxt=end.strftime("%Y-%m"),
        today=datetime.now().strftime("%Y-%m-%d"), rows=rows, total=total, cats_sum=cats_sum)


@app.post("/admin/api/expense")
def admin_expense_add():
    local_only(write=True)
    b = request.get_json(silent=True) or {}
    try:
        amount = int(b.get("amount"))
        day = datetime.strptime(str(b.get("day", "")), "%Y-%m-%d")
    except (TypeError, ValueError):
        return jsonify(ok=False, error="تاريخ أو مبلغ غير صالح"), 400
    cat = b.get("category") if b.get("category") in EXP_CATS else "أخرى"
    if not 1 <= amount <= 100_000_000:
        return jsonify(ok=False, error="المبلغ غير صالح"), 400
    today = datetime.now().strftime("%Y-%m-%d")
    ts = datetime.now().isoformat(timespec="seconds") if day.strftime("%Y-%m-%d") == today \
        else day.strftime("%Y-%m-%d") + "T12:00:00"
    ledger_exec("INSERT INTO expenses (ts, day, category, amount, note, from_till) VALUES (?,?,?,?,?,?)",
                (ts, day.strftime("%Y-%m-%d"), cat, amount, str(b.get("note", ""))[:80],
                 0 if b.get("from_till") is False else 1))
    return jsonify(ok=True)


@app.post("/admin/api/expense/<int:eid>/delete")
def admin_expense_delete(eid):
    local_only(write=True)
    ledger_exec("DELETE FROM expenses WHERE id = ?", (eid,))
    return jsonify(ok=True)


@app.get("/admin/stock")
def admin_stock():
    local_only()
    items = ledger_query("SELECT * FROM stock_items ORDER BY id")
    ready = {r["item_id"] for r in ledger_query("SELECT DISTINCT item_id FROM stock_moves")}
    for it in items:
        it["ready"] = it["id"] in ready
        it["low"] = it["ready"] and it["low_at"] > 0 and it["qty"] <= it["low_at"]
        ref = max(it["low_at"] * 4, it["qty"], 1)
        it["pct"] = max(0, min(100, round(it["qty"] / ref * 100)))
    moves = ledger_query("""SELECT m.ts, m.delta, m.reason, COALESCE(i.name, '(محذوف)') AS name
                            FROM stock_moves m LEFT JOIN stock_items i ON i.id = m.item_id
                            ORDER BY m.id DESC LIMIT 40""")
    return render_template_string(
        STOCK, shop=SHOP_NAME, title="المخزون", active="stock", cur=CURRENCY, items=items,
        low=[i for i in items if i["low"]], moves=moves, sizes=PAPER_SIZES)


@app.get("/admin/api/alerts")
def admin_alerts():
    local_only()
    return jsonify(low=len(low_items()), unclosed=cash_unclosed())


@app.post("/admin/api/stock/item")
def admin_stock_item():
    local_only(write=True)
    b = request.get_json(silent=True) or {}
    name = str(b.get("name", "")).strip()[:40]
    unit = str(b.get("unit", "")).strip()[:12] or "قطعة"
    size = b.get("size") if b.get("size") in PAPER_SIZES else ""
    try:
        qty, low = int(b.get("qty", 0)), int(b.get("low_at", 0))
    except (TypeError, ValueError):
        return jsonify(ok=False, error="كمية غير صالحة"), 400
    if not name:
        return jsonify(ok=False, error="اكتب اسم الصنف"), 400
    if ledger_query("SELECT id FROM stock_items WHERE name = ?", (name,)):
        return jsonify(ok=False, error="هذا الاسم موجود"), 400
    ledger_exec("INSERT INTO stock_items (name, unit, qty, low_at, size) VALUES (?,?,?,?,?)",
                (name, unit, 0, max(0, low), size))
    if qty:
        item = ledger_query("SELECT id FROM stock_items WHERE name = ?", (name,))[0]
        stock_move(item["id"], qty, "رصيد أولي")
    return jsonify(ok=True)


@app.post("/admin/api/stock/<int:iid>/<action>")
def admin_stock_action(iid, action):
    local_only(write=True)
    rows = ledger_query("SELECT * FROM stock_items WHERE id = ?", (iid,))
    if not rows:
        return jsonify(ok=False, error="الصنف غير موجود"), 404
    item = rows[0]
    b = request.get_json(silent=True) or {}
    try:
        if action == "add":
            qty, cost = int(b.get("qty")), int(b.get("cost") or 0)
            if not 1 <= qty <= 10_000_000 or not 0 <= cost <= 100_000_000:
                raise ValueError
            stock_move(iid, qty, "شراء / إضافة")
            if cost > 0:
                now = datetime.now()
                ledger_exec("INSERT INTO expenses (ts, day, category, amount, note) VALUES (?,?,?,?,?)",
                            (now.isoformat(timespec="seconds"), now.strftime("%Y-%m-%d"), "مخزون", cost,
                             f"شراء {qty} {item['unit']} - {item['name']}"))
        elif action == "set":
            target = int(b.get("qty"))
            if not -1_000_000 <= target <= 10_000_000:
                raise ValueError
            if target != item["qty"]:
                stock_move(iid, target - item["qty"], "جرد")
        elif action == "low":
            low = int(b.get("low_at"))
            if not 0 <= low <= 10_000_000:
                raise ValueError
            ledger_exec("UPDATE stock_items SET low_at = ? WHERE id = ?", (low, iid))
        elif action == "delete":
            ledger_exec("DELETE FROM stock_moves WHERE item_id = ?", (iid,))
            ledger_exec("DELETE FROM stock_items WHERE id = ?", (iid,))
        else:
            return jsonify(ok=False, error="أمر غير معروف"), 400
    except (TypeError, ValueError):
        return jsonify(ok=False, error="قيمة غير صالحة"), 400
    return jsonify(ok=True)


# ---------- صفحة الصندوق ----------
CASH = HEAD + """
  <div class="nav">
    <a href="/admin/cash?day={{ prev_day }}" aria-label="اليوم السابق">›</a>
    <form method="get" action="/admin/cash" style="margin:0">
      <input type="date" name="day" value="{{ day }}" onchange="this.form.submit()" aria-label="اليوم">
    </form>
    <a href="/admin/cash?day={{ next_day }}" aria-label="اليوم التالي">‹</a>
    <a href="/admin/cash">اليوم الحالي</a>
  </div>

  {% if close %}<div class="warn" style="border-color:var(--ok)">✓ أُغلق صندوق هذا اليوم الساعة {{ close.ts[11:16] }}. إذا تغيّر شيء بعدها فأعد الحساب وأكّد من جديد.</div>{% endif %}

  <div class="grid2">
    <section class="box">
      <h2>إغلاق الصندوق (نقدا)</h2>
      <table>
        <tr><td>رصيد البداية في الدرج</td>
            <td class="num"><input type="number" id="opening" value="{{ opening }}" min="0" inputmode="numeric" style="width:140px" oninput="upd()" aria-label="رصيد البداية"></td></tr>
        <tr><td>+ مبيعات قُبضت نقدا</td><td class="num">{{ d.cash_sales|money }}</td></tr>
        <tr><td>− مصاريف دُفعت من الصندوق</td><td class="num">{{ d.exp_till|money }}</td></tr>
        <tr><td>− سحوباتي الشخصية</td><td class="num">{{ d.drawings|money }}</td></tr>
        <tr><td><b>= المفروض أن يكون في الدرج</b></td><td class="num"><b id="exp">0</b></td></tr>
        <tr><td>المبلغ الذي عددته فعلا</td>
            <td class="num"><input type="number" id="counted" value="{{ close.counted if close else '' }}" min="0" inputmode="numeric" style="width:140px" oninput="upd()" aria-label="المبلغ المعدود"></td></tr>
        <tr><td><b>الفرق</b></td><td class="num"><b id="diff">—</b></td></tr>
      </table>
      <div class="frm" style="margin-top:12px">
        <input type="text" id="cnote" maxlength="120" placeholder="ملاحظة (اختياري)" value="{{ close.note if close else '' }}" style="flex:1;min-width:160px">
        <button class="p" onclick="closeDay()">تأكيد إغلاق اليوم</button>
      </div>
      <p class="muted" style="margin:10px 0 0">
        لا تدخل الصندوق: تحويلات وبريدي موب <b>{{ d.transfers|money }}</b> {{ cur }}
        • غير مدفوع اليوم <b>{{ d.unpaid|money }}</b> {{ cur }}
        • مصاريف خارج الصندوق <b>{{ d.exp_other|money }}</b> {{ cur }}
      </p>
    </section>

    <section class="box">
      <h2>سحوباتي الشخصية ({{ day }})</h2>
      <p class="muted" style="margin-top:0">ما تأخذه لنفسك من الصندوق. يُسجَّل منفصلا عن مصاريف المحل حتى لا يفسد حساب الربح.</p>
      <div class="frm">
        <div><label for="dkind">النوع</label>
          <select id="dkind">{% for k in kinds %}<option>{{ k }}</option>{% endfor %}</select></div>
        <div><label for="damt">المبلغ ({{ cur }})</label><input type="number" id="damt" min="1" inputmode="numeric" style="width:120px"></div>
        <div style="flex:1;min-width:120px"><label for="dnote">ملاحظة</label><input type="text" id="dnote" maxlength="80" style="width:100%"></div>
        <button class="p" onclick="addDraw()">تسجيل</button>
      </div>
      {% if draws %}<div class="scroll" style="margin-top:10px"><table>
        <tr><th>الوقت</th><th>النوع</th><th>ملاحظة</th><th class="num">المبلغ</th><th></th></tr>
        {% for r in draws %}<tr><td>{{ r.ts[11:16] }}</td><td>{{ r.kind }}</td><td>{{ r.note or '-' }}</td><td class="num">{{ r.amount|money }}</td>
          <td><button class="d" onclick="run('/admin/api/drawing/{{ r.id }}/delete', {}, 'حذف هذا السحب؟')">حذف</button></td></tr>{% endfor %}
      </table></div>{% else %}<div class="muted" style="margin-top:10px">لا توجد سحوبات في هذا اليوم.</div>{% endif %}
    </section>
  </div>

  <section class="box">
    <h2>سجل الإغلاقات (آخر 30 يوما)</h2>
    {% if hist %}<div class="scroll"><table>
      <tr><th>اليوم</th><th class="num">البداية</th><th class="num">المفروض</th><th class="num">المعدود</th><th class="num">الفرق</th><th class="num">سحوباتي</th><th>ملاحظة</th></tr>
      {% for r in hist %}<tr><td><a href="/admin/cash?day={{ r.day }}" style="color:var(--ink)">{{ r.day }}</a></td>
        <td class="num">{{ r.opening|money }}</td><td class="num">{{ r.expected|money }}</td><td class="num">{{ r.counted|money }}</td>
        <td class="num {{ 'good' if r.diff == 0 else 'bad' }}">{{ ('+' if r.diff > 0 else '') ~ (r.diff|money) }}</td>
        <td class="num">{{ r.drawings|money }}</td><td>{{ r.note or '-' }}</td></tr>{% endfor %}
    </table></div>{% else %}<div class="muted">لم تُغلق أي صندوق بعد.</div>{% endif %}
  </section>
""" + FOOT + """
const BASE = {{ base }};
const fmt = n => Number(n).toLocaleString("fr-FR");
function upd(){
  const exp = Number(document.getElementById("opening").value || 0) + BASE;
  document.getElementById("exp").textContent = fmt(exp);
  const c = document.getElementById("counted").value, el = document.getElementById("diff");
  if (c === "") { el.textContent = "—"; el.className = ""; return; }
  const diff = Number(c) - exp;
  el.textContent = "";
  if (diff === 0) { el.textContent = "مطابق ✓"; }
  else {
    el.append(diff > 0 ? "زيادة " : "عجز ");
    const num = document.createElement("span"); num.dir = "ltr";
    num.textContent = (diff > 0 ? "+" : "-") + fmt(Math.abs(diff));
    el.append(num);
  }
  el.className = diff === 0 ? "good" : "bad";
}
function closeDay(){
  const c = document.getElementById("counted").value;
  if (c === "") { toast("اكتب المبلغ الذي عددته"); return; }
  run("/admin/api/cash/close", {day: "{{ day }}", opening: Number(document.getElementById("opening").value || 0),
      counted: Number(c), note: document.getElementById("cnote").value});
}
function addDraw(){
  run("/admin/api/drawing", {day: "{{ day }}", kind: document.getElementById("dkind").value,
      amount: Number(document.getElementById("damt").value), note: document.getElementById("dnote").value});
}
upd();
</script></body></html>"""


@app.get("/admin/cash")
def admin_cash():
    local_only()
    dd = parse_day(request.args.get("day"))
    day = dd.strftime("%Y-%m-%d")
    d = day_cash(day)
    rows = ledger_query("SELECT * FROM cash_closes WHERE day = ?", (day,))
    close = rows[0] if rows else None
    if close:
        opening = close["opening"]
    else:
        last = ledger_query("SELECT counted FROM cash_closes WHERE day < ? ORDER BY day DESC LIMIT 1", (day,))
        opening = last[0]["counted"] if last else 0
    return render_template_string(
        CASH, shop=SHOP_NAME, title="الصندوق", active="cash", cur=CURRENCY, day=day,
        prev_day=(dd - timedelta(days=1)).strftime("%Y-%m-%d"), next_day=(dd + timedelta(days=1)).strftime("%Y-%m-%d"),
        d=d, close=close, opening=opening, base=d["cash_sales"] - d["exp_till"] - d["drawings"],
        draws=ledger_query("SELECT * FROM drawings WHERE day = ? ORDER BY id DESC", (day,)),
        kinds=DRAW_KINDS, hist=ledger_query("SELECT * FROM cash_closes ORDER BY day DESC LIMIT 30"))


@app.post("/admin/api/cash/close")
def admin_cash_close():
    local_only(write=True)
    b = request.get_json(silent=True) or {}
    try:
        day = datetime.strptime(str(b.get("day", "")), "%Y-%m-%d").strftime("%Y-%m-%d")
        opening, counted = int(b.get("opening")), int(b.get("counted"))
        if not (0 <= opening <= 10**9 and 0 <= counted <= 10**9):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify(ok=False, error="قيمة غير صالحة"), 400
    d = day_cash(day)          # نعيد الحساب في السيرفر ولا نثق بأرقام المتصفح
    expected = opening + d["cash_sales"] - d["exp_till"] - d["drawings"]
    ledger_exec("INSERT OR REPLACE INTO cash_closes VALUES (?,?,?,?,?,?,?,?,?,?)", (
        day, datetime.now().isoformat(timespec="seconds"), opening, d["cash_sales"], d["exp_till"],
        d["drawings"], expected, counted, counted - expected, str(b.get("note", ""))[:120]))
    return jsonify(ok=True)


@app.post("/admin/api/drawing")
def admin_drawing_add():
    local_only(write=True)
    b = request.get_json(silent=True) or {}
    try:
        day = datetime.strptime(str(b.get("day", "")), "%Y-%m-%d")
        amount = int(b.get("amount"))
        if not 1 <= amount <= 100_000_000:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify(ok=False, error="تاريخ أو مبلغ غير صالح"), 400
    kind = b.get("kind") if b.get("kind") in DRAW_KINDS else "أخرى"
    now = datetime.now()
    ts = now.isoformat(timespec="seconds") if day.strftime("%Y-%m-%d") == now.strftime("%Y-%m-%d") \
        else day.strftime("%Y-%m-%d") + "T12:00:00"
    ledger_exec("INSERT INTO drawings (ts, day, kind, amount, note) VALUES (?,?,?,?,?)",
                (ts, day.strftime("%Y-%m-%d"), kind, amount, str(b.get("note", ""))[:80]))
    return jsonify(ok=True)


@app.post("/admin/api/drawing/<int:did>/delete")
def admin_drawing_delete(did):
    local_only(write=True)
    ledger_exec("DELETE FROM drawings WHERE id = ?", (did,))
    return jsonify(ok=True)


@app.get("/admin/report")
def admin_report():
    local_only()
    rng, d, start, end, prev, nxt, rows = report_rows(request.args.get("range"), request.args.get("day"))
    tot = {
        "orders": len(rows),
        "printed": sum(r["printed"] for r in rows),
        "value": sum(r["price"] for r in rows),
        "paid": sum(r["price"] for r in rows if r["paid"]),
        "unpaid": sum(r["price"] for r in rows if not r["paid"]),
        "review": sum(1 for r in rows if not r["pages_known"]),
    }
    avg = round(tot["value"] / tot["orders"]) if tot["orders"] else 0

    def group(key):
        acc = {}
        for r in rows:
            g = acc.setdefault(r[key], [0, 0, 0])
            g[0] += 1
            g[1] += r["printed"]
            g[2] += r["price"]
        return sorted(acc.items(), key=lambda kv: -kv[1][2])

    counts = [0] * 24
    for r in rows:
        counts[int(r["ts"][11:13])] += 1
    top = max(counts) or 1
    hours = [(h, n, (round(n / top * 84) + 3) if n else 2) for h, n in enumerate(counts)]

    days = []
    if rng != "day":
        per = {}
        for r in rows:
            p = per.setdefault(r["day"], [0, 0])
            p[0] += 1
            p[1] += r["price"]
        biggest = max([v[1] for v in per.values()] or [1]) or 1
        cur = start
        while cur < end:
            k = cur.strftime("%Y-%m-%d")
            n, val = per.get(k, [0, 0])
            days.append((k[5:], n, val, round(val / biggest * 100)))
            cur += timedelta(days=1)

    debts = ledger_query("SELECT * FROM orders WHERE paid = 0 AND price > 0 ORDER BY ts DESC LIMIT 200")
    debts_total = ledger_query("SELECT COALESCE(SUM(price),0) AS t FROM orders WHERE paid = 0 AND price > 0")[0]["t"]
    exp_cats = [(r["category"], r["a"]) for r in ledger_query(
        "SELECT category, SUM(amount) AS a FROM expenses WHERE day >= ? AND day < ? GROUP BY category ORDER BY a DESC",
        (start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")))]
    exp_total = sum(v for _, v in exp_cats)
    net = tot["paid"] - exp_total
    draw_total = ledger_query("SELECT COALESCE(SUM(amount),0) AS v FROM drawings WHERE day >= ? AND day < ?",
                              (start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")))[0]["v"]
    left = net - draw_total
    title = {"day": d.strftime("%Y-%m-%d"),
             "week": f"{start.strftime('%Y-%m-%d')}  ←  {d.strftime('%Y-%m-%d')}",
             "month": start.strftime("%Y-%m")}[rng]
    return render_template_string(
        REPORT, shop=SHOP_NAME, cur=CURRENCY, rng=rng, day=d.strftime("%Y-%m-%d"),
        prev_day=prev.strftime("%Y-%m-%d"), next_day=nxt.strftime("%Y-%m-%d"), title=title,
        tot=tot, avg=avg, by_color=group("color"), by_size=group("size"), hours=hours, days=days,
        debts=debts, debts_total=debts_total, rows=rows, exp_cats=exp_cats, exp_total=exp_total, net=net, draw_total=draw_total, left=left)


def _csv_safe(v):
    v = str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


@app.get("/admin/report.csv")
def admin_report_csv():
    local_only()
    rng, d, start, end, prev, nxt, rows = report_rows(request.args.get("range"), request.args.get("day"))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["التاريخ", "الوقت", "الرمز", "الاسم", "عدد الملفات", "النسخ", "الورق", "اللون", "الوجه",
                "الصفحات", "القيمة (" + CURRENCY + ")", "مدفوع", "الحالة"])
    for r in rows:
        w.writerow([r["ts"][:10], r["ts"][11:16], r["code"], _csv_safe(r["name"] or ""), r["nfiles"],
                    r["copies"], r["size"], r["color"], r["sides"], r["pages"], r["price"],
                    "نعم" if r["paid"] else "لا", "تمّ" if r["status"] == "done" else "جديد"])
    name = f"report-{rng}-{d.strftime('%Y-%m-%d')}.csv"
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f"attachment; filename={name}"})


@app.post("/admin/api/order/<folder>/<action>")
def admin_action(folder, action):
    local_only(write=True)
    if not valid_folder(folder):
        return jsonify(ok=False, error="الطلب غير موجود"), 404
    path = os.path.join(UPLOAD_DIR, folder)
    order = read_order(folder)

    if action in ("done", "reopen") and order:
        order["status"] = "done" if action == "done" else "new"
        sync_stock(order, order["status"] == "done")
        write_order(folder, order)
        ledger_upsert(order)
    elif action == "delete":
        if order:
            sync_stock(order, False)
        shutil.rmtree(path, ignore_errors=True)
        ledger_delete(folder)
    elif action == "open":
        if not hasattr(os, "startfile"):
            return jsonify(ok=False, error="متاح على ويندوز فقط"), 400
        os.startfile(path)
    elif action == "print" and order:
        if not hasattr(os, "startfile"):
            return jsonify(ok=False, error="متاح على ويندوز فقط"), 400
        try:
            for fname in order["files"]:
                os.startfile(os.path.join(path, fname), "print")
        except OSError:
            return jsonify(ok=False, error="تعذّرت الطباعة، افتح الملف وطبعه يدويا"), 500
    else:
        return jsonify(ok=False, error="أمر غير معروف"), 400
    return jsonify(ok=True)


if __name__ == "__main__":
    print(f"\nالزبائن : http://<IP-هذا-الحاسوب>:{PORT}")
    print(f"المحل   : http://localhost:{PORT}/admin\n")
    app.run(host="0.0.0.0", port=PORT, threaded=True)
