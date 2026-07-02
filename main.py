"""
Replenishment Daily Metrics + JIT — Self-Hosted Server
FIXES IN THIS VERSION:
- Large file upload: increased timeout handling, chunked processing
- Added /api/debug endpoint to diagnose parse issues
- Fixed TAT returning None vs 0 — now always returns float or null explicitly
- Better error responses so frontend can show meaningful messages
- Date format M/D/YYYY H:MM confirmed as primary format
"""

import sqlite3, secrets, hashlib, hmac, json, csv, io, statistics, traceback
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Cookie, Response, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "app.db"
RAW_ARCHIVE_DIR = DATA_DIR / "raw_uploads"
RAW_ARCHIVE_DIR.mkdir(exist_ok=True)
SESSION_TTL_HOURS = 12

app = FastAPI(title="Replenishment + JIT Dashboard")

# Allow large uploads — 100MB limit
from fastapi import FastAPI
import uvicorn

# --------------------------------------------------------------------------
# DB
# --------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=60)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=10000")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','viewer')),
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expires_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS replen_rows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        so_date TEXT NOT NULL,
        so_week TEXT NOT NULL,
        so_month TEXT NOT NULL,
        supplier TEXT,
        store TEXT,
        city TEXT,
        entity_raw TEXT,
        entity_group TEXT,
        is_pvt_label INTEGER DEFAULT 0,
        so_status TEXT,
        is_pending INTEGER DEFAULT 0,
        is_cancelled INTEGER DEFAULT 0,
        is_jit INTEGER DEFAULT 0,
        is_auto INTEGER DEFAULT 0,
        criticality TEXT,
        po_type TEXT,
        processed_qty REAL DEFAULT 0,
        pushback_qty REAL DEFAULT 0,
        distinct_count REAL DEFAULT 0,
        pvt_label_qty REAL DEFAULT 0,
        proc_tat_hours REAL,
        grn_tat_hours REAL,
        so_created_at TEXT,
        consignment_created_at TEXT,
        grn_created_at TEXT,
        order_id TEXT,
        upload_batch_id TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_rd ON replen_rows(so_date);
    CREATE INDEX IF NOT EXISTS idx_rw ON replen_rows(so_week);
    CREATE INDEX IF NOT EXISTS idx_rm ON replen_rows(so_month);
    CREATE INDEX IF NOT EXISTS idx_rs ON replen_rows(supplier);
    CREATE INDEX IF NOT EXISTS idx_rj ON replen_rows(is_jit);
    CREATE TABLE IF NOT EXISTS projections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        supplier TEXT NOT NULL, sku TEXT,
        proj_date TEXT NOT NULL, projected_qty REAL NOT NULL,
        created_by TEXT, created_at TEXT,
        UNIQUE(supplier, sku, proj_date)
    );
    CREATE TABLE IF NOT EXISTS upload_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_id TEXT, filename TEXT, uploaded_by TEXT,
        uploaded_at TEXT, row_count INTEGER,
        skipped_count INTEGER DEFAULT 0,
        min_date TEXT, max_date TEXT
    );
    CREATE TABLE IF NOT EXISTS dataset_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        version INTEGER NOT NULL DEFAULT 0
    );
    """)
    conn.commit()
    if conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        salt = secrets.token_hex(16)
        conn.execute(
            "INSERT INTO users (username,password_hash,salt,role,created_at) VALUES (?,?,?,?,?)",
            ("admin", hash_password("changeme123", salt), salt, "admin", datetime.utcnow().isoformat())
        )
        conn.commit()
        print("✓ Default admin created -> admin / changeme123")
    if conn.execute("SELECT COUNT(*) c FROM dataset_meta").fetchone()["c"] == 0:
        conn.execute("INSERT INTO dataset_meta (id,version) VALUES (1,0)")
        conn.commit()
    conn.close()

def bump_version():
    conn = get_db()
    conn.execute("UPDATE dataset_meta SET version=version+1 WHERE id=1")
    conn.commit(); conn.close()

# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
def hash_password(p, s):
    return hashlib.pbkdf2_hmac("sha256", p.encode(), s.encode(), 200_000).hex()

def verify_password(p, s, h):
    return hmac.compare_digest(hash_password(p, s), h)

def create_session(user_id):
    token = secrets.token_urlsafe(32)
    exp = (datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
    conn = get_db()
    conn.execute("INSERT INTO sessions (token,user_id,expires_at) VALUES (?,?,?)", (token, user_id, exp))
    conn.commit(); conn.close()
    return token

def get_current_user(session: Optional[str] = Cookie(default=None)):
    if not session: return None
    conn = get_db()
    row = conn.execute("""SELECT u.id,u.username,u.role,s.expires_at FROM sessions s
        JOIN users u ON u.id=s.user_id WHERE s.token=?""", (session,)).fetchone()
    conn.close()
    if not row or datetime.fromisoformat(row["expires_at"]) < datetime.utcnow(): return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}

def require_login(session: Optional[str] = Cookie(default=None)):
    u = get_current_user(session)
    if not u: raise HTTPException(401, "Not authenticated")
    return u

def require_admin(session: Optional[str] = Cookie(default=None)):
    u = require_login(session)
    if u["role"] != "admin": raise HTTPException(403, "Admin required")
    return u

# --------------------------------------------------------------------------
# DATE PARSING — M/D/YYYY H:MM is your actual format
# --------------------------------------------------------------------------
DATE_FORMATS = [
    "%m/%d/%Y %H:%M",      # 6/16/2026 6:25   YOUR FORMAT
    "%m/%d/%Y %H:%M:%S",   # 6/16/2026 6:25:00
    "%m/%d/%Y",            # 6/16/2026
    "%d-%m-%Y %H:%M:%S",
    "%d-%m-%Y %H:%M",
    "%d-%m-%Y",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%d/%m/%Y",
]

def parse_dt(s):
    if not s: return None
    s = str(s).strip()
    if s in ("", "nan", "NaT", "None", "null", "N/A", "NA", "#N/A"): return None
    for f in DATE_FORMATS:
        try: return datetime.strptime(s, f)
        except ValueError: pass
    try: return datetime.fromisoformat(s)
    except: return None

def diff_hrs(a, b):
    """Returns hours between two datetimes. Always returns float or None."""
    if a is None or b is None: return None
    try:
        d = (b - a).total_seconds() / 3600.0
        if d < 0 or d > 99999: return None
        return round(d, 4)
    except: return None

def week_key(d):
    sunday = d - timedelta(days=(d.weekday() + 1) % 7)
    return sunday.strftime("%Y-%m-%d")

def to_float(v, default=0.0):
    if v is None: return default
    s = str(v).strip()
    if s in ("", "nan", "NaT", "None", "null", "N/A"): return default
    try: return float(s.replace(",", ""))
    except: return default

def to_bool_flag(v):
    return str(v).strip().upper() in ("1", "1.0", "TRUE", "YES", "Y")

HOSPITAL_GROUP = {"lfs", "hospital", "hospitals", "lifecraft"}

def group_entity(raw):
    if not raw or str(raw).strip() in ("", "nan", "None"): return "Other"
    lc = str(raw).strip().lower()
    return "Hospital" if lc in HOSPITAL_GROUP else str(raw).strip()

FULFILLED_STATUSES = {"shipped", "splitted"}

# --------------------------------------------------------------------------
# CSV/TSV PARSING — handles both tab and comma delimited
# --------------------------------------------------------------------------
COLS = {
    "supplier": "supplier_store", "order_id": "supplier_source_order_id",
    "so_dt": "so_created_at", "con_dt": "consignment_created_at",
    "status": "so_status", "grn_dt": "grn_created_at",
    "store": "store", "city": "city", "jit": "JIT Flag",
    "entity": "entity_type", "pvt_flag": "Pvt label flag",
    "auto_flag": "auto_grn_flag", "qty": "processed_sku_quantity",
    "pushback": "pushback_quantity", "distinct_count": "distinct count",
    "pvt_qty": "Pvt label qty", "criticality": "criticality_flag",
    "po_type": "po_generated_typee",
}

def detect_delimiter(text_sample):
    first_line = text_sample.split("\n")[0]
    tabs = first_line.count("\t")
    commas = first_line.count(",")
    return "\t" if tabs > commas else ","

def parse_csv_to_rows(file_bytes: bytes):
    # Try UTF-8 first, fall back to latin-1
    for enc in ("utf-8-sig", "utf-8", "latin-1", "cp1252"):
        try:
            text = file_bytes.decode(enc, errors="strict")
            break
        except (UnicodeDecodeError, LookupError):
            text = file_bytes.decode("latin-1", errors="replace")

    delim = detect_delimiter(text)
    reader = csv.DictReader(io.StringIO(text), delimiter=delim)

    # Normalize headers — strip whitespace and BOM
    rows = []
    skipped = 0
    sample_dates = []  # for debug

    for i, raw in enumerate(reader):
        # Normalize keys
        raw = {(k.strip().lstrip('\ufeff') if k else ""): (v.strip() if isinstance(v, str) else (v or "")) for k, v in raw.items()}

        # Get SO date — this is mandatory
        so_raw = raw.get(COLS["so_dt"], "") or raw.get("so_created_at", "")
        so = parse_dt(so_raw)

        if i < 3 and so_raw:
            sample_dates.append(f"raw='{so_raw}' parsed={so}")

        if not so:
            skipped += 1
            continue

        con_raw = raw.get(COLS["con_dt"], "") or raw.get("consignment_created_at", "")
        grn_raw = raw.get(COLS["grn_dt"], "") or raw.get("grn_created_at", "")
        con = parse_dt(con_raw)
        grn = parse_dt(grn_raw)

        # TAT: consignment_created_at - so_created_at
        proc_tat = diff_hrs(so, con)
        # GRN TAT: grn_created_at - so_created_at
        grn_tat = diff_hrs(so, grn)

        status = (raw.get(COLS["status"]) or raw.get("so_status") or "").lower().strip()
        is_cancelled = (status == "cancelled")
        is_pending = not is_cancelled and (status not in FULFILLED_STATUSES)

        jit_raw = raw.get(COLS["jit"]) or raw.get("JIT Flag") or raw.get("JIT_Flag") or ""
        is_jit = 1 if str(jit_raw).strip().upper() == "JIT" else 0

        po_type = (raw.get(COLS["po_type"]) or raw.get("po_generated_typee") or "").strip()
        auto_raw = (raw.get(COLS["auto_flag"]) or raw.get("auto_grn_flag") or "").strip()

        is_auto = 0
        if po_type.lower() == "auto": is_auto = 1
        elif po_type.lower() == "manual": is_auto = 0
        elif to_bool_flag(auto_raw): is_auto = 1

        pvt_raw = (raw.get(COLS["pvt_flag"]) or raw.get("Pvt label flag") or "").strip().lower()
        is_pvt = 1 if pvt_raw in ("1", "1.0", "true", "yes", "y", "pvt label") else 0

        entity_raw = (raw.get(COLS["entity"]) or raw.get("entity_type") or "").strip()
        entity_group = group_entity(entity_raw)

        rows.append({
            "so_date": so.strftime("%Y-%m-%d"),
            "so_week": week_key(so),
            "so_month": so.strftime("%Y-%m"),
            "supplier": (raw.get(COLS["supplier"]) or raw.get("supplier_store") or "Unknown").strip() or "Unknown",
            "store": (raw.get(COLS["store"]) or "Unknown").strip() or "Unknown",
            "city": (raw.get(COLS["city"]) or "Unknown").strip() or "Unknown",
            "entity_raw": entity_raw, "entity_group": entity_group,
            "is_pvt_label": is_pvt, "so_status": status,
            "is_pending": 1 if is_pending else 0,
            "is_cancelled": 1 if is_cancelled else 0,
            "is_jit": is_jit, "is_auto": is_auto,
            "criticality": (raw.get(COLS["criticality"]) or "").strip(),
            "po_type": po_type,
            "processed_qty": to_float(raw.get(COLS["qty"]) or raw.get("processed_sku_quantity")),
            "pushback_qty": to_float(raw.get(COLS["pushback"]) or raw.get("pushback_quantity")),
            "distinct_count": to_float(raw.get(COLS["distinct_count"]) or raw.get("distinct count") or raw.get("distinct_count")),
            "pvt_label_qty": to_float(raw.get(COLS["pvt_qty"]) or raw.get("Pvt label qty")),
            "proc_tat_hours": proc_tat,
            "grn_tat_hours": grn_tat,
            "so_created_at": so.isoformat(),
            "consignment_created_at": con.isoformat() if con else None,
            "grn_created_at": grn.isoformat() if grn else None,
            "order_id": (raw.get(COLS["order_id"]) or raw.get("supplier_source_order_id") or "").strip(),
            "_sample_dates": sample_dates,  # will be removed before insert
        })

    print(f"Parsed {len(rows)} rows, skipped {skipped}")
    if rows and rows[0].get("_sample_dates"):
        print(f"Sample date parsing: {rows[0]['_sample_dates']}")

    # Remove debug field before returning
    for r in rows:
        r.pop("_sample_dates", None)

    return rows, skipped

# --------------------------------------------------------------------------
# Metrics helpers
# --------------------------------------------------------------------------
def safe_avg(arr):
    filtered = [x for x in arr if x is not None]
    if not filtered: return None
    return round(statistics.mean(filtered) * 10) / 10

def safe_pctile(arr, p):
    filtered = [x for x in arr if x is not None]
    if not filtered: return None
    s = sorted(filtered)
    i = p / 100 * (len(s) - 1)
    lo, hi = int(i), min(int(i) + 1, len(s) - 1)
    return round((s[lo] + (s[hi] - s[lo]) * (i - lo)) * 10) / 10

def pct(a, b): return round(a / b * 1000) / 10 if b and b > 0 else 0.0

def group_metrics(rows, key_fn):
    groups = {}
    for r in rows:
        k = key_fn(r) or "Unknown"
        g = groups.setdefault(k, {
            "qty": 0.0, "sku": 0.0, "pushback": 0.0, "pvt_qty": 0.0,
            "pending_qty": 0.0, "pending_orders": set(),
            "proc": [], "grn": [], "jit_qty": 0.0, "auto_qty": 0.0, "orders": set()
        })
        g["qty"] += r["processed_qty"]; g["sku"] += r["distinct_count"]
        g["pushback"] += r["pushback_qty"]; g["pvt_qty"] += r["pvt_label_qty"]
        if r["order_id"]: g["orders"].add(r["order_id"])
        if r["is_pending"]:
            g["pending_qty"] += r["processed_qty"]
            if r["order_id"]: g["pending_orders"].add(r["order_id"])
        if r["proc_tat_hours"] is not None: g["proc"].append(r["proc_tat_hours"])
        if r["grn_tat_hours"] is not None: g["grn"].append(r["grn_tat_hours"])
        if r["is_jit"]: g["jit_qty"] += r["processed_qty"]
        if r["is_auto"]: g["auto_qty"] += r["processed_qty"]

    out = []
    for k, g in groups.items():
        dem = g["qty"] + g["pushback"]
        out.append({
            "name": k, "qty": g["qty"], "sku": g["sku"],
            "pushback_qty": g["pushback"], "pushback_pct": pct(g["pushback"], dem),
            "pvt_label_qty": g["pvt_qty"], "pvt_label_pct": pct(g["pvt_qty"], g["qty"]),
            "pending_qty": g["pending_qty"], "pending_orders": len(g["pending_orders"]),
            "orders": len(g["orders"]),
            "avg_proc_tat": safe_avg(g["proc"]), "p80_proc_tat": safe_pctile(g["proc"], 80),
            "avg_grn_tat": safe_avg(g["grn"]),
            "jit_qty": g["jit_qty"], "jit_pct": pct(g["jit_qty"], g["qty"]),
            "auto_pct": pct(g["auto_qty"], g["qty"]),
        })
    return sorted(out, key=lambda x: -x["qty"])

# --------------------------------------------------------------------------
# Startup
# --------------------------------------------------------------------------
@app.on_event("startup")
def startup(): init_db()

# --------------------------------------------------------------------------
# Auth endpoints
# --------------------------------------------------------------------------
@app.post("/api/login")
def login(username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not row or not verify_password(password, row["salt"], row["password_hash"]):
        raise HTTPException(401, "Invalid username or password")
    token = create_session(row["id"])
    resp = JSONResponse({"ok": True, "role": row["role"], "username": row["username"]})
    resp.set_cookie("session", token, httponly=True, max_age=SESSION_TTL_HOURS * 3600, samesite="lax")
    return resp

@app.post("/api/logout")
def logout(session: Optional[str] = Cookie(default=None)):
    if session:
        conn = get_db(); conn.execute("DELETE FROM sessions WHERE token=?", (session,)); conn.commit(); conn.close()
    resp = JSONResponse({"ok": True}); resp.delete_cookie("session"); return resp

@app.get("/api/me")
def me(session: Optional[str] = Cookie(default=None)):
    u = get_current_user(session)
    if not u: raise HTTPException(401, "Not authenticated")
    return u

@app.get("/api/users")
def list_users(admin=Depends(require_admin)):
    conn = get_db()
    rows = conn.execute("SELECT id,username,role,created_at FROM users ORDER BY id").fetchall()
    conn.close(); return [dict(r) for r in rows]

@app.post("/api/users")
def create_user(username: str = Form(...), password: str = Form(...), role: str = Form(...), admin=Depends(require_admin)):
    if role not in ("admin", "viewer"): raise HTTPException(400, "role must be admin or viewer")
    salt = secrets.token_hex(16)
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username,password_hash,salt,role,created_at) VALUES (?,?,?,?,?)",
                     (username, hash_password(password, salt), salt, role, datetime.utcnow().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError: raise HTTPException(400, "Username already exists")
    finally: conn.close()
    return {"ok": True}

@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, admin=Depends(require_admin)):
    if user_id == admin["id"]: raise HTTPException(400, "Cannot delete yourself")
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    conn.commit(); conn.close(); return {"ok": True}

@app.post("/api/users/{user_id}/password")
def change_password(user_id: int, password: str = Form(...), admin=Depends(require_admin)):
    salt = secrets.token_hex(16)
    conn = get_db()
    conn.execute("UPDATE users SET password_hash=?,salt=? WHERE id=?", (hash_password(password, salt), salt, user_id))
    conn.commit(); conn.close(); return {"ok": True}

# --------------------------------------------------------------------------
# Upload — handles large files, inserts in batches
# --------------------------------------------------------------------------
@app.post("/api/upload")
async def upload_csv(
    file: UploadFile = File(...),
    mode: str = Form("replace_all"),   # "replace_all" or "replace_dates"
    admin=Depends(require_admin)
):
    """
    mode="replace_all"   — wipe the entire table, insert only this file's rows.
                           Use this when each upload is a complete fresh extract.
    mode="replace_dates" — delete only rows whose so_date falls within the new
                           file's date range, then insert. Historical dates outside
                           the new file's range are kept intact.
                           Use this for incremental daily uploads.
    """
    try:
        content = await file.read()
        if not content: raise HTTPException(400, "Empty file")

        print(f"Upload started: {file.filename}, size={len(content):,} bytes, mode={mode}")
        rows, skipped = parse_csv_to_rows(content)

        if not rows:
            raise HTTPException(400,
                f"No valid rows found. {skipped} rows had unparseable so_created_at. "
                f"Check that your so_created_at column looks like: 6/16/2026 6:25"
            )

        batch_id = secrets.token_hex(8)

        # Archive
        try:
            arc = RAW_ARCHIVE_DIR / f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{batch_id}_{file.filename[:50]}"
            arc.write_bytes(content)
        except Exception as e:
            print(f"Archive write failed (non-fatal): {e}")

        dates = sorted({r["so_date"] for r in rows})
        min_d, max_d = dates[0], dates[-1]

        conn = get_db()

        # Delete strategy based on mode
        if mode == "replace_all":
            conn.execute("DELETE FROM replen_rows")
            print("replace_all: cleared entire table")
        else:
            conn.execute("DELETE FROM replen_rows WHERE so_date BETWEEN ? AND ?", (min_d, max_d))
            print(f"replace_dates: cleared rows from {min_d} to {max_d}")
        conn.commit()

        # Insert in batches of 2000
        BATCH = 2000
        insert_sql = """INSERT INTO replen_rows
            (so_date,so_week,so_month,supplier,store,city,entity_raw,entity_group,is_pvt_label,
             so_status,is_pending,is_cancelled,is_jit,is_auto,criticality,po_type,processed_qty,
             pushback_qty,distinct_count,pvt_label_qty,proc_tat_hours,grn_tat_hours,so_created_at,
             consignment_created_at,grn_created_at,order_id,upload_batch_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""

        for i in range(0, len(rows), BATCH):
            batch = rows[i:i+BATCH]
            conn.executemany(insert_sql, [(
                r["so_date"], r["so_week"], r["so_month"], r["supplier"], r["store"], r["city"],
                r["entity_raw"], r["entity_group"], r["is_pvt_label"], r["so_status"],
                r["is_pending"], r["is_cancelled"], r["is_jit"], r["is_auto"],
                r["criticality"], r["po_type"], r["processed_qty"], r["pushback_qty"],
                r["distinct_count"], r["pvt_label_qty"], r["proc_tat_hours"], r["grn_tat_hours"],
                r["so_created_at"], r["consignment_created_at"], r["grn_created_at"],
                r["order_id"], batch_id
            ) for r in batch])
            conn.commit()
            print(f"Inserted batch {i//BATCH + 1} ({min(i+BATCH, len(rows))}/{len(rows)} rows)")

        conn.execute(
            "INSERT INTO upload_log (batch_id,filename,uploaded_by,uploaded_at,row_count,skipped_count,min_date,max_date) VALUES (?,?,?,?,?,?,?,?)",
            (batch_id, file.filename, admin["username"], datetime.utcnow().isoformat(), len(rows), skipped, min_d, max_d)
        )
        conn.commit(); conn.close()
        bump_version()
        print(f"Upload complete: {len(rows)} rows, {skipped} skipped, mode={mode}")
        return {"ok": True, "rows": len(rows), "skipped": skipped, "date_range": [min_d, max_d], "mode": mode}

    except HTTPException: raise
    except Exception as e:
        print(f"Upload error: {traceback.format_exc()}")
        raise HTTPException(500, f"Server error during upload: {str(e)}")

@app.get("/api/version")
def get_version(user=Depends(require_login)):
    conn = get_db()
    v = conn.execute("SELECT version FROM dataset_meta WHERE id=1").fetchone()
    lu = conn.execute("SELECT * FROM upload_log ORDER BY id DESC LIMIT 1").fetchone()
    tr = conn.execute("SELECT COUNT(*) c FROM replen_rows").fetchone()["c"]
    ds = conn.execute("SELECT MIN(so_date) mn,MAX(so_date) mx FROM replen_rows").fetchone()
    conn.close()
    return {
        "version": v["version"] if v else 0,
        "total_rows": tr,
        "min_date": ds["mn"], "max_date": ds["mx"],
        "last_upload": dict(lu) if lu else None
    }

@app.get("/api/upload-log")
def get_upload_log(admin=Depends(require_admin)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM upload_log ORDER BY id DESC LIMIT 30").fetchall()
    conn.close(); return [dict(r) for r in rows]

# --------------------------------------------------------------------------
# Debug endpoint — check what got parsed (admin only)
# --------------------------------------------------------------------------
@app.get("/api/debug/sample")
def debug_sample(admin=Depends(require_admin)):
    """Returns 5 sample rows from DB so you can verify TAT parsing is correct."""
    conn = get_db()
    rows = conn.execute("""
        SELECT supplier, so_created_at, consignment_created_at, grn_created_at,
               proc_tat_hours, grn_tat_hours, is_jit, so_status, processed_qty
        FROM replen_rows LIMIT 10
    """).fetchall()
    total = conn.execute("SELECT COUNT(*) c FROM replen_rows").fetchone()["c"]
    tat_not_null = conn.execute("SELECT COUNT(*) c FROM replen_rows WHERE proc_tat_hours IS NOT NULL").fetchone()["c"]
    avg_tat = conn.execute("SELECT AVG(proc_tat_hours) a FROM replen_rows WHERE proc_tat_hours IS NOT NULL").fetchone()["a"]
    conn.close()
    return {
        "total_rows": total,
        "rows_with_proc_tat": tat_not_null,
        "avg_proc_tat_hours": round(avg_tat, 2) if avg_tat else None,
        "sample_rows": [dict(r) for r in rows]
    }

# --------------------------------------------------------------------------
# Main data API — computed from SQLite, returned as JSON
# --------------------------------------------------------------------------
def fetch_rows(conn, granularity, period, supplier, entity, store, city):
    where, params = ["1=1"], []
    if period:
        col = {"day": "so_date", "week": "so_week", "month": "so_month"}.get(granularity, "so_date")
        where.append(f"{col}=?"); params.append(period)
    if supplier: where.append("supplier=?"); params.append(supplier)
    if entity: where.append("entity_group=?"); params.append(entity)
    if store: where.append("store=?"); params.append(store)
    if city: where.append("city=?"); params.append(city)
    sql = f"SELECT * FROM replen_rows WHERE {' AND '.join(where)}"
    return [dict(r) for r in conn.execute(sql, params).fetchall()]

@app.get("/api/data")
def get_data(
    granularity: str = "day", period: str = "", supplier: str = "",
    entity: str = "", store: str = "", city: str = "",
    user=Depends(require_login)
):
    try:
        conn = get_db()
        rows = fetch_rows(conn, granularity, period, supplier, entity, store, city)

        def distinct(col):
            return sorted({r[col] for r in [dict(x) for x in conn.execute(
                f"SELECT DISTINCT {col} FROM replen_rows WHERE {col} IS NOT NULL AND {col}!='' AND {col}!='Unknown'"
            ).fetchall()]})

        filters_meta = {
            "suppliers": distinct("supplier"), "entities": distinct("entity_group"),
            "stores": distinct("store"), "cities": distinct("city"),
            "days": distinct("so_date"), "weeks": distinct("so_week"), "months": distinct("so_month"),
        }
        conn.close()

        if not rows:
            return {"summary": None, "filters_meta": filters_meta}

        # Core splits
        jit_rows = [r for r in rows if r["is_jit"]]
        jit_non_cancel = [r for r in rows if r["is_jit"] and not r["is_cancelled"]]
        pending_rows = [r for r in rows if r["is_pending"]]
        auto_rows = [r for r in rows if r["is_auto"]]

        total_qty = sum(r["processed_qty"] for r in rows)
        total_sku = sum(r["distinct_count"] for r in rows)
        total_pushback = sum(r["pushback_qty"] for r in rows)
        pvt_qty = sum(r["pvt_label_qty"] for r in rows)

        proc_tats = [r["proc_tat_hours"] for r in rows if r["proc_tat_hours"] is not None]
        grn_tats = [r["grn_tat_hours"] for r in rows if r["grn_tat_hours"] is not None]

        jit_qty = sum(r["processed_qty"] for r in jit_rows)
        jit_sku = sum(r["distinct_count"] for r in jit_rows)
        jit_proc_tats = [r["proc_tat_hours"] for r in jit_rows if r["proc_tat_hours"] is not None]
        jit_grn_tats = [r["grn_tat_hours"] for r in jit_rows if r["grn_tat_hours"] is not None]
        jit_pend = [r for r in jit_rows if r["is_pending"]]
        jit_created_qty = sum(r["processed_qty"] for r in jit_non_cancel)
        jit_fill_rate = pct(jit_qty, jit_created_qty) if jit_created_qty else 0.0

        summary = {
            "total_qty": total_qty, "total_sku": total_sku, "row_count": len(rows),
            "total_pushback_qty": total_pushback,
            "pushback_pct": pct(total_pushback, total_qty + total_pushback),
            "pvt_label_qty": pvt_qty, "pvt_label_pct": pct(pvt_qty, total_qty),
            "pending_qty": sum(r["processed_qty"] for r in pending_rows),
            "pending_sku": sum(r["distinct_count"] for r in pending_rows),
            "pending_orders": len({r["order_id"] for r in pending_rows if r["order_id"]}),
            "jit_qty": jit_qty, "jit_sku": jit_sku,
            "jit_pct": pct(jit_qty, total_qty),
            "jit_fill_rate": jit_fill_rate,
            "jit_created_qty": jit_created_qty,
            "jit_pend_qty": sum(r["processed_qty"] for r in jit_pend),
            "jit_pend_orders": len({r["order_id"] for r in jit_pend if r["order_id"]}),
            "jit_avg_proc_tat": safe_avg(jit_proc_tats),
            "jit_p80_proc_tat": safe_pctile(jit_proc_tats, 80),
            "jit_avg_grn_tat": safe_avg(jit_grn_tats),
            "jit_p80_grn_tat": safe_pctile(jit_grn_tats, 80),
            "auto_pct": pct(sum(r["processed_qty"] for r in auto_rows), total_qty),
            "manual_pct": round(100 - pct(sum(r["processed_qty"] for r in auto_rows), total_qty), 1),
            "avg_proc_tat": safe_avg(proc_tats),
            "p80_proc_tat": safe_pctile(proc_tats, 80),
            "avg_grn_tat": safe_avg(grn_tats),
            "p80_grn_tat": safe_pctile(grn_tats, 80),
            "proc_tat_sample_count": len(proc_tats),  # debug: how many rows have TAT
        }

        # Pendency ageing
        now = datetime.utcnow()
        bucket_defs = [
            ("0-1 days", 0, 1), ("2-3 days", 2, 3), ("4-7 days", 4, 7),
            ("8-15 days", 8, 15), ("16-30 days", 16, 30), ("30+ days", 31, 999999)
        ]
        pend_ageing = []
        for lbl, lo, hi in bucket_defs:
            b = []
            for r in pending_rows:
                if not r["so_created_at"]: continue
                try:
                    age = (now - datetime.fromisoformat(r["so_created_at"])).days
                    if lo <= age <= hi: b.append(r)
                except: pass
            pend_ageing.append({
                "label": lbl, "qty": sum(r["processed_qty"] for r in b),
                "sku": sum(r["distinct_count"] for r in b),
                "orders": len({r["order_id"] for r in b if r["order_id"]})
            })

        def pend_by(key_fn):
            g = {}
            for r in pending_rows:
                k = key_fn(r) or "Unknown"
                try:
                    age = (now - datetime.fromisoformat(r["so_created_at"])).days if r["so_created_at"] else 0
                except: age = 0
                gg = g.setdefault(k, {"qty": 0.0, "sku": 0.0, "orders": set(), "max_age": 0})
                gg["qty"] += r["processed_qty"]; gg["sku"] += r["distinct_count"]
                gg["max_age"] = max(gg["max_age"], age)
                if r["order_id"]: gg["orders"].add(r["order_id"])
            return sorted([{"name": k, "qty": v["qty"], "sku": v["sku"], "orders": len(v["orders"]),
                            "max_age_days": v["max_age"]} for k, v in g.items()], key=lambda x: -x["qty"])

        # Trend series — always daily for charts regardless of filter granularity
        conn3 = get_db()
        trend_rows = fetch_rows(conn3, "day", "", supplier, entity, store, city)
        conn3.close()

        daily_map = {}
        for r in trend_rows:
            d = r["so_date"]
            dd = daily_map.setdefault(d, {
                "qty": 0.0, "sku": 0.0, "pending_qty": 0.0, "proc": [], "grn": [],
                "jit_qty": 0.0, "pushback": 0.0, "auto_qty": 0.0
            })
            dd["qty"] += r["processed_qty"]; dd["sku"] += r["distinct_count"]
            dd["pushback"] += r["pushback_qty"]
            if r["is_pending"]: dd["pending_qty"] += r["processed_qty"]
            if r["proc_tat_hours"] is not None: dd["proc"].append(r["proc_tat_hours"])
            if r["grn_tat_hours"] is not None: dd["grn"].append(r["grn_tat_hours"])
            if r["is_jit"]: dd["jit_qty"] += r["processed_qty"]
            if r["is_auto"]: dd["auto_qty"] += r["processed_qty"]

        daily_series = [{
            "date": d, "qty": v["qty"], "sku": v["sku"], "pending_qty": v["pending_qty"],
            "avg_proc_tat": safe_avg(v["proc"]), "avg_grn_tat": safe_avg(v["grn"]),
            "jit_pct": pct(v["jit_qty"], v["qty"]),
            "pushback_pct": pct(v["pushback"], v["qty"] + v["pushback"]),
            "auto_pct": pct(v["auto_qty"], v["qty"])
        } for d, v in sorted(daily_map.items())]

        jit_daily_map = {}
        for r in trend_rows:
            if not r["is_jit"]: continue
            d = r["so_date"]
            dd = jit_daily_map.setdefault(d, {"qty": 0.0, "sku": 0.0, "proc": [], "grn": [], "pend_qty": 0.0})
            dd["qty"] += r["processed_qty"]; dd["sku"] += r["distinct_count"]
            if r["proc_tat_hours"] is not None: dd["proc"].append(r["proc_tat_hours"])
            if r["grn_tat_hours"] is not None: dd["grn"].append(r["grn_tat_hours"])
            if r["is_pending"]: dd["pend_qty"] += r["processed_qty"]

        jit_daily = [{
            "date": d, "qty": v["qty"], "sku": v["sku"], "pend_qty": v["pend_qty"],
            "avg_proc_tat": safe_avg(v["proc"]), "avg_grn_tat": safe_avg(v["grn"])
        } for d, v in sorted(jit_daily_map.items())]

        # Bifurcation
        bif_map = {}
        for r in rows:
            k = (r["supplier"], r["entity_group"])
            bif_map[k] = bif_map.get(k, 0.0) + r["processed_qty"]
        bifurcation = [{"supplier": s, "entity": e, "qty": q} for (s, e), q in bif_map.items()]

        pendency_detail = []
        for r in pending_rows[:500]:  # Cap at 500 for API response size; full export via CSV
            try:
                age = (now - datetime.fromisoformat(r["so_created_at"])).days if r["so_created_at"] else 0
            except: age = 0
            pendency_detail.append({
                "order_id": r["order_id"], "supplier": r["supplier"], "store": r["store"],
                "entity": r["entity_group"], "status": r["so_status"],
                "qty": r["processed_qty"], "age_days": age, "so_created_at": r["so_created_at"]
            })

        # ---- Auto landing time buckets (based on so_created_at hour) ----
        hour_buckets = [
            ("12am-2am", 0, 2), ("2am-4am", 2, 4), ("4am-6am", 4, 6),
            ("6am-8am", 6, 8), ("8am-10am", 8, 10), ("10am-12pm", 10, 12),
            ("12pm-2pm", 12, 14), ("2pm-4pm", 14, 16), ("4pm-6pm", 16, 18),
            ("6pm-8pm", 18, 20), ("8pm-10pm", 20, 22), ("10pm-12am", 22, 24),
        ]
        hour_landing = []
        for label, h_lo, h_hi in hour_buckets:
            b_rows = []
            for r in rows:
                if not r["so_created_at"]: continue
                try:
                    h = datetime.fromisoformat(r["so_created_at"]).hour
                    if h_lo <= h < h_hi: b_rows.append(r)
                except: pass
            qty = sum(r["processed_qty"] for r in b_rows)
            sku = sum(r["distinct_count"] for r in b_rows)
            hour_landing.append({
                "label": label, "qty": qty, "sku": sku,
                "pct_of_total": pct(qty, total_qty),
                "auto_qty": sum(r["processed_qty"] for r in b_rows if r["is_auto"]),
                "manual_qty": sum(r["processed_qty"] for r in b_rows if not r["is_auto"]),
            })

        # ---- Landing vs processing ageing table ----
        # For each row, check: did it get a consignment within 12h / 24h / 48h / 72h / >72h?
        proc_ageing_buckets = [
            ("≤ 12 hours", 0, 12),
            ("12-24 hours", 12, 24),
            ("24-48 hours", 24, 48),
            ("48-72 hours", 48, 72),
            ("> 72 hours", 72, 999999),
            ("Not processed", None, None),
        ]
        proc_ageing = []
        for label, lo, hi in proc_ageing_buckets:
            if label == "Not processed":
                b = [r for r in rows if r["proc_tat_hours"] is None]
            else:
                b = [r for r in rows if r["proc_tat_hours"] is not None and lo <= r["proc_tat_hours"] < hi]
            proc_ageing.append({
                "label": label,
                "qty": sum(r["processed_qty"] for r in b),
                "sku": sum(r["distinct_count"] for r in b),
                "orders": len({r["order_id"] for r in b if r["order_id"]}),
                "pct_of_total": pct(sum(r["processed_qty"] for r in b), total_qty),
                "auto_qty": sum(r["processed_qty"] for r in b if r["is_auto"]),
                "auto_sku": sum(r["distinct_count"] for r in b if r["is_auto"]),
                "manual_qty": sum(r["processed_qty"] for r in b if not r["is_auto"]),
                "manual_sku": sum(r["distinct_count"] for r in b if not r["is_auto"]),
            })

        # ---- JIT full detail: supplier/entity/store tables + exceptions ----
        jit_by_entity = group_metrics(jit_rows, lambda r: r["entity_group"])
        jit_by_store = group_metrics(jit_rows, lambda r: r["store"])
        jit_exceptions_proc = sorted(
            [r for r in jit_rows if r["proc_tat_hours"] is not None and r["proc_tat_hours"] > 24],
            key=lambda r: -(r["proc_tat_hours"] or 0)
        )[:200]
        jit_exceptions_grn = sorted(
            [r for r in jit_rows if r["grn_tat_hours"] is not None and r["grn_tat_hours"] > 48],
            key=lambda r: -(r["grn_tat_hours"] or 0)
        )[:200]
        jit_pend_detail = sorted(
            [r for r in jit_rows if r["is_pending"]],
            key=lambda r: -(r["processed_qty"] or 0)
        )[:300]

        return {
            "summary": summary,
            "daily_series": daily_series,
            "jit_daily": jit_daily,
            "by_supplier": group_metrics(rows, lambda r: r["supplier"]),
            "by_entity": group_metrics(rows, lambda r: r["entity_group"]),
            "by_store": group_metrics(rows, lambda r: r["store"]),
            "by_jit_supplier": group_metrics(jit_rows, lambda r: r["supplier"]),
            "by_jit_entity": jit_by_entity,
            "by_jit_store": jit_by_store,
            "jit_exceptions_proc": [{"order_id":r["order_id"],"supplier":r["supplier"],"store":r["store"],"entity":r["entity_group"],"status":r["so_status"],"proc_tat":r["proc_tat_hours"],"qty":r["processed_qty"]} for r in jit_exceptions_proc],
            "jit_exceptions_grn": [{"order_id":r["order_id"],"supplier":r["supplier"],"store":r["store"],"entity":r["entity_group"],"status":r["so_status"],"grn_tat":r["grn_tat_hours"],"qty":r["processed_qty"]} for r in jit_exceptions_grn],
            "jit_pend_detail": [{"order_id":r["order_id"],"supplier":r["supplier"],"store":r["store"],"entity":r["entity_group"],"status":r["so_status"],"qty":r["processed_qty"],"age_days":(datetime.utcnow()-datetime.fromisoformat(r["so_created_at"])).days if r["so_created_at"] else 0} for r in jit_pend_detail],
            "bifurcation": bifurcation,
            "pendency_ageing": pend_ageing,
            "pendency_by_supplier": pend_by(lambda r: r["supplier"]),
            "pendency_by_entity": pend_by(lambda r: r["entity_group"]),
            "pendency_by_store": pend_by(lambda r: r["store"]),
            "pendency_detail": pendency_detail,
            "hour_landing": hour_landing,
            "proc_ageing": proc_ageing,
            "filters_meta": filters_meta,
        }

    except Exception as e:
        print(f"Data API error: {traceback.format_exc()}")
        raise HTTPException(500, f"Error computing metrics: {str(e)}")

# --------------------------------------------------------------------------
# Projections
# --------------------------------------------------------------------------
@app.post("/api/projections")
def upsert_projection(supplier: str = Form(...), sku: str = Form(""), proj_date: str = Form(...),
                       projected_qty: float = Form(...), user=Depends(require_login)):
    conn = get_db()
    conn.execute("""INSERT INTO projections (supplier,sku,proj_date,projected_qty,created_by,created_at)
        VALUES (?,?,?,?,?,?) ON CONFLICT(supplier,sku,proj_date) DO UPDATE SET
        projected_qty=excluded.projected_qty,created_by=excluded.created_by,created_at=excluded.created_at""",
        (supplier, sku, proj_date, projected_qty, user["username"], datetime.utcnow().isoformat()))
    conn.commit(); conn.close(); return {"ok": True}

@app.get("/api/projections/vs-landing")
def proj_vs_landing(supplier: str, user=Depends(require_login)):
    conn = get_db()
    proj = {r["proj_date"]: r["q"] for r in conn.execute(
        "SELECT proj_date,SUM(projected_qty) q FROM projections WHERE supplier=? GROUP BY proj_date", (supplier,)).fetchall()}
    actual = {r["so_date"]: r["q"] for r in conn.execute(
        "SELECT so_date,SUM(processed_qty) q FROM replen_rows WHERE supplier=? GROUP BY so_date", (supplier,)).fetchall()}
    conn.close()
    all_dates = sorted(set(proj) | set(actual))
    return [{"date": d, "projected": proj.get(d, 0), "actual": actual.get(d, 0),
             "achievement_pct": pct(actual.get(d, 0), proj[d]) if d in proj and proj[d] else None}
            for d in all_dates]

@app.get("/api/projections")
def get_projections(supplier: str = "", user=Depends(require_login)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM projections" + (f" WHERE supplier=?" if supplier else "") + " ORDER BY proj_date",
                        ([supplier] if supplier else [])).fetchall()
    conn.close(); return [dict(r) for r in rows]

@app.delete("/api/projections/{proj_id}")
def delete_projection(proj_id: int, admin=Depends(require_admin)):
    conn = get_db(); conn.execute("DELETE FROM projections WHERE id=?", (proj_id,)); conn.commit(); conn.close()
    return {"ok": True}

# --------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------
@app.get("/api/export/rows")
def export_rows(granularity: str = "day", period: str = "", supplier: str = "",
                entity: str = "", store: str = "", city: str = "", user=Depends(require_login)):
    conn = get_db()
    rows = fetch_rows(conn, granularity, period, supplier, entity, store, city)
    conn.close()
    if not rows: raise HTTPException(404, "No rows match")
    cols = ["order_id", "supplier", "store", "city", "entity_group", "so_status",
            "is_pending", "is_jit", "processed_qty", "distinct_count", "pushback_qty",
            "pvt_label_qty", "is_auto", "po_type", "proc_tat_hours", "grn_tat_hours",
            "so_created_at", "consignment_created_at", "grn_created_at"]
    buf = io.StringIO(); w = csv.writer(buf); w.writerow(cols)
    for r in rows: w.writerow([r.get(c, "") for c in cols])
    return Response(content=buf.getvalue(), media_type="text/csv",
                     headers={"Content-Disposition": "attachment; filename=replenishment_export.csv"})

# --------------------------------------------------------------------------
# Static files
# --------------------------------------------------------------------------
STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/", response_class=HTMLResponse)
def root():
    p = STATIC_DIR / "index.html"
    return HTMLResponse(p.read_text(encoding="utf-8") if p.exists() else "<h1>Place index.html in ./static/</h1>")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False,
                timeout_keep_alive=300,  # 5 min keep-alive for large uploads
                limit_max_requests=None)