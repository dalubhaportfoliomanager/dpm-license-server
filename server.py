#!/usr/bin/env python3
"""Dalubha Portfolio Manager central license activation tracker (stdlib only)."""
from __future__ import annotations
import json, os, re, sqlite3
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
ISSUER_SALT="DPM-2026-LICENSE-V1"
DB_PATH=os.environ.get("DPM_LICENSE_SERVER_DB","activation_server.db")
HOST=os.environ.get("DPM_LICENSE_SERVER_HOST","0.0.0.0")
PORT=int(os.environ.get("PORT", os.environ.get("DPM_LICENSE_SERVER_PORT","9191")))
MAX_ACTIVATIONS=3
ADMIN_RESET_TOKEN=os.environ.get("DPM_LICENSE_ADMIN_TOKEN","DALUBHA-ADMIN-RESET-2026")
# License Management Pro is the authoritative license database.
# DPM and License Management Pro are sibling project folders.
_DEFAULT_LMP_DB_PATH=os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "License Management Pro",
    "database",
    "license_management.db",
))
LICENSE_DB_PATH=os.environ.get("DPM_LICENSE_DB_PATH", _DEFAULT_LMP_DB_PATH)

def utc_now(): return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")

IST=ZoneInfo("Asia/Kolkata")

def parse_license_datetime(value):
    """Parse LMP date/time values as authoritative local time (India) and return UTC."""
    text=str(value or "").strip()
    if not text: return None

    # GLOBAL: accept the canonical LMP/View License display separator.
    # Example: "08-Oct-2026 | 10:15 AM".
    text=text.replace(" | ", " ").replace("|", " ").strip()

    candidates=(
        "%d-%b-%Y %I:%M:%S %p",
        "%d-%b-%Y %I:%M %p",
        "%d-%b-%Y %H:%M:%S",
        "%d-%b-%Y %H:%M",
        "%d-%b-%Y",
        "%d-%m-%Y %I:%M:%S %p",
        "%d-%m-%Y %I:%M %p",
        "%d-%m-%Y %H:%M:%S",
        "%d-%m-%Y %H:%M",
        "%d/%m/%Y %I:%M:%S %p",
        "%d/%m/%Y %I:%M %p",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y",
        "%Y-%m-%d %I:%M:%S %p",
        "%Y-%m-%d %I:%M %p",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
    )
    for fmt in candidates:
        try:
            dt=datetime.strptime(text,fmt)
            return dt.replace(tzinfo=IST).astimezone(timezone.utc)
        except ValueError:
            pass
    try:
        iso=text.replace("Z","+00:00")
        dt=datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt=dt.replace(tzinfo=IST)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None

def expiry_iso(value):
    """Convert any LMP expiry value to UTC using the expiry calendar date.

    GLOBAL RULE:
    The license is valid through 11:59:59 PM IST on its expiry date,
    regardless of the time stored in the LMP/View License value.
    Example: "08-Oct-2026 | 10:15 AM" remains valid until
    08-Oct-2026 11:59:59 PM IST.
    """
    text = str(value or "").strip()
    if not text:
        return None

    # Accept the canonical LMP/View License separator globally.
    text = text.replace(" | ", " ").replace("|", " ").strip()

    dt = parse_license_datetime(text)
    if dt is None:
        return None

    # parse_license_datetime returns UTC. Convert back to IST, keep only
    # the calendar date, and make that date valid through 11:59:59 PM IST.
    ist_date = dt.astimezone(IST).date()
    expiry_ist = datetime(
        ist_date.year,
        ist_date.month,
        ist_date.day,
        23, 59, 59,
        tzinfo=IST,
    )
    return expiry_ist.astimezone(timezone.utc).isoformat().replace("+00:00","Z")
def fnv1a(v):
    h=0x811C9DC5
    for b in v.encode("utf-8"):
        h^=b; h=(h*0x01000193)&0xffffffff
    return h

def checksum(payload): return f"{fnv1a(f'{ISSUER_SALT}|{payload}'):08X}"
def decode_serial(serial):
    """Decode both the current DMP...LMP##### format and legacy DPM1 keys."""
    serial=(serial or "").strip().upper().replace(" ","")

    # Current format: DMP01OCT2026LMP00001
    m=re.fullmatch(r"DMP(\d{2})([A-Z]{3})(\d{4})LMP(\d{5})",serial)
    if m:
        day,mon,year,seq=m.groups()
        try:
            issued=datetime.strptime(f"{day}{mon}{year}","%d%b%Y").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
        return {
            "serial":serial,
            "client_code":"LMP",
            "issue_date":issued.strftime("%Y-%m-%d"),
            "expiry_date":None,
            "license_count":1,
            "sequence":int(seq),
            "expiry_epoch":None,
        }

    # Legacy format: DPM1-CLIENT-YYYYMMDD-COUNT-CHECKSUM
    p=serial.split("-")
    if len(p)!=5 or p[0]!="DPM1": return None
    client,date_text,count_text,check=p[1:]
    if not re.fullmatch(r"[A-Z0-9]{2,20}",client): return None
    if not re.fullmatch(r"\d{8}",date_text): return None
    if not re.fullmatch(r"\d{1,4}",count_text): return None
    if not re.fullmatch(r"[0-9A-F]{8}",check): return None
    payload=f"DPM1|{client}|{date_text}|{count_text}"
    if check!=checksum(payload): return None
    try:
        y,m,d=int(date_text[:4]),int(date_text[4:6]),int(date_text[6:8])
        expiry=datetime(y,m,d,23,59,59,tzinfo=timezone.utc)
    except ValueError: return None
    count=int(count_text)
    if count<1: return None
    return {"serial":serial,"client_code":client,"expiry_date":expiry.strftime("%Y-%m-%d"),"license_count":count,"expiry_epoch":expiry.timestamp()}

def db():
    conn=sqlite3.connect(DB_PATH); conn.row_factory=sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS activations(
      id INTEGER PRIMARY KEY AUTOINCREMENT, serial TEXT NOT NULL, client_code TEXT NOT NULL,
      customer_name TEXT, device_id TEXT NOT NULL, activated_at TEXT NOT NULL, last_seen TEXT NOT NULL,
      app_version TEXT, status TEXT NOT NULL DEFAULT 'ACTIVE', license_count INTEGER NOT NULL,
      expiry_date TEXT NOT NULL, first_ip TEXT, last_ip TEXT, UNIQUE(serial,device_id))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS license_usage(
      serial TEXT PRIMARY KEY, activation_count INTEGER NOT NULL DEFAULT 0,
      last_device_id TEXT, updated_at TEXT NOT NULL)""")
    conn.commit(); return conn

def respond(h,code,payload):
    raw=json.dumps(payload).encode(); h.send_response(code)
    h.send_header("Content-Type","application/json; charset=utf-8"); h.send_header("Content-Length",str(len(raw)))
    h.send_header("Access-Control-Allow-Origin","*"); h.end_headers(); h.wfile.write(raw)

def read_json(h):
    try: return json.loads(h.rfile.read(int(h.headers.get("Content-Length","0"))).decode("utf-8"))
    except Exception: return None

def local_license_metadata(serial):
    """Read authoritative license metadata from License Management Pro DB when available.
    This is read-only; it never creates, edits, or deletes license-management data.
    """
    try:
        if not os.path.exists(LICENSE_DB_PATH):
            return {}
        conn=sqlite3.connect(LICENSE_DB_PATH)
        conn.row_factory=sqlite3.Row
        row=conn.execute("SELECT * FROM licenses WHERE UPPER(TRIM(license_key))=? LIMIT 1",(serial.upper(),)).fetchone()
        if not row:
            conn.close()
            return {}
        d=dict(row)
        renewal_row=conn.execute(
            "SELECT renew_date FROM renewal_history WHERE license_id=? ORDER BY id DESC LIMIT 1",
            (row["id"],),
        ).fetchone()
        conn.close()
        out={}
        for key in ("customer_name","product_name","issue_date","expiry_date","license_duration","client_code","license_count","status","activation_date"):
            value=d.get(key)
            if value is not None and str(value).strip() != "":
                out[key]=str(value).strip()
        if renewal_row and renewal_row["renew_date"]:
            out["renewal_date"]=str(renewal_row["renew_date"]).strip()
        if out.get("license_count"):
            try: out["license_count"]=max(1,int(float(out["license_count"])))
            except Exception: out.pop("license_count",None)
        return out
    except Exception:
        return {}


def merge_license_metadata(item, serial):
    meta=local_license_metadata(serial)
    if not meta:
        return item
    merged=dict(item)
    # License Management Pro is authoritative for license definition fields.
    for key in ("customer_name","product_name","issue_date","expiry_date","license_duration","client_code","license_count","renewal_date"):
        if meta.get(key) not in (None, ""):
            merged[key]=meta[key]
    return merged


def register(payload,ip):
    serial=str(payload.get("serial","")).strip().upper(); device=str(payload.get("device_id","")).strip()
    customer=str(payload.get("customer_name","")).strip(); version=str(payload.get("app_version","")).strip()
    decoded=decode_serial(serial)
    meta=local_license_metadata(serial)
    if meta.get("customer_name"): customer=meta["customer_name"]
    if decoded is not None:
        if meta.get("client_code"): decoded["client_code"]=meta["client_code"]
        if meta.get("license_count") is not None: decoded["license_count"]=meta["license_count"]
        if meta.get("expiry_date"): decoded["expiry_date"]=meta["expiry_date"]
    if not serial or not device: return 400,{"ok":False,"error":"serial and device_id are required"}
    if not decoded: return 400,{"ok":False,"error":"invalid serial"}

    # SECURITY RULE: a syntactically valid DMP...LMP##### string is NOT a license.
    # The License ID must exist in the authoritative License Management Pro DB.
    if not meta:
        return 403,{"ok":False,"error":"License ID was not generated by License Management Pro","reason":"lmp_license_not_found"}

    lmp_status=str(meta.get("status") or "").strip().lower()
    if lmp_status != "active":
        return 403,{"ok":False,"error":"License is not ACTIVE in License Management Pro","reason":"lmp_license_inactive","license_status":meta.get("status","")}

    expiry_date=str(meta.get("expiry_date") or "").strip()
    expiry_at=expiry_iso(expiry_date)
    if not expiry_at:
        return 403,{"ok":False,"error":"License has no valid expiry date in License Management Pro","reason":"invalid_lmp_expiry"}
    expiry_dt=datetime.fromisoformat(expiry_at.replace("Z","+00:00"))
    if expiry_dt <= datetime.now(timezone.utc):
        return 403,{"ok":False,"error":"License has expired in License Management Pro","reason":"license_expired","expiry_at":expiry_at}

    conn=db(); now=utc_now()
    license_count=int(meta.get("license_count") or decoded.get("license_count") or 1)
    if license_count < 1: license_count=1

    existing=conn.execute("SELECT id,activated_at FROM activations WHERE serial=? AND device_id=?",(serial,device)).fetchone()
    other=conn.execute("SELECT id,device_id FROM activations WHERE serial=? AND device_id<>? AND status='ACTIVE' ORDER BY id DESC LIMIT 1",(serial,device)).fetchone()
    usage=conn.execute("SELECT activation_count FROM license_usage WHERE serial=?",(serial,)).fetchone()
    used_count=int(usage["activation_count"]) if usage else 0

    # One License ID may run on only one device at a time. A different device
    # must be cleared by the administrator before it can be activated.
    if existing is None and other is not None:
        conn.close(); return 409,{"ok":False,"error":"license already active on another system; please contact the License Administrator","reason":"device_in_use","activation_count":used_count,"activation_limit":MAX_ACTIVATIONS}

    # Maximum three activation events between administrator limit resets.
    if existing is None and used_count >= MAX_ACTIVATIONS:
        conn.close(); return 409,{"ok":False,"error":"license activation limit reached (3 activations); please contact the License Administrator","reason":"activation_limit","activation_count":used_count,"activation_limit":MAX_ACTIVATIONS}

    if existing:
        conn.execute("UPDATE activations SET last_seen=?,app_version=?,customer_name=?,status='ACTIVE',last_ip=?,expiry_date=?,license_count=? WHERE id=?",(now,version or None,customer or None,ip,expiry_date,license_count,existing["id"]))
        activated_at=existing["activated_at"]
    else:
        conn.execute("INSERT INTO activations(serial,client_code,customer_name,device_id,activated_at,last_seen,app_version,status,license_count,expiry_date,first_ip,last_ip) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(serial,decoded["client_code"],customer or None,device,now,now,version or None,"ACTIVE",license_count,expiry_date,ip,ip))
        conn.execute("INSERT INTO license_usage(serial,activation_count,last_device_id,updated_at) VALUES(?,?,?,?) ON CONFLICT(serial) DO UPDATE SET activation_count=license_usage.activation_count+1,last_device_id=excluded.last_device_id,updated_at=excluded.updated_at",(serial,1,device,now))
        activated_at=now; used_count += 1
    conn.commit(); conn.close()
    result={"ok":True,"serial":serial,"status":"ACTIVE","activated_at":activated_at,"last_seen":now,"activation_count":used_count,"current_device_id":device,"expiry_date":expiry_date,"expiry_at":expiry_at,"license_count":license_count}
    for key in ("customer_name","product_name","issue_date","license_duration","client_code","renewal_date"):
        if meta.get(key): result[key]=meta[key]
    return 200,result

def reset_activations(payload):
    serial=str(payload.get("serial","")).strip().upper().replace(" ","")
    token=str(payload.get("admin_token","")).strip()
    mode=str(payload.get("mode","clear_device")).strip().lower()
    if token != ADMIN_RESET_TOKEN:
        return 403,{"ok":False,"error":"administrator authorization required"}
    if not serial:
        return 400,{"ok":False,"error":"serial is required"}
    if not decode_serial(serial):
        return 400,{"ok":False,"error":"invalid serial"}
    conn=db()
    deleted=conn.execute("DELETE FROM activations WHERE serial=?",(serial,)).rowcount
    if mode == "reset_limit":
        conn.execute("DELETE FROM license_usage WHERE serial=?",(serial,))
    else:
        conn.execute("UPDATE license_usage SET last_device_id=NULL,updated_at=? WHERE serial=?",(utc_now(),serial))
    conn.commit()
    usage=conn.execute("SELECT activation_count FROM license_usage WHERE serial=?",(serial,)).fetchone()
    remaining=int(usage["activation_count"]) if usage else 0
    conn.close()
    return 200,{"ok":True,"serial":serial,"reset":True,"mode":mode,"deleted_activations":int(deleted),"activation_count":remaining,"activation_limit":MAX_ACTIVATIONS}


def status(serial):
    serial=(serial or "").strip().upper().replace(" ","")
    decoded=decode_serial(serial)
    if not decoded:
        return 400,{"ok":False,"error":"invalid serial"}
    meta=local_license_metadata(serial)
    if not meta:
        return 403,{"ok":False,"error":"License ID was not generated by License Management Pro","reason":"lmp_license_not_found"}
    lmp_status=str(meta.get("status") or "").strip().lower()
    if lmp_status != "active":
        return 403,{"ok":False,"error":"License is not ACTIVE in License Management Pro","reason":"lmp_license_inactive","license_status":meta.get("status","")}

    expiry_at=expiry_iso(meta.get("expiry_date"))
    if not expiry_at:
        return 403,{"ok":False,"error":"License has no valid expiry date in License Management Pro","reason":"invalid_lmp_expiry"}

    if datetime.fromisoformat(expiry_at.replace("Z","+00:00")) <= datetime.now(timezone.utc):
        return 403,{"ok":False,"error":"License has expired in License Management Pro","reason":"license_expired","expiry_at":expiry_at}

    conn=db()
    rows=conn.execute("SELECT serial,client_code,customer_name,device_id,activated_at,last_seen,app_version,status,license_count,expiry_date,first_ip,last_ip FROM activations WHERE serial=? ORDER BY id DESC",(serial,)).fetchall()
    items=[merge_license_metadata(dict(r), serial) for r in rows]
    usage=conn.execute("SELECT activation_count FROM license_usage WHERE serial=?",(serial,)).fetchone()
    lifetime_count=int(usage["activation_count"]) if usage else 0
    conn.close()

    expired=datetime.fromisoformat(expiry_at.replace("Z","+00:00")) <= datetime.now(timezone.utc)
    effective_status="EXPIRED" if expired else str(meta.get("status") or (items[0].get("status") if items else "" ) or "ACTIVE").upper()
    for item in items:
        item["expiry_at"]=expiry_at
        item["status"]=effective_status

    result={"ok":True,"serial":serial,"registered":bool(items),"activation_count":lifetime_count,"active_device_count":len(items),"activation_limit":MAX_ACTIVATIONS,"items":items,"expiry_at":expiry_at,"status":effective_status}
    for key in ("customer_name","product_name","issue_date","expiry_date","license_duration","client_code","license_count","renewal_date"):
        if meta.get(key) not in (None, ""): result[key]=meta[key]
    return 200,result

class Handler(BaseHTTPRequestHandler):
    server_version="DPM-License-Tracker/1.0"
    def log_message(self,fmt,*args): print(f"[{utc_now()}] {self.address_string()} - {fmt%args}")
    def do_OPTIONS(self):
        self.send_response(204); self.send_header("Access-Control-Allow-Origin","*"); self.send_header("Access-Control-Allow-Methods","GET, POST, OPTIONS"); self.send_header("Access-Control-Allow-Headers","Content-Type"); self.end_headers()
    def do_GET(self):
        parsed=urlparse(self.path)
        if parsed.path=="/health": return respond(self,200,{"ok":True,"service":"DPM license activation tracker","time":utc_now()})
        if parsed.path=="/v1/activation/status":
            code,payload=status(parse_qs(parsed.query).get("serial",[""])[0]); return respond(self,code,payload)
        return respond(self,404,{"ok":False,"error":"not found"})
    def do_POST(self):
        parsed=urlparse(self.path); payload=read_json(self)
        if payload is None: return respond(self,400,{"ok":False,"error":"invalid JSON"})
        if parsed.path in ("/v1/activation/register","/v1/activation/heartbeat"):
            code,result=register(payload,self.client_address[0]); return respond(self,code,result)
        if parsed.path == "/v1/activation/reset":
            code,result=reset_activations(payload); return respond(self,code,result)
        return respond(self,404,{"ok":False,"error":"not found"})

if __name__=="__main__":
    db().close(); print(f"DPM License Tracker listening on http://{HOST}:{PORT}"); ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
