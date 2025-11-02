import os, io, uuid, time, re, base64, secrets, hmac, hashlib, smtplib, ssl, math
from datetime import timedelta
from email.mime.text import MIMEText
from urllib.parse import urlencode

import streamlit as st
from sqlalchemy import create_engine, text
import qrcode
from PIL import Image

# ==================== Simple PBKDF2 password hashing ====================
def _hash_pw(pw: str, iterations: int = 200_000) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.strip().encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

def _check_pw(stored: str, pw: str) -> bool:
    try:
        algo, iters_s, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iters = int(iters_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", pw.strip().encode(), salt, iters)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

# ==================== Settings helpers ====================
def get_setting(key, default=None):
    return st.secrets.get(key, os.getenv(key, default))

def fix_db_url(url: str) -> str:
    if not url:
        return url
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    return url

DB_URL = fix_db_url(get_setting("DATABASE_URL"))
ADMIN_PASSWORD = (get_setting("ADMIN_PASSWORD", "change-me") or "").strip()
PUBLIC_BASE = (get_setting("PUBLIC_BASE_URL") or "").rstrip("/")
QR_PRICE_INR = 100  # fixed price requested

# Optional SMTP (for OTP email)
SMTP_HOST = get_setting("SMTP_HOST")
SMTP_PORT = int(get_setting("SMTP_PORT", "587") or 587)
SMTP_USER = get_setting("SMTP_USER")
SMTP_PASS = get_setting("SMTP_PASS")
SMTP_FROM = get_setting("SMTP_FROM")

if not DB_URL:
    st.error("DATABASE_URL is not set. Add it in Streamlit → App settings → Secrets.")
    st.stop()

# ==================== DB setup ====================
try:
    engine = create_engine(DB_URL, pool_pre_ping=True)
except Exception as e:
    st.error("Failed to connect to the database. Check DATABASE_URL in Secrets.")
    st.exception(e)
    st.stop()

def ensure_schema():
    with engine.begin() as conn:
        # Core cars table
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS cars (
          id UUID PRIMARY KEY,
          owner_name TEXT NOT NULL,
          car_no TEXT NOT NULL,
          owner_phone TEXT NOT NULL,
          virtual_number TEXT NOT NULL,
          dl_url TEXT,
          dl_url2 TEXT,
          rc_url TEXT,
          puc_url TEXT,
          doc_password_hash TEXT,
          owner_secret UUID NOT NULL,
          is_active BOOLEAN NOT NULL DEFAULT FALSE,        -- NEW: default inactive
          owner_user_id UUID,
          activated_at TIMESTAMPTZ,
          expires_at   TIMESTAMPTZ,
          payment_status TEXT NOT NULL DEFAULT 'pending',  -- 'pending'|'done'
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );"""))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS dl_url2 TEXT;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS puc_url TEXT;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS owner_secret UUID;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT FALSE;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS owner_user_id UUID;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS expires_at   TIMESTAMPTZ;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS payment_status TEXT DEFAULT 'pending';"))
        conn.execute(text("UPDATE cars SET is_active=FALSE WHERE is_active IS NULL;"))
        conn.execute(text("UPDATE cars SET payment_status='pending' WHERE payment_status IS NULL;"))

        # Users
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
          id UUID PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );"""))

        # Temporary signup OTP store
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS signup_otp (
          email TEXT PRIMARY KEY,
          password_hash TEXT NOT NULL,
          otp_code TEXT NOT NULL,
          otp_expires TIMESTAMPTZ NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );"""))

        # Optional file uploads (payment proofs)
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS payments (
          id UUID PRIMARY KEY,
          car_id UUID NOT NULL REFERENCES cars(id) ON DELETE CASCADE,
          user_id UUID,
          filename TEXT,
          mime TEXT,
          content BYTEA,
          verified BOOLEAN NOT NULL DEFAULT FALSE,
          notes TEXT,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );"""))

        # Settings (for Admin QR/payment instructions)
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY,
          value TEXT
        );"""))

ensure_schema()

# ==================== Utility functions ====================
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def sanitize_phone(s: str) -> str:
    if not s: return ""
    m = re.search(r"(\+?\d{7,15})", str(s))
    return m.group(1) if m else ""

def tel_href(num: str) -> str:
    p = sanitize_phone(num)
    return f"tel:{p}" if p else "tel:"

def make_qr_png(url: str) -> bytes:
    img = qrcode.make(url)
    buf = io.BytesIO(); img.save(buf, format="PNG"); return buf.getvalue()

def public_url_for_car(car_id: str) -> str:
    base = PUBLIC_BASE or ""
    return f"{base}?"+ urlencode({"page": "public", "c": car_id}) if base else f"?page=public&c={car_id}"

def owner_url_for_car(car_id: str, secret: str) -> str:
    base = PUBLIC_BASE or ""
    return f"{base}?"+ urlencode({"page": "owner", "owner": car_id, "secret": secret}) if base else f"?page=owner&owner={car_id}&secret={secret}"

def get_qp(name: str, default: str | None = None):
    try:
        v = st.query_params.get(name)
        return v if isinstance(v, str) else (v[0] if isinstance(v, list) and v else default)
    except Exception:
        qp = st.experimental_get_query_params()
        v = qp.get(name)
        return v[0] if isinstance(v, list) and v else default

def days_left(expires_at) -> int | None:
    if not expires_at: return None
    # naive days difference
    # Streamlit returns pendulum-like obj/string; cast to string and parse rough
    try:
        # Let Postgres format; we compare server-side in SQL later where needed
        return None
    except:  # not used; we compute server-side when needed
        return None

# ==================== Data access ====================
def create_car(owner_name, car_no, owner_phone, virtual_number, rc, dl1, dl2, puc, doc_pw):
    with engine.begin() as conn:
        car_id = str(uuid.uuid4())
        owner_secret = str(uuid.uuid4())
        pw_hash = _hash_pw(doc_pw) if (doc_pw or "").strip() else None
        conn.execute(text("""
          INSERT INTO cars (id, owner_name, car_no, owner_phone, virtual_number,
                            rc_url, dl_url, dl_url2, puc_url,
                            doc_password_hash, owner_secret, is_active, payment_status)
          VALUES (:id,:on,:cn,:op,:vn,:rc,:dl1,:dl2,:puc,:hash,:sec,FALSE,'pending')
        """), dict(id=car_id, on=owner_name, cn=car_no, op=owner_phone, vn=virtual_number,
                   rc=rc, dl1=dl1, dl2=dl2, puc=puc, hash=pw_hash, sec=owner_secret))
        return car_id, owner_secret

def enforce_expiry():
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE cars
               SET is_active = FALSE
             WHERE is_active = TRUE
               AND expires_at IS NOT NULL
               AND now() > expires_at
        """))

def get_car(car_id: str):
    enforce_expiry()
    with engine.begin() as conn:
        row = conn.execute(text("SELECT * FROM cars WHERE id=:id"), dict(id=car_id)).mappings().first()
        return dict(row) if row else None

def list_cars_admin(search: str | None = None):
    enforce_expiry()
    q = """
      SELECT id, owner_name, car_no, owner_phone, virtual_number,
             created_at, is_active, owner_secret, activated_at, expires_at, payment_status
        FROM cars
       WHERE 1=1
    """
    params = {}
    if search:
        q += " AND (owner_name ILIKE :q OR car_no ILIKE :q OR id::text ILIKE :q) "
        params["q"] = f"%{search}%"
    q += " ORDER BY created_at DESC "
    with engine.begin() as conn:
        rows = conn.execute(text(q), params).mappings().all()
        return [dict(r) for r in rows]

def set_active(car_id: str, active: bool):
    with engine.begin() as conn:
        conn.execute(text("UPDATE cars SET is_active=:a WHERE id=:id"), dict(a=active, id=car_id))

def set_payment_status(car_id: str, status: str):
    with engine.begin() as conn:
        conn.execute(text("UPDATE cars SET payment_status=:s WHERE id=:id"),
                     dict(s='done' if status=='done' else 'pending', id=car_id))

def activate_with_days(car_id: str, days: int):
    days = max(1, int(days))
    with engine.begin() as conn:
        conn.execute(text("""
            UPDATE cars
               SET is_active   = TRUE,
                   activated_at = now(),
                   expires_at   = now() + (:d || ' days')::interval
             WHERE id = :id
        """), dict(id=car_id, d=days))

def car_already_linked_to_user(car_id: str, user_id: str) -> bool:
    with engine.begin() as conn:
        row = conn.execute(text("SELECT owner_user_id FROM cars WHERE id=:id"),
                           dict(id=car_id)).mappings().first()
        return bool(row and row["owner_user_id"] == user_id)

def claim_car_for_user(car_id: str, owner_secret: str, user_id: str) -> str:
    # Returns 'ok'/'already'/'invalid'
    with engine.begin() as conn:
        row = conn.execute(text("""
            SELECT id, owner_secret, is_active, owner_user_id,
                   GREATEST(0, CEIL(EXTRACT(EPOCH FROM (expires_at - now()))/86400)) AS days_left
              FROM cars WHERE id=:id
        """), dict(id=car_id)).mappings().first()
        if not row or str(row["owner_secret"]) != str(owner_secret):
            return "invalid"
        if row["owner_user_id"] == user_id:
            st.session_state["last_days_left"] = int(row["days_left"] or 0)
            return "already"
        if not row["is_active"]:
            return "invalid"
        conn.execute(text("UPDATE cars SET owner_user_id=:u WHERE id=:id"), dict(u=user_id, id=car_id))
        return "ok"

def list_user_cars(user_id: str):
    enforce_expiry()
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT *, GREATEST(0, CEIL(EXTRACT(EPOCH FROM (expires_at - now()))/86400)) AS days_left
              FROM cars WHERE owner_user_id=:u ORDER BY created_at DESC
        """), dict(u=user_id)).mappings().all()
        return [dict(r) for r in rows]

# OTP signup helpers
def upsert_signup_otp(email: str, password_hash: str, otp: str, ttl_minutes: int = 10):
    with engine.begin() as conn:
        conn.execute(text("""
          INSERT INTO signup_otp (email, password_hash, otp_code, otp_expires)
          VALUES (:e,:p,:o, now() + (:m || ' minutes')::interval)
          ON CONFLICT (email) DO UPDATE
          SET password_hash=excluded.password_hash,
              otp_code=excluded.otp_code,
              otp_expires=excluded.otp_expires,
              created_at=now()
        """), dict(e=email, p=password_hash, o=otp, m=ttl_minutes))

def consume_signup_otp(email: str, otp: str) -> bool:
    with engine.begin() as conn:
        row = conn.execute(text("""
          SELECT otp_code, otp_expires FROM signup_otp WHERE email=:e
        """), dict(e=email)).mappings().first()
        if not row: return False
        ok = (row["otp_code"] == otp) and (str(row["otp_expires"]) > str(time.strftime("%Y-%m-%d %H:%M:%S")))
        if ok:
            conn.execute(text("DELETE FROM signup_otp WHERE email=:e"), dict(e=email))
        return ok

def create_user(email: str, password: str):
    with engine.begin() as conn:
        uid = str(uuid.uuid4())
        ph = _hash_pw(password.strip())
        conn.execute(text("INSERT INTO users (id, email, password_hash) VALUES (:id,:e,:p)"),
                     dict(id=uid, e=email.strip().lower(), p=ph))
        return uid

def auth_user(email: str, password: str):
    with engine.begin() as conn:
        row = conn.execute(text("SELECT id, password_hash FROM users WHERE email=:e"),
                           dict(e=email.strip().lower())).mappings().first()
        if not row: return None
        return row["id"] if _check_pw(row["password_hash"], password.strip()) else None

# Settings KV
def get_setting_kv(key: str) -> str | None:
    with engine.begin() as conn:
        row = conn.execute(text("SELECT value FROM settings WHERE key=:k"),
                           dict(k=key)).mappings().first()
        return row["value"] if row else None

def set_setting_kv(key: str, value: str | None):
    with engine.begin() as conn:
        if value is None:
            conn.execute(text("DELETE FROM settings WHERE key=:k"), dict(k=key))
        else:
            conn.execute(text("""
              INSERT INTO settings(key,value) VALUES (:k,:v)
              ON CONFLICT (key) DO UPDATE SET value=excluded.value
            """), dict(k=key, v=value))

# Payments (proof upload)
def add_payment_proof(car_id: str, user_id: str, filename: str, mime: str, data: bytes):
    with engine.begin() as conn:
        pid = str(uuid.uuid4())
        conn.execute(text("""
          INSERT INTO payments (id, car_id, user_id, filename, mime, content)
          VALUES (:id,:c,:u,:f,:m,:d)
        """), dict(id=pid, c=car_id, u=user_id, f=filename, m=mime, d=data))
        return pid

def list_unverified_payments():
    with engine.begin() as conn:
        rows = conn.execute(text("""
          SELECT p.id, p.car_id, p.user_id, p.filename, p.mime, p.created_at, u.email, c.owner_name, c.car_no
            FROM payments p
            LEFT JOIN users u ON u.id = p.user_id
            LEFT JOIN cars c ON c.id = p.car_id
           WHERE p.verified = FALSE
           ORDER BY p.created_at DESC
        """)).mappings().all()
        return [dict(r) for r in rows]

def mark_payment_verified(pid: str, note: str | None):
    with engine.begin() as conn:
        conn.execute(text("UPDATE payments SET verified=TRUE, notes=:n WHERE id=:id"),
                     dict(id=pid, n=note or ""))

# Email (OTP)
def send_otp_email(to_email: str, otp: str) -> bool:
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and SMTP_FROM):
        return False
    msg = MIMEText(f"Your MYSCAN signup OTP is: {otp}\nIt expires in 10 minutes.")
    msg["Subject"] = "MYSCAN OTP Verification"
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())
        return True
    except Exception:
        return False

# ==================== THEME ====================
st.set_page_config(page_title="MYSCAN", page_icon="🚗", layout="centered")
st.markdown("""
<style>
:root { --blue:#0b1b3a; --muted:#4a6786; --border:#e6eef6; --orange1:#ffe6cc; --orange2:#ffcc99; --orangeBorder:#ffd7b3; --green:#16a34a; --red:#dc2626;}
[data-testid="stAppViewContainer"] { background:#fff; }
.topbar{position:sticky;top:0;z-index:1000;background:rgba(255,255,255,.95);backdrop-filter:blur(8px);
  border-bottom:1px solid var(--border);margin-bottom:18px;padding:10px 14px;border-radius:0 0 16px 16px;}
.topbar .brand{font-weight:800;letter-spacing:.2px;font-size:18px;color:var(--blue)}
.topbar .muted{color:var(--muted);font-weight:600}
.topbar a{color:#1d4ed8;text-decoration:none;margin-left:14px}
.card{background:#fff;border:1px solid var(--border);border-radius:16px;padding:22px;box-shadow:0 12px 30px rgba(12,35,64,.06);color:var(--blue)}
.hero{background:linear-gradient(180deg,#fff,#f8fbff)}
.h1{font-size:28px;margin:0 0 8px;color:var(--blue)}
.subtle{color:var(--muted);margin:0}
.sep{border:0;border-top:1px solid var(--border);margin:18px 0}
.chip{display:inline-block;padding:6px 10px;border-radius:999px;border:1px solid var(--border);color:var(--muted);font-size:12px;background:#f3f8ff}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700}
.badge.pending{background:#fff0ed;color:var(--red);border:1px solid #ffd4cc}
.badge.done{background:#ecfdf5;color:var(--green);border:1px solid #bbf7d0}
.stTextInput>div>div>input,.stTextArea textarea{background:#fff;color:var(--blue);border:1px solid var(--border);border-radius:10px}
.stButton>button,.stLinkButton>button{
  display:inline-flex;align-items:center;justify-content:center;white-space:nowrap;min-width:138px;
  border-radius:12px;padding:12px 18px;font-weight:700;border:1px solid var(--orangeBorder);color:#5b2400;
  background:linear-gradient(180deg,var(--orange1),var(--orange2));box-shadow:0 8px 20px rgba(255,153,51,.20)}
.stButton>button:hover,.stLinkButton>button:hover{filter:brightness(1.03)}
.btn-secondary button{background:linear-gradient(180deg,#e6f0ff,#cfe0ff);color:var(--blue);border:1px solid #c7d7f7;box-shadow:0 8px 20px rgba(29,78,216,.12)}
.btn-ghost button{background:#fff;color:var(--muted);border:1px solid var(--border);box-shadow:none}
.btn-warn  button{background:linear-gradient(180deg,#ffe5e5,#ffd0b3);color:#5b2400;border:1px solid #ffc2a3}
.qr-preview{border:1px dashed #dbe7f3;border-radius:12px;padding:10px;background:#fbfdff}
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.scrollbox{max-height:480px;overflow:auto;border:1px solid var(--border);border-radius:12px;padding:8px}
.car-hero{position:relative;border:1px solid var(--border);border-radius:16px;padding:18px;background:linear-gradient(180deg,#fff,#f8fbff);overflow:hidden}
.car-hero .qr{position:absolute;right:18px;top:18px;border:6px solid #fff;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.15)}
.car-lane{position:relative;height:80px;margin-top:12px;border-top:1px dashed #e7eef6}
.car{position:absolute;top:16px;font-size:28px;animation:drive 8s linear infinite}
.car:nth-child(2){top:42px;animation-duration:12s}
@keyframes drive{0%{left:-40px}100%{left:calc(100% + 40px)}}
.price{font-weight:800}
</style>
""", unsafe_allow_html=True)

# ==================== Topbar ====================
st.markdown("""
<div class="topbar">
  <span class="brand">MYSCAN</span>
  <span class="muted">· Smart vehicle QR</span>
  <span style="float:right">
    <a href="?page=user">User dashboard</a>
    <a href="?page=admin">Admin</a>
    <a href="?">Home</a>
  </span>
</div>
""", unsafe_allow_html=True)

def section_card(title: str, subtitle: str = "", hero=False):
    cls = "card hero" if hero else "card"
    st.markdown(f"<div class='{cls}'><div class='h1'>{title}</div><p class='subtle'>{subtitle}</p>", unsafe_allow_html=True)
    return st.container()

def end_card():
    st.markdown("</div>", unsafe_allow_html=True)

# ==================== Router ====================
page   = get_qp("page", "")
car_id = get_qp("c")
owner_id = get_qp("owner")
secret  = get_qp("secret")

# ==================== HOME ====================
if page == "":
    c = section_card("Welcome to MYSCAN", "Contact car owners quickly. Securely share RC/DL/PUC with a password.", hero=True)
    with c:
        # Car hero with QR overlay + moving cars
        sample = (PUBLIC_BASE or "") + "?page=public&c=YOUR-CAR-ID"
        png = make_qr_png(sample)
        st.markdown('<div class="car-hero">', unsafe_allow_html=True)
        st.image("https://images.unsplash.com/photo-1525609004556-c46c7d6cf023?q=80&w=1200&auto=format&fit=crop", use_container_width=True)
        st.image(Image.open(io.BytesIO(png)), caption=None, width=140)
        st.markdown('<img class="qr" src="data:image/png;base64,' + base64.b64encode(png).decode() + '"/>', unsafe_allow_html=True)
        st.markdown('<div class="car-lane"><div class="car">🚗</div><div class="car">🚙</div></div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown(f"**Price:** <span class='price'>₹{QR_PRICE_INR}</span> / QR", unsafe_allow_html=True)
        st.write("Use the **User dashboard** to sign up and link your car, or ask Admin to generate your QR.")
    end_card()
    st.stop()

# ==================== ADMIN ====================
if page == "admin":
    enforce_expiry()

    c = section_card("Admin dashboard", "Create cars, manage payments, and activate windows", hero=True)
    with c:
        cols = st.columns([2,1])
        with cols[0]:
            pwd = st.text_input("Admin password", type="password", placeholder="Enter admin password", key="admin_pwd")
            if st.button("Sign in"):
                if (pwd or "").strip() == ADMIN_PASSWORD:
                    st.session_state["admin_ok"] = True
                else:
                    st.error("Wrong password")
        with cols[1]:
            st.caption(f"Base URL: {PUBLIC_BASE or '(not set)'}")
            # Payment QR for users
            pay_qr = get_setting_kv("payment_qr_url") or ""
            with st.expander("Payment QR / Instructions"):
                new_qr = st.text_input("Payment QR image URL (public)", value=pay_qr)
                new_msg = st.text_area("Payment instructions (shown to users)", value=get_setting_kv("payment_msg") or "Scan QR to pay ₹100. Upload screenshot to your dashboard.")
                if st.button("Save payment settings"):
                    set_setting_kv("payment_qr_url", (new_qr or "").strip() or None)
                    set_setting_kv("payment_msg", (new_msg or "").strip() or None)
                    st.success("Saved payment settings.")
    end_card()

    if not st.session_state.get("admin_ok"):
        st.stop()

    # --- Create new car / QR ---
    c2 = section_card("Generate new QR", "New cars default to INACTIVE until payment marked Done + activation window set")
    with c2:
        if not PUBLIC_BASE:
            st.info("Tip: set PUBLIC_BASE_URL in Secrets so QR links use your live domain.")
        with st.form("create"):
            g = st.columns(2)
            with g[0]:
                on = st.text_input("Owner name *", placeholder="e.g. Mukesh Kumar", key="admin_on")
                cn = st.text_input("Car number *", placeholder="e.g. DL01AB1234", key="admin_cn")
                op = st.text_input("Owner mobile (record) *", placeholder="+91XXXXXXXXXX", key="admin_op")
            with g[1]:
                vn = st.text_input("Proxy/Virtual number *", placeholder="+91XXXXXXXXXX", key="admin_vn")
                rc = st.text_input("RC link (optional)", placeholder="https://...", key="admin_rc")
                docpw = st.text_input("Docs password (optional)", type="password", key="admin_docpw")
            h = st.columns(2)
            with h[0]:
                dl1 = st.text_input("DL front link (optional)", placeholder="https://...", key="admin_dl1")
            with h[1]:
                dl2 = st.text_input("DL back link (optional)", placeholder="https://...", key="admin_dl2")
            puc = st.text_input("Pollution (PUC) link (optional)", placeholder="https://...", key="admin_puc")
            s = st.form_submit_button("Create")
        if s:
            if not on or not cn or not op or not vn:
                st.error("Please fill all required fields.")
            else:
                op_s = sanitize_phone(op); vn_s = sanitize_phone(vn)
                if not op_s or not vn_s:
                    st.error("Enter valid phone numbers (7–15 digits, optional +).")
                else:
                    new_id, owner_secret = create_car(on, cn, op_s, vn_s, rc, dl1, dl2, puc, docpw or "")
                    pub_url = public_url_for_car(new_id)
                    own_url = owner_url_for_car(new_id, owner_secret)
                    st.success("Car created (INACTIVE). Share IDs below with the user.")

                    idc1, idc2 = st.columns(2)
                    with idc1:
                        st.markdown("**Car ID**")
                        st.code(new_id, language="text")
                    with idc2:
                        st.markdown("**Owner Secret**")
                        st.code(owner_secret, language="text")

                    pcols = st.columns(2)
                    with pcols[0]:
                        st.markdown("**Public page**"); st.code(pub_url, language="text")
                        st.image(Image.open(io.BytesIO(make_qr_png(pub_url))), caption="Public QR")
                        st.download_button("Download Public QR", make_qr_png(pub_url), file_name=f"qr-{new_id}.png", mime="image/png")
                    with pcols[1]:
                        st.markdown("**Owner panel**"); st.code(own_url, language="text")
                        st.image(Image.open(io.BytesIO(make_qr_png(own_url))), caption="Owner Panel QR")
                        st.download_button("Download Owner QR", make_qr_png(own_url), file_name=f"owner-qr-{new_id}.png", mime="image/png")
    end_card()

    # --- Manage cars / searchable scrollable list + actions ---
    c3 = section_card("Vehicles", "Deactivate, reactivate on payment, set activation window, and view IDs")
    with c3:
        st.write(f"Price per QR: **₹{QR_PRICE_INR}**")
        search = st.text_input("Search by owner / car / ID", key="admin_search")
        rows = list_cars_admin(search.strip() or None)

        # Summary table with scroll
        st.markdown("**List (most recent first)**")
        st.markdown('<div class="scrollbox">', unsafe_allow_html=True)
        # Header
        st.markdown("| S.No | Owner | Car No | Status | Payment | Activated | Expires | |\n|---:|---|---|---|---|---|---|---|", unsafe_allow_html=True)
        for i, r in enumerate(rows, start=1):
            status = "🟢 Active" if r['is_active'] else "🔴 Inactive"
            pay = f"<span class='badge {'done' if r['payment_status']=='done' else 'pending'}'>{r['payment_status'].title()}</span>"
            act = str(r['activated_at'] or "—")
            exp = str(r['expires_at']   or "—")
            st.markdown(f"| {i} | {r['owner_name']} | {r['car_no']} | {status} | {pay} | {act} | {exp} | `[select #{i}]` |", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

        if not rows:
            st.caption("No entries yet.")
        else:
            idx = st.number_input("Select row number for actions", min_value=1, max_value=len(rows), value=1, step=1)
            sel = rows[idx-1]
            st.markdown("---")
            st.markdown(f"**Selected:** {sel['owner_name']} · {sel['car_no']}  ({'Active' if sel['is_active'] else 'Inactive'})")
            st.caption("IDs to share with user")
            cc = st.columns(2)
            with cc[0]:
                st.code(sel['id'], language="text")
            with cc[1]:
                st.code(str(sel['owner_secret']), language="text")

            z1,z2,z3 = st.columns(3)
            with z1:
                st.link_button("Open public", public_url_for_car(sel['id']))
            with z2:
                # Payment toggle
                pay_done = (sel['payment_status']=='done')
                if st.button("Mark payment: Done" if not pay_done else "Mark payment: Pending"):
                    set_payment_status(sel['id'], 'done' if not pay_done else 'pending')
                    st.success("Payment status updated."); st.rerun()
                st.caption("Pending=red, Done=green")
            with z3:
                days = st.number_input("Activate days", min_value=1, max_value=3650, value=30, step=1)
                if st.button("Activate with days"):
                    if sel['payment_status']!='done':
                        st.error("Payment must be Done before activation.")
                    else:
                        activate_with_days(sel['id'], int(days))
                        st.success(f"Activated for {int(days)} day(s)."); st.rerun()

            y1,y2 = st.columns(2)
            with y1:
                if sel['is_active']:
                    if st.button("Deactivate now"):
                        set_active(sel['id'], False); st.success("Deactivated"); st.rerun()
            with y2:
                if st.button("Regenerate QRs"):
                    car = get_car(sel['id']); own_link = owner_url_for_car(sel['id'], car['owner_secret'])
                    st.success("Download fresh QR images below.")
                    a,b = st.columns(2)
                    with a:
                        st.download_button("Public QR", make_qr_png(public_url_for_car(sel['id'])),
                                           file_name=f"qr-{sel['id']}.png", mime="image/png")
                    with b:
                        st.download_button("Owner QR", make_qr_png(own_link),
                                           file_name=f"owner-qr-{sel['id']}.png", mime="image/png")

        st.markdown("----")
        st.subheader("Verify new payments")
        unv = list_unverified_payments()
        if not unv:
            st.caption("No new payment uploads.")
        else:
            for p in unv:
                st.markdown(f"**{p['owner_name']} · {p['car_no']}** — {p['email'] or 'unknown email'} · {p['filename']}")
                note = st.text_input(f"Note for {p['id']}", key=f"note_{p['id']}")
                c1, c2 = st.columns(2)
                with c1:
                    if st.button("Mark verified", key=f"v_{p['id']}"):
                        mark_payment_verified(p['id'], note)
                        st.success("Marked verified.")
                        st.rerun()
                with c2:
                    st.caption(str(p['created_at']))
    end_card()
    st.stop()

# ==================== USER DASHBOARD ====================
if page == "user":
    enforce_expiry()
    c = section_card("User dashboard", "Sign up with OTP, link your car, manage docs & payment", hero=True)
    with c:
        tab_login, tab_signup = st.tabs(["Sign in", "Create account (OTP)"])

        # --- Sign in ---
        with tab_login:
            le = st.text_input("Email", key="login_email")
            lp = st.text_input("Password", type="password", key="login_password")
            if st.button("Sign in"):
                if not le or not EMAIL_RE.match(le):
                    st.error("Enter a valid email address.")
                else:
                    uid = auth_user(le or "", lp or "")
                    if uid: st.session_state["user_id"] = uid; st.success("Signed in"); st.rerun()
                    else: st.error("Invalid email or password")

        # --- Signup with OTP ---
        with tab_signup:
            se  = st.text_input("Email (for new account)", key="signup_email")
            sp1 = st.text_input("Password", type="password", key="signup_password")
            sp2 = st.text_input("Confirm password", type="password", key="signup_confirm")
            otp_box = st.text_input("OTP (check your email)", key="signup_otp")
            colS = st.columns(2)
            send_clicked = colS[0].button("Send OTP")
            create_clicked = colS[1].button("Complete signup")

            if send_clicked:
                if not se or not EMAIL_RE.match(se):
                    st.error("Enter a valid email (must include @).")
                elif not sp1 or sp1 != sp2:
                    st.error("Enter matching passwords.")
                else:
                    otp = f"{secrets.randbelow(1000000):06d}"
                    pw_temp = _hash_pw(sp1.strip())
                    upsert_signup_otp(se.lower().strip(), pw_temp, otp, ttl_minutes=10)
                    sent = send_otp_email(se.lower().strip(), otp)
                    if sent:
                        st.success("OTP sent to your email.")
                    else:
                        st.warning(f"SMTP not configured; DEV MODE OTP: {otp}")

            if create_clicked:
                if not se or not EMAIL_RE.match(se):
                    st.error("Enter a valid email.")
                elif not otp_box or len(otp_box.strip()) != 6:
                    st.error("Enter the 6-digit OTP.")
                else:
                    # verify & create
                    ok = consume_signup_otp(se.lower().strip(), otp_box.strip())
                    if not ok:
                        st.error("Invalid or expired OTP.")
                    else:
                        # get hash from temp, but to simplify we'll ask password again or reuse sp1
                        try:
                            uid = create_user(se, sp1)  # store a fresh hash
                            st.session_state["user_id"] = uid
                            st.success("Account created & verified.")
                            st.rerun()
                        except Exception:
                            st.error("Could not create account (maybe email already used)")

    end_card()

    if not st.session_state.get("user_id"): st.stop()
    uid = st.session_state["user_id"]

    # --- Link car ---
    c2 = section_card("Link your car", "Use Car ID and Owner Secret from Admin (car must be active)")
    with c2:
        ccid = st.text_input("Car ID", key="claim_car_id")
        csec = st.text_input("Owner Secret", key="claim_secret")
        if st.button("Claim this car"):
            res = claim_car_for_user(ccid or "", csec or "", uid)
            if res == "ok":
                st.success("Car linked"); st.rerun()
            elif res == "already":
                left = st.session_state.get("last_days_left", 0)
                st.info(f"This car is already linked to you. QR will expire in {left} day(s).")
            else:
                st.error("Invalid / inactive Car ID or Owner Secret. Contact Admin.")
    end_card()

    # --- My vehicles ---
    c3 = section_card("My vehicles", "Docs via Google Drive links + Payment")
    with c3:
        mycars = list_user_cars(uid)
        if not mycars: st.caption("No cars linked yet.")
        pay_qr = get_setting_kv("payment_qr_url")
        pay_msg= get_setting_kv("payment_msg") or f"Scan the QR to pay ₹{QR_PRICE_INR}. Upload the screenshot below."

        for car in mycars:
            status = "🟢 Active" if car['is_active'] else "🔴 Inactive"
            left_days = int(car.get("days_left") or 0)
            expiry_note = f" · Expires in {left_days} day(s)" if car.get("expires_at") else ""
            st.markdown(f"### {car['owner_name']} · {car['car_no']}  {status}{expiry_note}")

            # Documents (Drive links)
            with st.form(f"docs_{car['id']}"):
                new_pw = st.text_input("Documents password (leave blank to keep)", type="password", key=f"pw_{car['id']}")
                rc  = st.text_input("RC (Google Drive link)", value=car.get("rc_url") or "", placeholder="https://drive.google.com/...", key=f"rc_{car['id']}")
                dl1 = st.text_input("DL (front) Drive link", value=car.get("dl_url") or "", placeholder="https://drive.google.com/...", key=f"dl1_{car['id']}")
                dl2 = st.text_input("DL (back) Drive link", value=car.get("dl_url2") or "", placeholder="https://drive.google.com/...", key=f"dl2_{car['id']}")
                puc = st.text_input("PUC Drive link", value=car.get("puc_url") or "", placeholder="https://drive.google.com/...", key=f"puc_{car['id']}")
                save_docs = st.form_submit_button("Save document links")
            if save_docs:
                # Just store links + password
                def update_owner_links(cid, rc, dl1, dl2, puc, new_pw):
                    sets = ["rc_url=:rc","dl_url=:dl1","dl_url2=:dl2","puc_url=:puc"]
                    params = dict(id=cid, rc=(rc or None), dl1=(dl1 or None), dl2=(dl2 or None), puc=(puc or None))
                    if (new_pw or "").strip():
                        sets.append("doc_password_hash=:hash")
                        params["hash"] = _hash_pw(new_pw.strip())
                    with engine.begin() as conn2:
                        conn2.execute(text(f"UPDATE cars SET {', '.join(sets)} WHERE id=:id"), params)
                update_owner_links(car["id"], rc, dl1, dl2, puc, new_pw)
                st.success("Saved")
                st.rerun()

            with st.expander("How to make a Google Drive link public"):
                st.markdown("""
1) Upload your file to Google Drive  
2) Right-click → **Get link**  
3) Change "Restricted" to **Anyone with the link**  
4) Copy link and paste it in the fields above  
""")

            st.markdown("---")
            # Payment section
            st.subheader("Payment")
            st.caption(f"Price: ₹{QR_PRICE_INR} • Status: " + ("**Done** ✅" if car.get("payment_status")=="done" else "**Pending** ⏳"))
            if pay_qr:
                st.image(pay_qr, caption="Scan to pay", use_container_width=False)
            st.write(pay_msg)

            proof = st.file_uploader("Upload payment screenshot (PNG/JPG/PDF)", type=["png","jpg","jpeg","pdf"], key=f"pay_{car['id']}")
            if proof is not None:
                pid = add_payment_proof(car["id"], uid, proof.name, proof.type or "application/octet-stream", proof.getvalue())
                st.success("Payment screenshot uploaded. Admin will verify and activate your QR.")
    end_card()
    st.stop()

# ==================== OWNER (legacy link) ====================
if page == "owner":
    enforce_expiry()
    if not owner_id or not secret: st.error("Invalid owner link"); st.stop()
    car = get_car(owner_id)
    if not car or str(car.get("owner_secret")) != str(secret):
        st.error("Invalid owner link"); st.stop()

    c = section_card(f"Owner Panel — {'Active' if car['is_active'] else 'Inactive'}",
                     f"{car['owner_name']} · {car['car_no']}", hero=True)
    with c:
        with st.form("owner_update"):
            new_pw = st.text_input("Set/Change password (leave blank to keep)",
                                   type="password", key=f"owner_pw_{owner_id}")
            st.markdown("<hr class='sep'/>", unsafe_allow_html=True)
            rc  = st.text_input("RC Drive link", value=car.get("rc_url") or "", placeholder="https://...")
            dl1 = st.text_input("DL (front) Drive link", value=car.get("dl_url") or "", placeholder="https://...")
            dl2 = st.text_input("DL (back) Drive link", value=car.get("dl_url2") or "", placeholder="https://...")
            puc = st.text_input("PUC Drive link", value=car.get("puc_url") or "", placeholder="https://...")
            row = st.columns([1,1])
            save = row[0].form_submit_button("Save changes")
            deact = row[1].form_submit_button("Deactivate QR") if car["is_active"] else None
        if save:
            def update_owner_links(cid, rc, dl1, dl2, puc, new_pw):
                sets = ["rc_url=:rc","dl_url=:dl1","dl_url2=:dl2","puc_url=:puc"]
                params = dict(id=cid, rc=(rc or None), dl1=(dl1 or None), dl2=(dl2 or None), puc=(puc or None))
                if (new_pw or "").strip():
                    sets.append("doc_password_hash=:hash")
                    params["hash"] = _hash_pw(new_pw.strip())
                with engine.begin() as conn2:
                    conn2.execute(text(f"UPDATE cars SET {', '.join(sets)} WHERE id=:id"), params)
            update_owner_links(owner_id, rc, dl1, dl2, puc, new_pw)
            st.success("Saved")
        if deact:
            set_active(owner_id, False); st.success("QR deactivated"); st.rerun()

        st.link_button("Open public page", public_url_for_car(owner_id), use_container_width=True)
    end_card()
    st.stop()

# ==================== PUBLIC ====================
if page == "public":
    enforce_expiry()
    if not car_id: st.error("Missing car id"); st.stop()
    car = get_car(car_id)
    if not car: st.error("Not found"); st.stop()
    if not car["is_active"]:
        c = section_card("QR inactive", "This QR is inactive or expired. Contact the owner.", hero=True)
        end_card(); st.stop()

    c = section_card("Vehicle contact", f"{car['owner_name']} · {car['car_no']}", hero=True)
    with c:
        st.link_button("Contact owner", tel_href(car["virtual_number"]), use_container_width=True)
        if car.get("expires_at"):
            st.caption(f"Active until: {car['expires_at']}")
        st.markdown("<hr class='sep'/>", unsafe_allow_html=True)
        st.subheader("View documents (password)")
        pw = st.text_input("Password", type="password", key=f"public_pw_{car_id}", placeholder="Enter password to unlock")
        if st.button("Unlock"):
            hash_ = car.get("doc_password_hash")
            if not hash_: st.error("Owner has not set a password yet.")
            elif _check_pw(hash_, (pw or "").strip()):
                left, right = st.columns(2)
                with left:
                    if car.get("rc_url"):  st.link_button("Open RC link", car["rc_url"], use_container_width=True)
                    if car.get("dl_url"):  st.link_button("Open DL (front) link", car["dl_url"], use_container_width=True)
                with right:
                    if car.get("dl_url2"): st.link_button("Open DL (back) link", car["dl_url2"], use_container_width=True)
                    if car.get("puc_url"): st.link_button("Open PUC link", car["puc_url"], use_container_width=True)
            else:
                st.error("Wrong password")
        st.caption(["Keep it moving.", "Small steps every day.", "Progress, not perfection."][int(time.time()) % 3])
    end_card()
    st.stop()
