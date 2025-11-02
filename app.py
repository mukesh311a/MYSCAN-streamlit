import os, io, uuid, time, re
import streamlit as st
from urllib.parse import urlencode
from sqlalchemy import create_engine, text
import qrcode, bcrypt
from PIL import Image

# =========================
# Settings & DB URL helper
# =========================
def get_setting(key, default=None):
    return st.secrets.get(key, os.getenv(key, default))

def fix_db_url(url: str) -> str:
    if not url:
        return url
    # Normalize to SQLAlchemy + psycopg3 driver
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

if not DB_URL:
    st.error("DATABASE_URL is not set. Add it in Streamlit → App settings → Secrets.")
    st.stop()

# ===========
# DB
# ===========
engine = create_engine(DB_URL, pool_pre_ping=True)

def ensure_schema():
    with engine.begin() as conn:
        # main cars table
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
          is_active BOOLEAN NOT NULL DEFAULT TRUE,
          owner_user_id UUID,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );"""))
        # add any missing columns on existing installs
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS dl_url2 TEXT;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS puc_url TEXT;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS owner_secret UUID;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS owner_user_id UUID;"))
        conn.execute(text("UPDATE cars SET is_active=TRUE WHERE is_active IS NULL;"))

        # users (for User Dashboard)
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
          id UUID PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );"""))

        # uploaded docs (optional, per car + kind)
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS docs (
          id UUID PRIMARY KEY,
          car_id UUID NOT NULL REFERENCES cars(id) ON DELETE CASCADE,
          kind TEXT NOT NULL CHECK (kind IN ('rc','dl1','dl2','puc')),
          filename TEXT,
          mime TEXT,
          content BYTEA,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );"""))
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS docs_car_kind_idx ON docs(car_id, kind);"))

ensure_schema()

# ===========
# Utils
# ===========
PHONE_RE = re.compile(r"(\+?\d{7,15})")
def sanitize_phone(s: str) -> str:
    if not s: return ""
    m = PHONE_RE.search(str(s))
    if not m: return ""
    return m.group(1).replace("+", "", 1) if m.group(1).count("+") > 1 else m.group(1)

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

# ===========
# Data access: cars
# ===========
def create_car(owner_name, car_no, owner_phone, virtual_number, rc, dl1, dl2, puc, doc_pw):
    with engine.begin() as conn:
        car_id = str(uuid.uuid4())
        owner_secret = str(uuid.uuid4())
        pw_hash = bcrypt.hashpw(doc_pw.encode(), bcrypt.gensalt()).decode() if (doc_pw or "").strip() else None
        conn.execute(text("""
          INSERT INTO cars (id, owner_name, car_no, owner_phone, virtual_number,
                            rc_url, dl_url, dl_url2, puc_url, doc_password_hash, owner_secret, is_active)
          VALUES (:id,:on,:cn,:op,:vn,:rc,:dl1,:dl2,:puc,:hash,:sec,TRUE)
        """), dict(id=car_id, on=owner_name, cn=car_no, op=owner_phone, vn=virtual_number,
                   rc=rc, dl1=dl1, dl2=dl2, puc=puc, hash=pw_hash, sec=owner_secret))
        return car_id, owner_secret

def get_car(car_id: str):
    with engine.begin() as conn:
        row = conn.execute(text("SELECT * FROM cars WHERE id=:id"), dict(id=car_id)).mappings().first()
        return dict(row) if row else None

def list_cars():
    with engine.begin() as conn:
        rows = conn.execute(text("""
        SELECT id, owner_name, car_no, created_at, is_active FROM cars ORDER BY created_at DESC
        """)).mappings().all()
        return [dict(r) for r in rows]

def set_active(car_id: str, active: bool):
    with engine.begin() as conn:
        conn.execute(text("UPDATE cars SET is_active=:a WHERE id=:id"), dict(a=active, id=car_id))

def update_owner(car_id, rc, dl1, dl2, puc, new_pw):
    sets = ["rc_url=:rc","dl_url=:dl1","dl_url2=:dl2","puc_url=:puc"]
    params = dict(id=car_id, rc=(rc or None), dl1=(dl1 or None), dl2=(dl2 or None), puc=(puc or None))
    if (new_pw or "").strip():
        sets.append("doc_password_hash=:hash")
        params["hash"] = bcrypt.hashpw(new_pw.strip().encode(), bcrypt.gensalt()).decode()
    with engine.begin() as conn:
        conn.execute(text(f"UPDATE cars SET {', '.join(sets)} WHERE id=:id"), params)

# ===========
# Data access: users & ownership
# ===========
def create_user(email: str, password: str):
    with engine.begin() as conn:
        uid = str(uuid.uuid4())
        ph = bcrypt.hashpw(password.strip().encode(), bcrypt.gensalt()).decode()
        conn.execute(text("""
          INSERT INTO users (id, email, password_hash) VALUES (:id,:e,:p)
        """), dict(id=uid, e=email.strip().lower(), p=ph))
        return uid

def auth_user(email: str, password: str):
    with engine.begin() as conn:
        row = conn.execute(text("SELECT id, password_hash FROM users WHERE email=:e"),
                           dict(e=email.strip().lower())).mappings().first()
        if not row: return None
        return row["id"] if bcrypt.checkpw(password.strip().encode(), row["password_hash"].encode()) else None

def claim_car_for_user(car_id: str, owner_secret: str, user_id: str) -> bool:
    with engine.begin() as conn:
        car = conn.execute(text("SELECT id, owner_secret FROM cars WHERE id=:id"), dict(id=car_id)).mappings().first()
        if not car or str(car["owner_secret"]) != str(owner_secret):
            return False
        conn.execute(text("UPDATE cars SET owner_user_id=:u WHERE id=:id"), dict(u=user_id, id=car_id))
        return True

def list_user_cars(user_id: str):
    with engine.begin() as conn:
        rows = conn.execute(text("""
          SELECT * FROM cars WHERE owner_user_id=:u ORDER BY created_at DESC
        """), dict(u=user_id)).mappings().all()
        return [dict(r) for r in rows]

# ===========
# Data access: uploaded docs
# ===========
def get_docs_for_car(car_id: str):
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT * FROM docs WHERE car_id=:c"), dict(c=car_id)).mappings().all()
        out = {}
        for r in rows:
            out[r["kind"]] = dict(r)
        return out

def upsert_doc(car_id: str, kind: str, filename: str, mime: str, data: bytes):
    with engine.begin() as conn:
        doc_id = str(uuid.uuid4())
        conn.execute(text("""
          INSERT INTO docs (id, car_id, kind, filename, mime, content)
          VALUES (:id,:c,:k,:f,:m,:d)
          ON CONFLICT (car_id, kind) DO UPDATE
          SET filename=excluded.filename, mime=excluded.mime, content=excluded.content, created_at=now()
        """), dict(id=doc_id, c=car_id, k=kind, f=filename, m=mime, d=data))
        return doc_id

# ===========
# UI theme (white + dark-blue + light-orange)
# ===========
st.set_page_config(page_title="MYSCAN", page_icon="🚗", layout="centered")

st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
html, body, [data-testid="stAppViewContainer"] * { font-family: 'Inter', system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }
[data-testid="stAppViewContainer"] { background: #ffffff; }
.topbar {
  position: sticky; top: 0; z-index: 1000;
  background: rgba(255,255,255,.9); backdrop-filter: blur(8px);
  border-bottom: 1px solid #e6eef6;
  margin-bottom: 18px; padding: 10px 14px; border-radius: 0 0 16px 16px;
}
.topbar .brand { font-weight: 800; letter-spacing: .2px; font-size: 18px; color: #0b1b3a }
.topbar .muted { color: #4a6786; font-weight: 600; }
.topbar a { color: #1d4ed8; text-decoration: none; margin-left: 14px; }
.card {
  background: #ffffff;
  border:1px solid #e6eef6; border-radius: 16px;
  padding: 22px; box-shadow: 0 12px 30px rgba(12, 35, 64, .06);
  color: #0b1b3a;
}
.hero { background: linear-gradient(180deg, #ffffff, #f8fbff); }
.h1 { font-size: 28px; margin: 0 0 8px; color: #0b1b3a; }
.subtle { color: #4a6786; margin: 0; }
.grid2 { display:grid; grid-template-columns: 1fr 1fr; gap: 14px; }
@media (max-width: 820px){ .grid2 { grid-template-columns:1fr; } }
.chip { display:inline-block; padding:6px 10px; border-radius:999px; border:1px solid #e6eef6; color:#4a6786; font-size:12px; background:#f3f8ff; }
.kv { display:grid; grid-template-columns: 160px 1fr; gap:10px; margin-top: 8px; }
.kv div { padding: 10px 0; border-bottom: 1px solid #e6eef6; }
.note { color:#4a6786; font-size: 13px; }
.sep { border:0; border-top:1px solid #e6eef6; margin:18px 0; }

/* Inputs */
.stTextInput>div>div>input, .stTextInput>label, .stTextArea textarea {
  background: #ffffff !important; color: #0b1b3a !important; border:1px solid #e6eef6 !important; border-radius: 10px !important;
}

/* Buttons: light orange primary, blue secondary, subtle ghost */
.stButton>button, .stLinkButton>button {
  border-radius: 12px !important; padding: 12px 18px !important; font-weight: 700 !important;
  border: 1px solid #ffd7b3 !important; color: #5b2400 !important;
  background: linear-gradient(180deg,#ffe6cc,#ffcc99) !important; /* light orange */
  box-shadow: 0 8px 20px rgba(255, 153, 51, .25) !important;
}
.stButton>button:hover, .stLinkButton>button:hover { filter: brightness(1.03); }
.btn-secondary button {
  background: linear-gradient(180deg,#e6f0ff,#cfe0ff) !important; color: #0b1b3a !important; border:1px solid #c7d7f7 !important;
  box-shadow: 0 8px 20px rgba(29, 78, 216, .12) !important;
}
.btn-ghost button {
  background: #ffffff !important; color: #4a6786 !important; border: 1px solid #e6eef6 !important; box-shadow:none !important;
}
.btn-warn button {
  background: linear-gradient(180deg,#ffe5e5,#ffd0b3) !important; color: #5b2400 !important; border:1px solid #ffc2a3 !important;
}

/* small bits */
.qr-preview { border:1px dashed #dbe7f3; border-radius:12px; padding:10px; background:#fbfdff; }
.help ul { margin: 0 0 0 18px; }
</style>
""", unsafe_allow_html=True)

# sticky topbar
st.markdown(
    """
<div class="topbar">
  <span class="brand">MYSCAN</span>
  <span class="muted">· Smart vehicle QR</span>
  <span style="float:right">
    <a href="?page=user">User dashboard</a>
    <a href="?page=admin">Admin</a>
    <a href="?">Home</a>
  </span>
</div>
""",
    unsafe_allow_html=True,
)

def section_card(title: str, subtitle: str = "", hero=False):
    cls = "card hero" if hero else "card"
    st.markdown(f"<div class='{cls}'><div class='h1'>{title}</div><p class='subtle'>{subtitle}</p>", unsafe_allow_html=True)
    return st.container()

def end_card():
    st.markdown("</div>", unsafe_allow_html=True)

# ===========
# Router
# ===========
qs = st.query_params
page = qs.get("page") or ""
car_id = qs.get("c")
owner_id = qs.get("owner")
secret = qs.get("secret")

# ===========
# Admin
# ===========
if page == "admin":
    c = section_card("Admin dashboard", "Create & manage vehicle QRs", hero=True)
    with c:
        cols = st.columns([2,1])
        with cols[0]:
            pwd = st.text_input("Admin password", type="password", placeholder="Enter admin password")
            sign = st.button("Sign in", key="signin_btn")
            if sign:
                if (pwd or "").strip() == ADMIN_PASSWORD:
                    st.session_state["admin_ok"] = True
                else:
                    st.error("Wrong password")
        with cols[1]:
            st.markdown("<div class='chip'>Environment</div>", unsafe_allow_html=True)
            st.caption(f"Base URL: {PUBLIC_BASE or '(not set)'}")
    end_card()

    if not st.session_state.get("admin_ok"):
        st.stop()

    # Create
    c2 = section_card("Generate new QR", "Fill in the details below")
    with c2:
        if not PUBLIC_BASE:
            st.info("Tip: set PUBLIC_BASE_URL in Secrets so QR codes use your live domain.")
        with st.form("create"):
            g = st.columns(2)
            with g[0]:
                on = st.text_input("Owner name *", placeholder="e.g. Mukesh Kumar")
                cn = st.text_input("Car number *", placeholder="e.g. DL01AB1234")
                op = st.text_input("Owner mobile (record) *", placeholder="+91XXXXXXXXXX")
            with g[1]:
                vn = st.text_input("Proxy/Virtual number *", placeholder="+91XXXXXXXXXX")
                rc = st.text_input("RC link (optional)", placeholder="https://...")
                docpw = st.text_input("Docs password (optional)", type="password")
            h = st.columns(2)
            with h[0]:
                dl1 = st.text_input("DL front link (optional)", placeholder="https://...")
            with h[1]:
                dl2 = st.text_input("DL back link (optional)", placeholder="https://...")
            puc = st.text_input("Pollution (PUC) link (optional)", placeholder="https://...")
            s = st.form_submit_button("Create & generate QRs")

        if s:
            if not on or not cn or not op or not vn:
                st.error("Please fill all required fields.")
            else:
                op_s = sanitize_phone(op)
                vn_s = sanitize_phone(vn)
                if not op_s or not vn_s:
                    st.error("Enter valid phone numbers (7–15 digits, optional +).")
                else:
                    new_id, owner_secret = create_car(on, cn, op_s, vn_s, rc, dl1, dl2, puc, docpw or "")
                    pub_url = public_url_for_car(new_id)
                    own_url = owner_url_for_car(new_id, owner_secret)
                    st.success("QRs ready")

                    pcols = st.columns([1,1])
                    with pcols[0]:
                        st.markdown("**Public page**")
                        st.code(pub_url, language="text")
                        st.image(Image.open(io.BytesIO(make_qr_png(pub_url))), caption="Public QR", use_column_width=False)
                        st.download_button("Download Public QR", make_qr_png(pub_url), file_name=f"qr-{new_id}.png", mime="image/png")
                    with pcols[1]:
                        st.markdown("**Owner panel**")
                        st.code(own_url, language="text")
                        st.image(Image.open(io.BytesIO(make_qr_png(own_url))), caption="Owner Panel QR", use_column_width=False)
                        st.download_button("Download Owner QR", make_qr_png(own_url), file_name=f"owner-qr-{new_id}.png", mime="image/png")
    end_card()

    # List
    c3 = section_card("Vehicles", "Manage status, open public page, regenerate QRs")
    with c3:
        rows = list_cars()
        if not rows:
            st.caption("No entries yet.")
        for r in rows:
            box = st.columns([5,2,3,3])
            with box[0]:
                st.markdown(f"**{r['owner_name']}** · {r['car_no']}")
                st.caption(str(r['created_at']))
            with box[1]:
                st.markdown(f"<span class='chip'>{'Active' if r['is_active'] else 'Inactive'}</span>", unsafe_allow_html=True)
            with box[2]:
                pub_link = public_url_for_car(r['id'])
                st.link_button("Open public", pub_link)
            with box[3]:
                a, b, cbtn = st.columns(3)
                if r['is_active']:
                    if a.button("Deactivate", key=f"btn-deact-{r['id']}"):
                        set_active(r['id'], False); st.rerun()
                else:
                    if a.button("Reactivate", key=f"btn-react-{r['id']}"):
                        set_active(r['id'], True); st.rerun()
                if b.button("Regenerate QRs", key=f"regen-{r['id']}"):
                    car = get_car(r['id'])
                    own_link = owner_url_for_car(r['id'], car['owner_secret'])
                    st.success("Download fresh QR images below.")
                    d1, d2 = st.columns(2)
                    with d1:
                        st.download_button("Public QR", make_qr_png(pub_link), file_name=f"qr-{r['id']}.png", mime="image/png", key=f"dpub-{r['id']}")
                    with d2:
                        st.download_button("Owner QR", make_qr_png(own_link), file_name=f"owner-qr-{r['id']}.png", mime="image/png", key=f"down-{r['id']}")
                if cbtn.button("Copy URL", key=f"copy-{r['id']}"):
                    st.code(pub_link, language="text")
    end_card()
    st.stop()

# ===========
# User dashboard (NEW)
# ===========
if page == "user":
    # Auth UI
    c = section_card("User dashboard", "Sign in to manage your vehicle documents", hero=True)
    with c:
        tab_login, tab_signup = st.tabs(["Sign in", "Create account"])
        with tab_login:
            le = st.text_input("Email")
            lp = st.text_input("Password", type="password")
            if st.button("Sign in", key="user_signin"):
                uid = auth_user(le or "", lp or "")
                if uid:
                    st.session_state["user_id"] = uid
                    st.success("Signed in")
                    st.rerun()
                else:
                    st.error("Invalid email or password")
        with tab_signup:
            se = st.text_input("Email (for new account)")
            sp1 = st.text_input("Password", type="password")
            sp2 = st.text_input("Confirm password", type="password")
            if st.button("Create account", key="user_signup"):
                if not se or not sp1 or sp1 != sp2:
                    st.error("Enter email and matching passwords")
                else:
                    try:
                        uid = create_user(se, sp1)
                        st.session_state["user_id"] = uid
                        st.success("Account created")
                        st.rerun()
                    except Exception as e:
                        st.error("Could not create account (maybe email already used)")
    end_card()

    # If not signed in, stop
    if not st.session_state.get("user_id"):
        st.stop()

    # Signed in view
    uid = st.session_state["user_id"]
    c2 = section_card("Link your car", "Use Owner Secret (from Admin) to claim your car and manage docs")
    with c2:
        ccid = st.text_input("Car ID")
        csec = st.text_input("Owner Secret")
        if st.button("Claim this car"):
            if claim_car_for_user(ccid or "", csec or "", uid):
                st.success("Car linked to your account"); st.rerun()
            else:
                st.error("Invalid Car ID or Owner Secret")
    end_card()

    c3 = section_card("My vehicles", "Update password, links, and upload documents")
    with c3:
        mycars = list_user_cars(uid)
        if not mycars:
            st.caption("No cars linked yet.")
        for car in mycars:
            st.markdown(f"### {car['owner_name']} · {car['car_no']}  "
                        f"{'🟢 Active' if car['is_active'] else '🔴 Inactive'}")
            with st.form(f"edit-{car['id']}"):
                new_pw = st.text_input("Docs password (leave blank to keep)", type="password")
                rc = st.text_input("RC link", value=car.get("rc_url") or "", placeholder="https://...")
                dl1= st.text_input("DL (front) link", value=car.get("dl_url") or "", placeholder="https://...")
                dl2= st.text_input("DL (back) link", value=car.get("dl_url2") or "", placeholder="https://...")
                puc= st.text_input("Pollution (PUC) link", value=car.get("puc_url") or "", placeholder="https://...")

                st.markdown("<hr class='sep'/>", unsafe_allow_html=True)
                st.caption("Optional uploads (small PDFs/images). If provided, they’ll show as downloadable files after password unlock on the public page.")
                up_rc  = st.file_uploader("Upload RC file", type=["pdf","png","jpg","jpeg"], key=f"rc-{car['id']}")
                up_dl1 = st.file_uploader("Upload DL (front)", type=["pdf","png","jpg","jpeg"], key=f"dl1-{car['id']}")
                up_dl2 = st.file_uploader("Upload DL (back)", type=["pdf","png","jpg","jpeg"], key=f"dl2-{car['id']}")
                up_puc = st.file_uploader("Upload PUC", type=["pdf","png","jpg","jpeg"], key=f"puc-{car['id']}")

                col = st.columns(3)
                save = col[0].form_submit_button("Save changes")
                if car["is_active"]:
                    deact = col[1].form_submit_button("Deactivate QR")
                    react = None
                else:
                    react = col[1].form_submit_button("Reactivate QR")
                    deact = None

            if save:
                update_owner(car["id"], rc, dl1, dl2, puc, new_pw)
                # handle uploads
                for blob, kind in [(up_rc,"rc"),(up_dl1,"dl1"),(up_dl2,"dl2"),(up_puc,"puc")]:
                    if blob is not None:
                        upsert_doc(car["id"], kind, blob.name, blob.type or "application/octet-stream", blob.getvalue())
                st.success("Saved")
                st.rerun()
            if deact:
                set_active(car["id"], False); st.success("QR deactivated"); st.rerun()
            if react:
                set_active(car["id"], True); st.success("QR reactivated"); st.rerun()
    end_card()
    st.stop()

# ===========
# Owner panel (legacy secret link)
# ===========
if page == "owner":
    if not owner_id or not secret:
        st.error("Invalid owner link"); st.stop()
    car = get_car(owner_id)
    if not car or str(car.get("owner_secret")) != str(secret):
        st.error("Invalid owner link"); st.stop()

    c = section_card(f"Owner Panel — {'Active' if car['is_active'] else 'Inactive'}",
                     f"{car['owner_name']} · {car['car_no']}", hero=True)
    with c:
        with st.form("owner_update"):
            st.markdown("**Password**")
            new_pw = st.text_input("Set/Change password (leave blank to keep)", type="password", placeholder="Enter a new password")
            st.markdown("<hr class='sep'/>", unsafe_allow_html=True)
            st.markdown("**Documents (links)**")
            rc = st.text_input("RC link", value=car.get("rc_url") or "", placeholder="https://...")
            dl1= st.text_input("DL (front)", value=car.get("dl_url") or "", placeholder="https://...")
            dl2= st.text_input("DL (back)", value=car.get("dl_url2") or "", placeholder="https://...")
            puc= st.text_input("Pollution (PUC)", value=car.get("puc_url") or "", placeholder="https://...")
            row = st.columns([1,1])
            with row[0]:
                save = st.form_submit_button("Save changes")
            with row[1]:
                if car["is_active"]:
                    deact = st.form_submit_button("Deactivate QR")
                else:
                    deact = None
        if save:
            update_owner(owner_id, rc, dl1, dl2, puc, new_pw)
            st.success("Saved")
        if deact:
            set_active(owner_id, False); st.success("QR deactivated"); st.rerun()

        st.link_button("Open public page", public_url_for_car(owner_id), use_container_width=True)
    end_card()
    st.stop()

# ===========
# Public
# ===========
if page == "public":
    if not car_id:
        st.error("Missing car id"); st.stop()
    car = get_car(car_id)
    if not car:
        st.error("Not found"); st.stop()
    if not car["is_active"]:
        c = section_card("QR inactive", "This QR has been deactivated by the owner or admin.", hero=True)
        end_card(); st.stop()

    c = section_card("Vehicle contact", f"{car['owner_name']} · {car['car_no']}", hero=True)
    with c:
        st.link_button("Contact owner", tel_href(car["virtual_number"]), use_container_width=True)
        st.markdown("<hr class='sep'/>", unsafe_allow_html=True)
        st.subheader("View documents (password)")
        pw = st.text_input("Password", type="password", placeholder="Enter password to unlock")
        if st.button("Unlock"):
            hash_ = car.get("doc_password_hash")
            if not hash_:
                st.error("Owner has not set a password yet.")
            elif bcrypt.checkpw((pw or "").strip().encode(), hash_.encode()):
                # links
                g1 = st.columns(2)
                with g1[0]:
                    if car.get("rc_url"):  st.link_button("Open RC link", car["rc_url"], use_container_width=True)
                    if car.get("dl_url"):  st.link_button("Open DL (front) link", car["dl_url"], use_container_width=True)
                with g1[1]:
                    if car.get("dl_url2"): st.link_button("Open DL (back) link", car["dl_url2"], use_container_width=True)
                    if car.get("puc_url"): st.link_button("Open PUC link", car["puc_url"], use_container_width=True)

                # uploaded files (if any)
                docs = get_docs_for_car(car_id)
                if docs:
                    st.markdown("<hr class='sep'/>", unsafe_allow_html=True)
                    st.subheader("Downloads (uploaded)")
                    dcols = st.columns(2)
                    order = [("rc","RC"),("dl1","DL (front)"),("dl2","DL (back)"),("puc","PUC")]
                    i = 0
                    for k,label in order:
                        if k in docs and docs[k].get("content"):
                            data = bytes(docs[k]["content"])
                            name = docs[k].get("filename") or f"{k}.bin"
                            with dcols[i%2]:
                                st.download_button(f"Download {label}", data, file_name=name,
                                                   mime=docs[k].get("mime") or "application/octet-stream", use_container_width=True)
                            i += 1
            else:
                st.error("Wrong password")
        st.caption(["Keep it moving.", "Small steps every day.", "Progress, not perfection."][int(time.time()) % 3])
    end_card()
    st.stop()

# ===========
# Home
# ===========
c = section_card("MYSCAN", "User dashboard for owners, Admin for creation, Public via QR.", hero=True)
with c:
    st.markdown("""
<div class="help">
  <ul>
    <li><a href="?page=user">User dashboard</a> — sign in, claim car, update links, upload docs</li>
    <li><a href="?page=admin">Admin</a> — create car entries & generate QRs</li>
    <li><code>?page=public&c=&lt;car_id&gt;</code> — public view from QR</li>
</div>
""", unsafe_allow_html=True)
end_card()
