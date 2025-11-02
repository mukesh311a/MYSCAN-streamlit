import os, io, uuid, time, re
import streamlit as st
from urllib.parse import urlencode
from sqlalchemy import create_engine, text
import qrcode, bcrypt
from PIL import Image

# ---------- SETTINGS ----------
def get_setting(key, default=None):
    # Prefer Streamlit Cloud secrets; fallback to env vars
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

if not DB_URL:
    st.error("DATABASE_URL is not set. Add it in Streamlit → App settings → Secrets.")
    st.stop()

# ---------- DB ----------
engine = create_engine(DB_URL, pool_pre_ping=True)

def ensure_schema():
    with engine.begin() as conn:
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
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );"""))
        # Safety: add columns if an old table exists
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS dl_url2 TEXT;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS puc_url TEXT;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS owner_secret UUID;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;"))
        conn.execute(text("UPDATE cars SET is_active=TRUE WHERE is_active IS NULL;"))
        rows = conn.execute(text("SELECT id, owner_secret FROM cars WHERE owner_secret IS NULL LIMIT 1")).fetchall()
        for _ in rows:
            conn.execute(text("UPDATE cars SET owner_secret=:s WHERE owner_secret IS NULL"), {"s": str(uuid.uuid4())})

ensure_schema()

# ---------- UTIL ----------
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
    base = PUBLIC_BASE or ""  # set this in secrets for perfect QR links
    return f"{base}?"+ urlencode({"page": "public", "c": car_id}) if base else f"?page=public&c={car_id}"

def owner_url_for_car(car_id: str, secret: str) -> str:
    base = PUBLIC_BASE or ""
    return f"{base}?"+ urlencode({"page": "owner", "owner": car_id, "secret": secret}) if base else f"?page=owner&owner={car_id}&secret={secret}"

# ---------- DATA ACCESS ----------
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

# ---------- UI THEME ----------
st.set_page_config(page_title="MYSCAN", page_icon="🔗", layout="centered")
st.markdown("""
<style>
:root { --card-bg: #0f172a; --border:#1e293b; --muted:#9fb0c3; --accent:#22d3ee; }
.block-container { padding-top: 2rem; }
.card { background: linear-gradient(180deg, rgba(15,23,42,.92), rgba(15,23,42,.86));
        border:1px solid var(--border); border-radius:18px; padding:20px; }
.btn a, .stButton>button { border-radius:12px; padding:10px 16px; font-weight:600; }
.badge { display:inline-block; padding:4px 10px; border:1px solid var(--border); border-radius:999px; color:var(--muted); font-size:12px; }
.small { color:var(--muted); font-size:13px }
h1, h2, h3 { margin-bottom: .4rem; }
</style>
""", unsafe_allow_html=True)

def header(title: str, subtitle: str = ""):
    st.markdown(f"<div class='card'><h1>{title}</h1><p class='small'>{subtitle}</p></div>", unsafe_allow_html=True)

# ---------- ROUTER ----------
qs = st.query_params
page = qs.get("page") or ""
car_id = qs.get("c")
owner_id = qs.get("owner")
secret = qs.get("secret")

# ---------- ADMIN ----------
if page == "admin":
    header("Admin", "Create & manage vehicle QRs")
    pwd = st.text_input("Password", type="password")
    if st.button("Sign in"):
        if (pwd or "").strip() == ADMIN_PASSWORD:
            st.session_state["admin_ok"] = True
        else:
            st.error("Wrong password")
    if not st.session_state.get("admin_ok"):
        st.stop()

    st.success("Signed in")
    if not PUBLIC_BASE:
        st.info("Tip: Set PUBLIC_BASE_URL in secrets for correct QR links (e.g. https://myscan.streamlit.app).")

    st.divider()
    st.subheader("Generate new QR")
    with st.form("create"):
        col1, col2 = st.columns(2)
        with col1:
            on = st.text_input("Owner name*")
            cn = st.text_input("Car no*")
            op = st.text_input("Owner mobile (record)*")
        with col2:
            vn = st.text_input("Proxy/Virtual number*")
            rc = st.text_input("RC link (optional)")
            docpw = st.text_input("Docs password (optional)", type="password")
        c3, c4 = st.columns(2)
        with c3:
            dl1 = st.text_input("DL front link (optional)")
            puc = st.text_input("Pollution (PUC) link (optional)")
        with c4:
            dl2 = st.text_input("DL back link (optional)")
            st.markdown("<span class='small'>Links open directly after password unlock.</span>", unsafe_allow_html=True)
        s = st.form_submit_button("Generate QR")

    if s:
        if not on or not cn or not op or not vn:
            st.error("Fill required fields.")
        else:
            op_s = sanitize_phone(op)
            vn_s = sanitize_phone(vn)
            if not op_s or not vn_s:
                st.error("Enter valid phone numbers (7-15 digits, optional +).")
            else:
                new_id, owner_secret = create_car(on, cn, op_s, vn_s, rc, dl1, dl2, puc, docpw or "")
                pub_url = public_url_for_car(new_id)
                own_url = owner_url_for_car(new_id, owner_secret)
                st.info(f"Public URL: {pub_url}")
                st.info(f"Owner Panel URL: {own_url}")
                st.download_button("Download Public QR", make_qr_png(pub_url), file_name=f"qr-{new_id}.png", mime="image/png")
                st.download_button("Download Owner Panel QR", make_qr_png(own_url), file_name=f"owner-qr-{new_id}.png", mime="image/png")

    st.divider()
    st.subheader("Vehicles")
    rows = list_cars()
    for r in rows:
        c1, c2, c3 = st.columns([3,2,3])
        with c1:
            st.write(f"**{r['owner_name']}**  ·  {r['car_no']}")
            st.caption(str(r['created_at']))
        with c2:
            st.markdown(f"<span class='badge'>{'Active' if r['is_active'] else 'Inactive'}</span>", unsafe_allow_html=True)
        with c3:
            pub_link = public_url_for_car(r['id'])
            st.link_button("Open Public", pub_link)
            with st.popover("Actions"):
                colA, colB, colC = st.columns(3)
                if r['is_active']:
                    if colA.button("Deactivate", key=f"deact-{r['id']}"):
                        set_active(r['id'], False); st.rerun()
                else:
                    if colA.button("Reactivate", key=f"react-{r['id']}"):
                        set_active(r['id'], True); st.rerun()
                # "Regenerate" just re-downloads with current base URL
                if colB.button("Regenerate QRs", key=f"regen-{r['id']}"):
                    st.success("Use the download buttons below:")
                    st.download_button("Public QR", make_qr_png(pub_link), file_name=f"qr-{r['id']}.png", mime="image/png", key=f"dpub-{r['id']}")
                    # Owner link fetch (need owner_secret)
                    car = get_car(r['id']); own_link = owner_url_for_car(r['id'], car['owner_secret'])
                    st.download_button("Owner QR", make_qr_png(own_link), file_name=f"owner-qr-{r['id']}.png", mime="image/png", key=f"down-{r['id']}")
                if colC.button("Copy public URL", key=f"copy-{r['id']}"):
                    st.write(pub_link)

    st.stop()

# ---------- OWNER PANEL ----------
if page == "owner":
    if not owner_id or not secret:
        st.error("Invalid owner link"); st.stop()
    car = get_car(owner_id)
    if not car or str(car.get("owner_secret")) != str(secret):
        st.error("Invalid owner link"); st.stop()

    header(f"Owner Panel — {'Active' if car['is_active'] else 'Inactive'}", f"{car['owner_name']} · {car['car_no']}")
    with st.form("owner_update"):
        new_pw = st.text_input("Set/Change password (leave blank to keep)", type="password")
        rc = st.text_input("RC link", value=car.get("rc_url") or "")
        dl1= st.text_input("DL front", value=car.get("dl_url") or "")
        dl2= st.text_input("DL back", value=car.get("dl_url2") or "")
        puc= st.text_input("Pollution (PUC)", value=car.get("puc_url") or "")
        save = st.form_submit_button("Save changes")
    if save:
        update_owner(owner_id, rc, dl1, dl2, puc, new_pw)
        st.success("Saved")

    c1, c2 = st.columns(2)
    if car["is_active"]:
        if c1.button("Deactivate QR", type="primary"):
            set_active(owner_id, False); st.rerun()
    else:
        st.info("This QR is inactive. Ask Admin to reactivate from dashboard.")
    st.link_button("Open Public Page", public_url_for_car(owner_id))
    st.stop()

# ---------- PUBLIC ----------
if page == "public":
    if not car_id:
        st.error("Missing car id"); st.stop()
    car = get_car(car_id)
    if not car:
        st.error("Not found"); st.stop()
    if not car["is_active"]:
        header("QR inactive", "This QR has been deactivated by the owner or admin.")
        st.stop()

    header("Vehicle contact", f"{car['owner_name']} · {car['car_no']}")
    st.link_button("Contact owner", tel_href(car["virtual_number"]))

    st.divider()
    st.subheader("View documents (password)")
    pw = st.text_input("Password", type="password")
    if st.button("Unlock"):
        hash_ = car.get("doc_password_hash")
        if not hash_:
            st.error("Owner has not set a password yet.")
        elif bcrypt.checkpw((pw or "").strip().encode(), hash_.encode()):
            if car.get("rc_url"):  st.link_button("Show RC", car["rc_url"])
            if car.get("dl_url"):  st.link_button("Show DL (front)", car["dl_url"])
            if car.get("dl_url2"): st.link_button("Show DL (back)", car["dl_url2"])
            if car.get("puc_url"): st.link_button("Show Pollution", car["puc_url"])
        else:
            st.error("Wrong password")

    # small, rotating encouragement
    quotes = [
        "Believe you can and you’re halfway there.",
        "Small steps every day.",
        "Stay curious, stay kind.",
        "Do the next right thing.",
        "Progress, not perfection.",
        "Make it simple, make it better."
    ]
    st.caption(quotes[int(time.time()) % len(quotes)])
    st.stop()

# ---------- HOME (help) ----------
header("MYSCAN", "Add ?page=admin to manage, or use a QR to open a public car page.")
st.write("Examples:")
st.code("?page=admin", language="text")
st.code("?page=public&c=<car_id>", language="text")
st.code("?page=owner&owner=<car_id>&secret=<owner_secret>", language="text")
