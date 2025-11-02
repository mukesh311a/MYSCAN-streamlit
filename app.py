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
    # Normalize to SQLAlchemy + psycopg3
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
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS dl_url2 TEXT;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS puc_url TEXT;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS owner_secret UUID;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;"))
        conn.execute(text("UPDATE cars SET is_active=TRUE WHERE is_active IS NULL;"))
        rows = conn.execute(text("SELECT id FROM cars WHERE owner_secret IS NULL LIMIT 1")).fetchall()
        for _ in rows:
            conn.execute(text("UPDATE cars SET owner_secret=:s WHERE owner_secret IS NULL"), {"s": str(uuid.uuid4())})
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
# Data access
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
# UI theme & helpers
# ===========
st.set_page_config(page_title="MYSCAN", page_icon="🚗", layout="centered")

st.markdown("""
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
html, body, [data-testid="stAppViewContainer"] * { font-family: 'Inter', system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }
[data-testid="stAppViewContainer"] {
  background:
    radial-gradient(1300px 700px at 10% -10%, #122143 0%, transparent 60%),
    radial-gradient(1000px 600px at 90% 10%, #1b2b49 0%, transparent 55%),
    linear-gradient(180deg,#0a0f1a,#0e1426);
}
.topbar {
  position: sticky; top: 0; z-index: 1000;
  background: rgba(9,12,20,.75); backdrop-filter: blur(10px);
  border-bottom: 1px solid #1e293b;
  margin-bottom: 18px; padding: 10px 14px; border-radius: 0 0 16px 16px;
}
.topbar .brand { font-weight: 800; letter-spacing: .2px; font-size: 18px; color: #e2e8f0 }
.topbar .muted { color: #8aa0b7; font-weight: 600; }
.topbar a { color: #8dd1ff; text-decoration: none; margin-left: 14px; }
.card {
  background: linear-gradient(180deg, rgba(15,23,42,.92), rgba(15,23,42,.86));
  border:1px solid #1e293b; border-radius: 20px;
  padding: 22px; box-shadow: 0 20px 48px rgba(0,0,0,.45);
}
.hero {
  position: relative; overflow: hidden;
  background:
    radial-gradient(650px 240px at 15% 0%, rgba(94,234,212,.12), transparent 65%),
    radial-gradient(650px 240px at 85% 10%, rgba(192,132,252,.12), transparent 70%);
}
.h1 { font-size: 30px; margin: 0 0 8px; color: #ecf2f8; }
.subtle { color: #9fb0c3; margin: 0; }
.grid2 { display:grid; grid-template-columns: 1fr 1fr; gap: 14px; }
@media (max-width: 820px){ .grid2 { grid-template-columns:1fr; } }
.chip {
  display:inline-block; padding:6px 10px; border-radius:999px; border:1px solid #283548; color:#9fb0c3; font-size:12px;
}
.kv { display:grid; grid-template-columns: 160px 1fr; gap:10px; margin-top: 8px; }
.kv div { padding: 10px 0; border-bottom: 1px solid #1e293b; }
.note { color:#9fb0c3; font-size: 13px; }
.sep { border:0; border-top:1px solid #1e293b; margin:18px 0; }

.stTextInput>div>div>input, .stTextInput>label, .stTextArea textarea {
  background: #0d1420 !important; color: #ecf2f8 !important;
}
.stButton>button, .stLinkButton>button {
  border-radius: 14px !important; padding: 12px 18px !important; font-weight: 700 !important;
  border: 0 !important; color: #041217 !important;
  background: linear-gradient(180deg,#5eead4,#22d3ee) !important;
  box-shadow: 0 12px 30px rgba(34,211,238,.28) !important;
}
.stButton>button:hover, .stLinkButton>button:hover { filter: brightness(1.06); }
.btn-secondary button {
  background: linear-gradient(180deg,#c084fc,#a855f7) !important; color: #160728 !important;
  box-shadow: 0 12px 30px rgba(168,85,247,.28) !important;
}
.btn-ghost button {
  background: transparent !important; color: #9fb0c3 !important; border: 1px solid #283548 !important; box-shadow:none !important;
}
.btn-warn button {
  background: linear-gradient(180deg,#fca5a5,#f97316) !important; color: #2b1105 !important;
  box-shadow: 0 12px 30px rgba(249,115,22,.28) !important;
}
.qr-preview { border:1px dashed #2b3a52; border-radius:16px; padding:10px; background:#0b1220; }
.help ul { margin: 0 0 0 18px; }
</style>
""", unsafe_allow_html=True)

# sticky topbar
st.markdown(
    f"""
<div class="topbar">
  <span class="brand">MYSCAN</span>
  <span class="muted">· Smart vehicle QR</span>
  <span style="float:right">
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
                    with a: st.button("Deactivate", key=f"deact-{r['id']}", help="Make public page unavailable")
                    if st.session_state.get(f"deact-{r['id']}", False): pass
                    if a.button(" ", key=f"deact_submit_{r['id']}", help="hidden"): pass
                    if a.button: pass
                    if a: pass
                    if a and a: pass
                # simple explicit buttons (no tricks)
                if r['is_active']:
                    if a.button("Deactivate", key=f"btn-deact-{r['id']}", help="Make public page unavailable"):
                        set_active(r['id'], False); st.rerun()
                else:
                    if a.button("Reactivate", key=f"btn-react-{r['id']}", help="Make public page available"):
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
# Owner panel
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
            st.markdown("**Documents**")
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
                g = st.columns(2)
                with g[0]:
                    if car.get("rc_url"):  st.link_button("Show RC", car["rc_url"], use_container_width=True)
                    if car.get("dl_url"):  st.link_button("Show DL (front)", car["dl_url"], use_container_width=True)
                with g[1]:
                    if car.get("dl_url2"): st.link_button("Show DL (back)", car["dl_url2"], use_container_width=True)
                    if car.get("puc_url"): st.link_button("Show Pollution", car["puc_url"], use_container_width=True)
            else:
                st.error("Wrong password")
        st.caption(["Believe you can and you’re halfway there.",
                    "Small steps every day.",
                    "Stay curious, stay kind.",
                    "Do the next right thing.",
                    "Progress, not perfection.",
                    "Make it simple, make it better."][int(time.time()) % 6])
    end_card()
    st.stop()

# ===========
# Home
# ===========
c = section_card("MYSCAN", "Add ?page=admin to manage, or use a QR to open a public car page.", hero=True)
with c:
    st.markdown("""
<div class="help">
  <ul>
    <li><a href="?page=admin">Admin dashboard</a></li>
    <li><code>?page=public&c=&lt;car_id&gt;</code></li>
    <li><code>?page=owner&owner=&lt;car_id&gt;&secret=&lt;owner_secret&gt;</code></li>
  </ul>
</div>
""", unsafe_allow_html=True)
end_card()
