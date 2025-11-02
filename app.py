import os, io, uuid, time, re, base64, secrets, hmac, hashlib
import streamlit as st
from urllib.parse import urlencode
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

# ==================== Settings & DB URL helper ====================
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

# ==================== DB ====================
try:
    engine = create_engine(DB_URL, pool_pre_ping=True)
except Exception as e:
    st.error("Failed to connect to the database. Check DATABASE_URL in Secrets.")
    st.exception(e)
    st.stop()

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
          owner_user_id UUID,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );"""))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS dl_url2 TEXT;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS puc_url TEXT;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS owner_secret UUID;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;"))
        conn.execute(text("ALTER TABLE cars ADD COLUMN IF NOT EXISTS owner_user_id UUID;"))
        conn.execute(text("UPDATE cars SET is_active=TRUE WHERE is_active IS NULL;"))

        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
          id UUID PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );"""))

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

# ==================== Utils ====================
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

# Query params helper compatible across Streamlit versions
def get_qp(name: str, default: str | None = None):
    try:
        v = st.query_params.get(name)  # 1.30+
        return v if isinstance(v, str) else (v[0] if isinstance(v, list) and v else default)
    except Exception:
        qp = st.experimental_get_query_params()
        v = qp.get(name)
        return v[0] if isinstance(v, list) and v else default

# ==================== Data access: cars ====================
def create_car(owner_name, car_no, owner_phone, virtual_number, rc, dl1, dl2, puc, doc_pw):
    with engine.begin() as conn:
        car_id = str(uuid.uuid4())
        owner_secret = str(uuid.uuid4())
        pw_hash = _hash_pw(doc_pw) if (doc_pw or "").strip() else None
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
        params["hash"] = _hash_pw(new_pw.strip())
    with engine.begin() as conn:
        conn.execute(text(f"UPDATE cars SET {', '.join(sets)} WHERE id=:id"), params)

# ==================== Data access: users & ownership ====================
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

def claim_car_for_user(car_id: str, owner_secret: str, user_id: str) -> bool:
    with engine.begin() as conn:
        car = conn.execute(text("SELECT id, owner_secret FROM cars WHERE id=:id"), dict(id=car_id)).mappings().first()
        if not car or str(car["owner_secret"]) != str(owner_secret):
            return False
        conn.execute(text("UPDATE cars SET owner_user_id=:u WHERE id=:id"), dict(u=user_id, id=car_id))
        return True

def list_user_cars(user_id: str):
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT * FROM cars WHERE owner_user_id=:u ORDER BY created_at DESC"),
                            dict(u=user_id)).mappings().all()
        return [dict(r) for r in rows]

# ==================== Uploads (optional binary docs) ====================
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

# ==================== THEME (white/blue + light orange) ====================
st.set_page_config(page_title="MYSCAN", page_icon="🚗", layout="centered")
st.markdown("""
<style>
:root { --blue:#0b1b3a; --muted:#4a6786; --border:#e6eef6; --orange1:#ffe6cc; --orange2:#ffcc99; --orangeBorder:#ffd7b3; }
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

# ==================== Admin ====================
if page == "admin":
    c = section_card("Admin dashboard", "Create & manage vehicle QRs", hero=True)
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
            st.markdown("<span class='chip'>Environment</span>", unsafe_allow_html=True)
            st.caption(f"Base URL: {PUBLIC_BASE or '(not set)'}")
    end_card()

    if not st.session_state.get("admin_ok"):
        st.stop()

    c2 = section_card("Generate new QR", "Fill in the details below")
    with c2:
        if not PUBLIC_BASE:
            st.info("Tip: set PUBLIC_BASE_URL in Secrets so QR codes use your live domain.")
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
            s = st.form_submit_button("Create & generate QRs")
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
                    st.success("QRs ready")
                    pcols = st.columns([1,1])
                    with pcols[0]:
                        st.markdown("**Public page**"); st.code(pub_url, language="text")
                        st.image(Image.open(io.BytesIO(make_qr_png(pub_url))), caption="Public QR")
                        st.download_button("Download Public QR", make_qr_png(pub_url), file_name=f"qr-{new_id}.png", mime="image/png")
                    with pcols[1]:
                        st.markdown("**Owner panel**"); st.code(own_url, language="text")
                        st.image(Image.open(io.BytesIO(make_qr_png(own_url))), caption="Owner Panel QR")
                        st.download_button("Download Owner QR", make_qr_png(own_url), file_name=f"owner-qr-{new_id}.png", mime="image/png")
    end_card()

    c3 = section_card("Vehicles", "Manage status, open public page, regenerate QRs")
    with c3:
        rows = list_cars()
        if not rows:
            st.caption("No entries yet.")
        for r in rows:
            pub_link = public_url_for_car(r['id'])
            a,b,c,d,e = st.columns([3,1.2,1.6,1.8,1.2])
            with a:
                st.markdown(f"**{r['owner_name']}** · {r['car_no']}")
                st.caption(str(r['created_at']))
            with b:
                st.markdown(f"<span class='chip'>{'Active' if r['is_active'] else 'Inactive'}</span>", unsafe_allow_html=True)
            with c:
                st.link_button("Open public", pub_link)
            with d:
                if r['is_active']:
                    if st.button("Deactivate", key=f"btn_deact_{r['id']}"):
                        set_active(r['id'], False); st.rerun()
                else:
                    if st.button("Reactivate", key=f"btn_react_{r['id']}"):
                        set_active(r['id'], True); st.rerun()
            with e:
                if st.button("Regenerate", key=f"btn_regen_{r['id']}"):
                    car = get_car(r['id']); own_link = owner_url_for_car(r['id'], car['owner_secret'])
                    st.success("Download fresh QR images below.")
                    g1, g2 = st.columns(2)
                    with g1:
                        st.download_button("Public QR", make_qr_png(pub_link), file_name=f"qr-{r['id']}.png", mime="image/png", key=f"dpub_{r['id']}")
                    with g2:
                        st.download_button("Owner QR", make_qr_png(own_link), file_name=f"owner-qr-{r['id']}.png", mime="image/png", key=f"down_{r['id']}")
            st.markdown("<hr class='sep'/>", unsafe_allow_html=True)
    end_card()
    st.stop()

# ==================== User dashboard ====================
if page == "user":
    c = section_card("User dashboard", "Sign in to manage your vehicle documents", hero=True)
    with c:
        tab_login, tab_signup = st.tabs(["Sign in", "Create account"])
        with tab_login:
            le = st.text_input("Email", key="login_email")
            lp = st.text_input("Password", type="password", key="login_password")
            if st.button("Sign in"):
                uid = auth_user(le or "", lp or "")
                if uid: st.session_state["user_id"] = uid; st.success("Signed in"); st.rerun()
                else: st.error("Invalid email or password")
        with tab_signup:
            se  = st.text_input("Email (for new account)", key="signup_email")
            sp1 = st.text_input("Password", type="password", key="signup_password")
            sp2 = st.text_input("Confirm password", type="password", key="signup_confirm")
            if st.button("Create account"):
                if not se or not sp1 or sp1 != sp2:
                    st.error("Enter email and matching passwords")
                else:
                    try:
                        uid = create_user(se, sp1); st.session_state["user_id"] = uid; st.success("Account created"); st.rerun()
                    except Exception:
                        st.error("Could not create account (maybe email already used)")
    end_card()

    if not st.session_state.get("user_id"): st.stop()

    uid = st.session_state["user_id"]
    c2 = section_card("Link your car", "Use Owner Secret (from Admin) to claim your car and manage docs")
    with c2:
        ccid = st.text_input("Car ID", key="claim_car_id")
        csec = st.text_input("Owner Secret", key="claim_secret")
        if st.button("Claim this car"):
            if claim_car_for_user(ccid or "", csec or "", uid): st.success("Car linked"); st.rerun()
            else: st.error("Invalid Car ID or Owner Secret")
    end_card()

    c3 = section_card("My vehicles", "Update password, links, and upload documents")
    with c3:
        mycars = list_user_cars(uid)
        if not mycars: st.caption("No cars linked yet.")
        for car in mycars:
            st.markdown(f"### {car['owner_name']} · {car['car_no']}  {'🟢 Active' if car['is_active'] else '🔴 Inactive'}")
            form_key = f"edit_{car['id']}"
            with st.form(form_key):
                new_pw = st.text_input("Docs password (leave blank to keep)", type="password", key=f"{form_key}_pw")
                rc  = st.text_input("RC link", value=car.get("rc_url") or "", placeholder="https://...", key=f"{form_key}_rc")
                dl1 = st.text_input("DL (front) link", value=car.get("dl_url") or "", placeholder="https://...", key=f"{form_key}_dl1")
                dl2 = st.text_input("DL (back) link", value=car.get("dl_url2") or "", placeholder="https://...", key=f"{form_key}_dl2")
                puc = st.text_input("Pollution (PUC) link", value=car.get("puc_url") or "", placeholder="https://...", key=f"{form_key}_puc")

                st.markdown("<hr class='sep'/>", unsafe_allow_html=True)
                st.caption("Optional uploads (PDF/JPG/PNG). They appear as downloads after password unlock on the public page.")
                up_rc  = st.file_uploader("Upload RC file", type=["pdf","png","jpg","jpeg"], key=f"{form_key}_up_rc")
                up_dl1 = st.file_uploader("Upload DL (front)", type=["pdf","png","jpg","jpeg"], key=f"{form_key}_up_dl1")
                up_dl2 = st.file_uploader("Upload DL (back)", type=["pdf","png","jpg","jpeg"], key=f"{form_key}_up_dl2")
                up_puc = st.file_uploader("Upload PUC", type=["pdf","png","jpg","jpeg"], key=f"{form_key}_up_puc")

                cols = st.columns([1,1,1])
                save = cols[0].form_submit_button("Save changes", use_container_width=True)
                if car["is_active"]:
                    deact = cols[1].form_submit_button("Deactivate QR", use_container_width=True)
                    react = None
                else:
                    react = cols[1].form_submit_button("Reactivate QR", use_container_width=True)
                    deact = None

            if save:
                update_owner(car["id"], rc, dl1, dl2, puc, new_pw)
                for blob, kind in [(up_rc,"rc"),(up_dl1,"dl1"),(up_dl2,"dl2"),(up_puc,"puc")]:
                    if blob is not None:
                        upsert_doc(car["id"], kind, blob.name, blob.type or "application/octet-stream", blob.getvalue())
                st.success("Saved"); st.rerun()
            if deact: set_active(car["id"], False); st.success("QR deactivated"); st.rerun()
            if react: set_active(car["id"], True); st.success("QR reactivated"); st.rerun()
    end_card()
    st.stop()

# ==================== Owner panel (legacy link) ====================
if page == "owner":
    if not owner_id or not secret: st.error("Invalid owner link"); st.stop()
    car = get_car(owner_id)
    if not car or str(car.get("owner_secret")) != str(secret): st.error("Invalid owner link"); st.stop()

    c = section_card(f"Owner Panel — {'Active' if car['is_active'] else 'Inactive'}",
                     f"{car['owner_name']} · {car['car_no']}", hero=True)
    with c:
        with st.form("owner_update"):
            new_pw = st.text_input("Set/Change password (leave blank to keep)",
                                   type="password", key=f"owner_pw_{owner_id}")
            st.markdown("<hr class='sep'/>", unsafe_allow_html=True)
            rc  = st.text_input("RC link", value=car.get("rc_url") or "", placeholder="https://...", key=f"owner_rc_{owner_id}")
            dl1 = st.text_input("DL (front)", value=car.get("dl_url") or "", placeholder="https://...", key=f"owner_dl1_{owner_id}")
            dl2 = st.text_input("DL (back)", value=car.get("dl_url2") or "", placeholder="https://...", key=f"owner_dl2_{owner_id}")
            puc = st.text_input("Pollution (PUC)", value=car.get("puc_url") or "", placeholder="https://...", key=f"owner_puc_{owner_id}")
            row = st.columns([1,1])
            save = row[0].form_submit_button("Save changes")
            deact = row[1].form_submit_button("Deactivate QR") if car["is_active"] else None
        if save: update_owner(owner_id, rc, dl1, dl2, puc, new_pw); st.success("Saved")
        if deact: set_active(owner_id, False); st.success("QR deactivated"); st.rerun()
        st.link_button("Open public page", public_url_for_car(owner_id), use_container_width=True)
    end_card()
    st.stop()

# ==================== Public ====================
if page == "public":
    if not car_id: st.error("Missing car id"); st.stop()
    car = get_car(car_id)
    if not car: st.error("Not found"); st.stop()
    if not car["is_active"]:
        c = section_card("QR inactive", "This QR has been deactivated by the owner or admin.", hero=True)
        end_card(); st.stop()

    c = section_card("Vehicle contact", f"{car['owner_name']} · {car['car_no']}", hero=True)
    with c:
        st.link_button("Contact owner", tel_href(car["virtual_number"]), use_container_width=True)
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
                            with dcols[i % 2]:
                                st.download_button(f"Download {label}", data, file_name=name,
                                                   mime=docs[k].get("mime") or "application/octet-stream",
                                                   use_container_width=True)
                            i += 1
            else:
                st.error("Wrong password")
        st.caption(["Keep it moving.", "Small steps every day.", "Progress, not perfection."][int(time.time()) % 3])
    end_card()
    st.stop()

# ==================== Home ====================
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
