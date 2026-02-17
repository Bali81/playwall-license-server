from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os, secrets, time
import psycopg

APP = FastAPI(title="PlayWall License Server (Postgres)")

DATABASE_URL = os.environ["DATABASE_URL"]  # Render adja
ADMIN_PASSWORD = os.environ["PLAYWALL_ADMIN_PASSWORD"]

def init_db():
    with psycopg.connect(DATABASE_URL) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id SERIAL PRIMARY KEY,
            key TEXT UNIQUE NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            fingerprint TEXT NULL,
            created_at BIGINT NOT NULL
        );
        """)
        conn.commit()

init_db()

class ActivateIn(BaseModel):
    license_key: str
    fingerprint: str
    device_name: str | None = None

class CheckIn(BaseModel):
    license_key: str
    fingerprint: str

class AdminIn(BaseModel):
    admin_password: str

def normalize_key(k: str) -> str:
    return k.strip().upper().replace(" ", "")

def admin_guard(pw: str):
    if pw != ADMIN_PASSWORD:
        raise HTTPException(401, "BAD_ADMIN_PASSWORD")

def gen_key() -> str:
    raw = secrets.token_hex(8).upper()
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"

@APP.post("/v1/activate")
def activate(body: ActivateIn):
    key = normalize_key(body.license_key)
    fp = body.fingerprint.strip().lower()

    with psycopg.connect(DATABASE_URL) as conn:
        row = conn.execute("SELECT id, status, fingerprint FROM licenses WHERE key=%s", (key,)).fetchone()
        if not row:
            raise HTTPException(401, "INVALID_KEY")

        lic_id, status, bound_fp = row
        if status != "active":
            raise HTTPException(403, "BANNED")

        if bound_fp is None:
            conn.execute("UPDATE licenses SET fingerprint=%s WHERE id=%s", (fp, lic_id))
            conn.commit()
            return {"ok": True, "message": "Activated on this PC."}

        if bound_fp != fp:
            raise HTTPException(403, "DEVICE_MISMATCH")

        return {"ok": True, "message": "Already activated on this PC."}

@APP.post("/v1/check")
def check(body: CheckIn):
    key = normalize_key(body.license_key)
    fp = body.fingerprint.strip().lower()

    with psycopg.connect(DATABASE_URL) as conn:
        row = conn.execute("SELECT status, fingerprint FROM licenses WHERE key=%s", (key,)).fetchone()
        if not row:
            return {"ok": False, "reason": "INVALID_KEY"}

        status, bound_fp = row
        if status != "active":
            return {"ok": False, "reason": "BANNED"}
        if bound_fp is None:
            return {"ok": False, "reason": "NOT_ACTIVATED"}
        if bound_fp != fp:
            return {"ok": False, "reason": "DEVICE_MISMATCH"}

        return {"ok": True}

@APP.post("/admin/create")
def admin_create(body: AdminIn):
    admin_guard(body.admin_password)
    key = gen_key()
    with psycopg.connect(DATABASE_URL) as conn:
        conn.execute(
            "INSERT INTO licenses (key, status, fingerprint, created_at) VALUES (%s,'active',NULL,%s)",
            (key, int(time.time()))
        )
        conn.commit()
    return {"license_key": key}

@APP.post("/admin/reset")
def admin_reset(body: AdminIn, license_key: str):
    admin_guard(body.admin_password)
    key = normalize_key(license_key)
    with psycopg.connect(DATABASE_URL) as conn:
        cur = conn.execute("UPDATE licenses SET fingerprint=NULL WHERE key=%s", (key,))
        conn.commit()
        return {"ok": cur.rowcount > 0}

@APP.post("/admin/ban")
def admin_ban(body: AdminIn, license_key: str):
    admin_guard(body.admin_password)
    key = normalize_key(license_key)
    with psycopg.connect(DATABASE_URL) as conn:
        cur = conn.execute("UPDATE licenses SET status='banned' WHERE key=%s", (key,))
        conn.commit()
        return {"ok": cur.rowcount > 0}
