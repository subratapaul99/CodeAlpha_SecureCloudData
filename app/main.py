import re
from pathlib import Path
from fastapi import FastAPI, Depends, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import select, insert
from sqlalchemy.exc import IntegrityError

from . import db, security, validation

db.init_db()
app = FastAPI(title="CodeAlpha Secure Cloud Data System")
STATIC = Path(__file__).resolve().parent.parent / "static"


# ---------- schemas (Layer 1: type + length validation) ----------
class Credentials(BaseModel):
    username: str = Field(max_length=30)
    password: str = Field(min_length=8, max_length=128)


class RecordIn(BaseModel):
    name: str = Field(max_length=100)
    email: str = Field(max_length=150)
    phone: str = Field(max_length=30)


# ---------- Layer 2: capability-token dependency ----------
def require(scope: str):
    def dep(x_capability: str = Header(default=None)):
        claims = security.verify_capability(x_capability, scope)
        if not claims:
            raise HTTPException(401, "Missing, invalid or insufficient capability token")
        return claims
    return dep


def _log_rejection(conn, fp, classification, reason):
    conn.execute(insert(db.rejected).values(
        fingerprint=fp, classification=classification, reason=reason))


# ---------- auth ----------
@app.post("/register", status_code=201)
def register(c: Credentials):
    if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", c.username):
        raise HTTPException(422, "Username: 3-30 letters, digits or underscore")
    try:
        with db.engine.begin() as conn:
            conn.execute(insert(db.users).values(
                username=c.username, password_hash=security.hash_password(c.password)))
    except IntegrityError:
        raise HTTPException(409, "Username already taken")
    return {"message": "registered"}


@app.post("/login")
def login(c: Credentials):
    with db.engine.connect() as conn:
        row = conn.execute(select(db.users).where(db.users.c.username == c.username)).first()
    if not row or not security.verify_password(c.password, row.password_hash):
        raise HTTPException(401, "Invalid credentials")
    token = security.issue_capability(c.username, ["read", "write"], ttl=900)
    return {"capability_token": token, "expires_in": 900}


# ---------- Task 1: redundancy-free inserts ----------
@app.post("/records", status_code=201)
def add_record(r: RecordIn, _=Depends(require("write"))):
    name, email, phone = validation.normalise(r.name, r.email, r.phone)
    ok, classification, reason = validation.classify(name, email, phone)

    rejection = None
    with db.engine.begin() as conn:
        if not ok:
            _log_rejection(conn, None, classification, reason)
            rejection = (422, {"classification": classification, "reason": reason})
        else:
            fp = security.fingerprint(validation.canonical_key(name, email, phone))
            exists = conn.execute(
                select(db.records.c.id).where(db.records.c.fingerprint == fp)).first()
            if exists:
                _log_rejection(conn, fp, "redundant", "duplicate of existing record")
                rejection = (409, {"classification": "redundant", "reason": "duplicate record"})
            else:
                try:
                    with conn.begin_nested():
                        conn.execute(insert(db.records).values(
                            fingerprint=fp, name=name,
                            email_enc=security.encrypt(email),
                            phone_enc=security.encrypt(phone)))
                except IntegrityError:  # race: UNIQUE constraint still protects us
                    _log_rejection(conn, fp, "redundant", "duplicate (concurrent insert)")
                    rejection = (409, {"classification": "redundant", "reason": "duplicate record"})
    if rejection:   # raised after commit so the rejection log is kept
        raise HTTPException(*rejection)
    return {"message": "stored", "classification": "unique"}


@app.get("/records")
def list_records(_=Depends(require("read"))):
    with db.engine.connect() as conn:
        rows = conn.execute(select(db.records).order_by(db.records.c.id)).all()
    return [{"id": r.id, "name": r.name,
             "email": security.decrypt(r.email_enc),
             "phone": security.decrypt(r.phone_enc)} for r in rows]


@app.get("/rejected")
def list_rejected(_=Depends(require("read"))):
    with db.engine.connect() as conn:
        rows = conn.execute(
            select(db.rejected).order_by(db.rejected.c.id.desc()).limit(100)).all()
    return [{"classification": r.classification, "reason": r.reason,
             "at": str(r.created_at)} for r in rows]


@app.get("/health")
def health():
    return {"status": "ok"}


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC / "index.html")
