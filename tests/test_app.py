import base64, os
os.environ["AES_KEY"] = base64.b64encode(os.urandom(32)).decode()
os.environ["CAPABILITY_SECRET"] = "test-secret"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
if os.path.exists("test.db"):
    os.remove("test.db")

from fastapi.testclient import TestClient
from sqlalchemy import text
from app.main import app
from app import db

client = TestClient(app)


def _token():
    client.post("/register", json={"username": "alice", "password": "StrongPass123"})
    r = client.post("/login", json={"username": "alice", "password": "StrongPass123"})
    return {"X-Capability": r.json()["capability_token"]}


def test_no_token_blocked():
    assert client.get("/records").status_code == 401


def test_tampered_token_blocked():
    h = _token()
    bad = {"X-Capability": h["X-Capability"][:-3] + "abc"}
    assert client.get("/records", headers=bad).status_code == 401


def test_unique_then_duplicate():
    h = _token()
    rec = {"name": "john doe", "email": "John@Mail.com", "phone": "+91 98765-43210"}
    assert client.post("/records", json=rec, headers=h).status_code == 201
    dup = {"name": "John  Doe", "email": "john@mail.com", "phone": "919876543210"}
    r = client.post("/records", json=dup, headers=h)
    assert r.status_code == 409 and r.json()["detail"]["classification"] == "redundant"
    log = client.get("/rejected", headers=h).json()
    assert any(x["classification"] == "redundant" for x in log)


def test_sql_injection_rejected_and_tables_survive():
    h = _token()
    evil = {"name": "Robert'); DROP TABLE records;--", "email": "x@y.com", "phone": "1234567890"}
    r = client.post("/records", json=evil, headers=h)
    assert r.status_code == 422 and r.json()["detail"]["classification"] == "false_positive"
    assert client.get("/records", headers=h).status_code == 200   # table still exists


def test_data_encrypted_at_rest():
    h = _token()
    client.post("/records", json={"name": "Jane Roe", "email": "jane@mail.com",
                                  "phone": "9998887776"}, headers=h)
    with db.engine.connect() as c:
        raw = c.execute(text("SELECT email_enc FROM records WHERE name='Jane Roe'")).scalar()
    assert "jane@mail.com" not in raw
    emails = [x["email"] for x in client.get("/records", headers=h).json()]
    assert "jane@mail.com" in emails


def test_frontend_served():
    r = client.get("/")
    assert r.status_code == 200 and "Secure Cloud Data System" in r.text
