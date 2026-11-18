# CodeAlpha Cloud Computing — Tasks 1 & 2
**Secure Cloud Data System: Redundancy Removal + SQL-Injection / Data-Leak Protection**

## Architecture
```
Client --HTTPS--> FastAPI (EC2 / Elastic Beanstalk)
                    1. Capability token check (HMAC-signed, scoped, 15-min expiry)
                    2. Input validation + SQLi pattern detection  -> false_positive log
                    3. Normalise + keyed SHA-256 fingerprint      -> redundant log
                    4. Parameterised insert (SQLAlchemy) + UNIQUE constraint
                            |
                            v
                 PostgreSQL (AWS RDS): email/phone stored as AES-256-GCM ciphertext
```

## Task 1 - Data Redundancy Removal
- Incoming data is normalised (case, spacing, phone digits) and classified as
  **unique**, **redundant** (fingerprint already exists) or **false_positive** (invalid / placeholder / malicious).
- Rejected entries are logged in `rejected_entries`; only unique, verified rows are appended.
- `UNIQUE(fingerprint)` in the database guarantees no duplicates, even under concurrent requests.

## Task 2 - SQL Injection / Data-Leak Protection
- **AES-256-GCM** encryption for sensitive fields; key kept outside the DB (env var / AWS Secrets Manager).
- Passwords are stored as salted scrypt hashes (one-way, safer than reversible encryption for credentials).
- **Double-layer security**
  1. Parameterised queries + strict validation + SQLi pattern filter
  2. **Capability code**: signed, scoped, expiring token required for every data request
- Lightweight: runs on a free-tier t3.micro.

## Run locally
```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # fill AES_KEY and CAPABILITY_SECRET (commands inside the file)
export $(grep -v '^#' .env | xargs)
uvicorn app.main:app --reload      # web UI: http://127.0.0.1:8000  |  API docs: /docs
pytest -q
```

## Run locally on Windows (PowerShell)
```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
$env:AES_KEY = python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
$env:CAPABILITY_SECRET = python -c "import secrets;print(secrets.token_hex(32))"
$env:DATABASE_URL = "sqlite:///./data.db"
uvicorn app.main:app --reload
```
Set the three variables in the same terminal before starting the server. Open http://127.0.0.1:8000 for the web interface (API docs: http://127.0.0.1:8000/docs)

> Keep the same AES_KEY between runs. If it changes, records saved earlier can no longer be decrypted.

## Demo flow
1. `POST /register` then `POST /login`, copy `capability_token`
2. Send header `X-Capability: <token>` to `POST /records`
3. Re-send the same data -> **409 redundant**
4. Send `Robert'); DROP TABLE records;--` as name -> **422 false_positive**
5. Call without a token -> **401**

## Deploy on AWS (free tier)
1. RDS PostgreSQL (db.t3.micro), private, security group allowing only the EC2 instance.
2. EC2 t3.micro: `git clone`, `pip install -r requirements.txt`, set env vars, then
   `uvicorn app.main:app --host 0.0.0.0 --port 8000` (add systemd + nginx/HTTPS for production).
3. Store `AES_KEY` and `CAPABILITY_SECRET` in AWS Secrets Manager.

## Features added in v2
- **Live dashboard:** stored / duplicates blocked / attacks blocked / rejection rate (`GET /stats`).
- **Bulk CSV import** with per-row validation and a summary (try `sample_data.csv`: 3 stored, 2 duplicates, 2 blocked).
- **Search, delete (`DELETE /records/{id}`) and CSV export** of stored records.
- **Brute-force protection:** 5 failed logins lock that username for 5 minutes (HTTP 429).
