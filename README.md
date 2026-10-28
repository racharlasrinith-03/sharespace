# ShareSpace — Trusted Resource Sharing MVP

A working hackathon prototype for safely sharing underused institutional equipment and spaces.

## Features
- User registration and sign-in; owner/admin/user roles
- Resource listing with location, availability, conditions, training, membership, supervision and deposit
- Search/filter resources
- Booking requests and owner/admin approval, rejection or waiting list
- Eligibility checks and 2 active/pending booking limit per user in a rolling 30-day window
- Scheduling-conflict checks
- Check-in/check-out with before-and-after condition notes
- Incident/damage reporting and resolution
- Auditable action history
- Fictional demo data and accounts

## Run locally
Requires Python 3.10+.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```
Open http://127.0.0.1:8000

API docs: http://127.0.0.1:8000/docs

## Demo accounts
- Admin: `admin@sharespace.test` / `Admin123!`
- Owner: `owner@sharespace.test` / `Owner123!`
- Student: `student@sharespace.test` / `Student123!`
- Unverified member: `member@sharespace.test` / `Member123!`

All accounts and resources are fictional.

## Deployment
Deploy as a Python web service with build command `pip install -r requirements.txt` and start command `uvicorn main:app --host 0.0.0.0 --port $PORT`.
Set `APP_SECRET` to a long random secret and set `DATABASE_PATH` to a persistent disk path. SQLite is suitable for a small demo; use PostgreSQL for production/multiple instances. Ensure the database is on persistent storage.
For Render, add a persistent disk and set `DATABASE_PATH` to a file path on that disk.

## Important limitations before real-world use
This is an MVP, not a production security certification. The demo uses an HMAC token in browser local storage, permissive CORS for prototype convenience, and basic role controls. Before real deployment: use secure HTTP-only sessions or OAuth, strict CORS, CSRF protection if using cookies, rate limiting, email verification, stronger admin provisioning, file uploads with malware scanning, encrypted backups, database migrations, automated tests, and institution-approved identity/training verification. Never use this demo for dangerous equipment access without human verification and safety procedures.
