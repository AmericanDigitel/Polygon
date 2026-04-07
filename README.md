# Polygon Checker - Phase 5

This version adds:
- signup and login
- email verification
- forgot password / reset password
- saved polygons
- per-user address check history

## Run locally on Mac

```bash
cd ~/Downloads/polygon_checker_phase5
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export GEOCODER_PROVIDER=nominatim
export GEOCODER_USER_AGENT=polygon-checker-demo/1.0
export SESSION_SECRET='change-this-to-any-random-secret'
export APP_BASE_URL='http://127.0.0.1:8000'
python3 -m fastapi dev app/main.py
```

Open:
- http://127.0.0.1:8000/signup
- http://127.0.0.1:8000/login
- http://127.0.0.1:8000/admin

## Important local testing note

If SMTP is not configured, the app still works.
Instead of sending real emails, it returns a **preview link** on the signup and forgot-password screens.
Click that link to verify email or reset password while testing locally.

## Production note

To send real emails, configure the SMTP variables from `.env.example`.
