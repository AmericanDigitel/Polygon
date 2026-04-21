from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import requests
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
from shapely.geometry import Point, shape
from starlette.middleware.sessions import SessionMiddleware

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
POLYGONS_FILE = DATA_DIR / "polygons.geojson"
DB_FILE = DATA_DIR / "app.db"
STATIC_DIR = BASE_DIR / "app" / "static"

DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Polygon Address Checker", version="6.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "change-this-in-production"),
    same_site="lax",
    https_only=False,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ─── Pydantic Models ──────────────────────────────────────────────────────────

class AddressRequest(BaseModel):
    address: str = Field(..., min_length=3)


class SignupRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=20)
    password: str = Field(..., min_length=8, max_length=128)


class VerifyEmailRequest(BaseModel):
    token: str = Field(..., min_length=20)


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class CreateProjectRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = Field(None, max_length=500)


class GeocodeResult(BaseModel):
    lat: float
    lng: float
    display_name: str


class MatchResponse(BaseModel):
    address: str
    normalized_address: str | None = None
    geocode: GeocodeResult
    matched: bool
    matched_polygon_names: list[str]
    total_polygons_checked: int


class PolygonSummary(BaseModel):
    id: str
    name: str
    geometry_type: str
    source_file: str | None = None


class ProjectResponse(BaseModel):
    id: int
    name: str
    description: str | None = None
    created_at: str
    polygon_count: int


class UserResponse(BaseModel):
    id: int
    full_name: str
    email: str
    created_at: str
    is_verified: bool


class GenericMessage(BaseModel):
    message: str
    preview_url: str | None = None


EMAIL_TOKEN_HOURS = 24
RESET_TOKEN_HOURS = 1


# ─── Utilities ────────────────────────────────────────────────────────────────

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def add_hours_iso(hours: int) -> str:
    return (utc_now() + timedelta(hours=hours)).isoformat()


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def parse_iso(dt_str: str) -> datetime:
    return datetime.fromisoformat(dt_str)


# ─── Database Setup ───────────────────────────────────────────────────────────

@app.on_event("startup")
def startup() -> None:
    init_db()


def init_db() -> None:
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                is_verified INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS project_polygons (
                id TEXT PRIMARY KEY,
                project_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                geometry_type TEXT NOT NULL,
                source_file TEXT,
                feature_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            );

            CREATE TABLE IF NOT EXISTS address_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                project_id INTEGER,
                input_address TEXT NOT NULL,
                normalized_address TEXT,
                lat REAL NOT NULL,
                lng REAL NOT NULL,
                matched INTEGER NOT NULL,
                matched_polygon_names TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (project_id) REFERENCES projects(id)
            );

            CREATE TABLE IF NOT EXISTS email_verification_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )

        # Migrate legacy columns
        user_cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "is_verified" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 0")

        check_cols = {row[1] for row in conn.execute("PRAGMA table_info(address_checks)").fetchall()}
        if "project_id" not in check_cols:
            conn.execute("ALTER TABLE address_checks ADD COLUMN project_id INTEGER REFERENCES projects(id)")

    # Migrate legacy polygons.geojson into a default project per user
    migrate_legacy_polygons()


def migrate_legacy_polygons() -> None:
    """Import polygons.geojson into the first user's first project if not already done."""
    if not POLYGONS_FILE.exists():
        return
    try:
        geojson = json.loads(POLYGONS_FILE.read_text(encoding="utf-8"))
        features = geojson.get("features", [])
        if not features:
            return
    except Exception:
        return

    with get_db() as conn:
        # Only migrate if project_polygons is empty (first time)
        existing_count = conn.execute("SELECT COUNT(*) FROM project_polygons").fetchone()[0]
        if existing_count > 0:
            return

        # Get or create a default project for user 1 (or first user)
        user_row = conn.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
        if not user_row:
            return
        user_id = user_row["id"]

        proj = conn.execute(
            "SELECT id FROM projects WHERE user_id = ? ORDER BY id LIMIT 1", (user_id,)
        ).fetchone()

        if not proj:
            cursor = conn.execute(
                "INSERT INTO projects (user_id, name, description, created_at) VALUES (?, ?, ?, ?)",
                (user_id, "Default Project", "Migrated from previous version", utc_now_iso()),
            )
            project_id = cursor.lastrowid
        else:
            project_id = proj["id"]

        for feature in features:
            props = feature.get("properties", {}) or {}
            poly_id = props.get("id") or str(uuid.uuid4())
            name = props.get("name", "Unnamed polygon")
            geom_type = feature.get("geometry", {}).get("type", "Unknown")
            source_file = props.get("source_file")
            conn.execute(
                """
                INSERT OR IGNORE INTO project_polygons (id, project_id, name, geometry_type, source_file, feature_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (poly_id, project_id, name, geom_type, source_file, json.dumps(feature), utc_now_iso()),
            )


# ─── Auth Helpers ─────────────────────────────────────────────────────────────

def hash_password(password: str, salt: str | None = None) -> str:
    chosen_salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), chosen_salt.encode("utf-8"), 120_000)
    return f"{chosen_salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, expected = stored_hash.split("$", 1)
    except ValueError:
        return False
    actual = hash_password(password, salt).split("$", 1)[1]
    return hmac.compare_digest(actual, expected)


def row_to_user(row: sqlite3.Row) -> UserResponse:
    return UserResponse(
        id=row["id"],
        full_name=row["full_name"],
        email=row["email"],
        created_at=row["created_at"],
        is_verified=bool(row["is_verified"]),
    )


def get_current_user(request: Request) -> UserResponse:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Please log in.")
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, full_name, email, created_at, is_verified FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    if not row:
        request.session.clear()
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
    return row_to_user(row)


def require_login_page(request: Request) -> UserResponse | RedirectResponse:
    try:
        return get_current_user(request)
    except HTTPException:
        return RedirectResponse(url="/login", status_code=303)


def get_project_for_user(project_id: int, user_id: int) -> sqlite3.Row:
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, user_id, name, description, created_at FROM projects WHERE id = ? AND user_id = ?",
            (project_id, user_id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Project not found.")
    return row


# ─── KML / GeoJSON Helpers ────────────────────────────────────────────────────

def make_label_from_filename(filename: str | None) -> str:
    if not filename:
        return "Polygon"
    stem = Path(filename).stem
    label = re.sub(r"[_\-]+", " ", stem).strip()
    return label.title() if label else "Polygon"


def is_generic_polygon_name(name: str | None) -> bool:
    if not name:
        return True
    normalized = name.strip().lower()
    return bool(re.fullmatch(r"polygon(\s+\d+)?", normalized)) or normalized in {
        "unnamed polygon", "untitled", "feature",
    }


def parse_kml_coordinates(raw_text: str) -> list[list[float]]:
    coords: list[list[float]] = []
    for chunk in raw_text.strip().split():
        parts = chunk.split(",")
        if len(parts) < 2:
            continue
        try:
            lng = float(parts[0])
            lat = float(parts[1])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid coordinate found in KML file.") from exc
        coords.append([lng, lat])
    if len(coords) < 4:
        raise HTTPException(status_code=400, detail="Each KML polygon ring must contain at least 4 coordinates.")
    if coords[0] != coords[-1]:
        coords.append(coords[0])
    return coords


def strip_namespace(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def find_first_child(element: ET.Element, name: str) -> ET.Element | None:
    for child in list(element):
        if strip_namespace(child.tag) == name:
            return child
    return None


def find_children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(element) if strip_namespace(child.tag) == name]


def parse_kml_polygon_element(polygon_el: ET.Element) -> dict[str, Any]:
    outer = find_first_child(polygon_el, "outerBoundaryIs")
    if outer is None:
        raise HTTPException(status_code=400, detail="A KML polygon is missing outerBoundaryIs.")
    outer_ring = find_first_child(outer, "LinearRing")
    if outer_ring is None:
        raise HTTPException(status_code=400, detail="A KML polygon is missing a LinearRing.")
    outer_coords_el = find_first_child(outer_ring, "coordinates")
    if outer_coords_el is None or not (outer_coords_el.text or "").strip():
        raise HTTPException(status_code=400, detail="A KML polygon is missing coordinates.")
    rings = [parse_kml_coordinates(outer_coords_el.text or "")]
    for inner in find_children(polygon_el, "innerBoundaryIs"):
        inner_ring = find_first_child(inner, "LinearRing")
        if inner_ring is None:
            continue
        inner_coords_el = find_first_child(inner_ring, "coordinates")
        if inner_coords_el is None or not (inner_coords_el.text or "").strip():
            continue
        rings.append(parse_kml_coordinates(inner_coords_el.text or ""))
    return {"type": "Polygon", "coordinates": rings}


def kml_to_geojson(raw_bytes: bytes, source_filename: str | None = None) -> dict[str, Any]:
    try:
        root = ET.fromstring(raw_bytes.decode("utf-8"))
    except UnicodeDecodeError:
        try:
            root = ET.fromstring(raw_bytes.decode("utf-8-sig"))
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid KML file encoding.") from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid KML file.") from exc

    placemarks = [el for el in root.iter() if strip_namespace(el.tag) == "Placemark"]
    if not placemarks:
        raise HTTPException(status_code=400, detail="No Placemark elements found in KML file.")

    features: list[dict[str, Any]] = []
    file_label = make_label_from_filename(source_filename)

    for idx, placemark in enumerate(placemarks, start=1):
        name_el = find_first_child(placemark, "name")
        placemark_name = (name_el.text or "").strip() if name_el is not None and name_el.text else None
        polygons = [el for el in placemark.iter() if strip_namespace(el.tag) == "Polygon"]
        if not polygons:
            continue

        if len(polygons) == 1:
            geometry = parse_kml_polygon_element(polygons[0])
        else:
            geometry = {
                "type": "MultiPolygon",
                "coordinates": [parse_kml_polygon_element(poly)["coordinates"] for poly in polygons],
            }

        properties: dict[str, Any] = {"source_file": source_filename}
        if placemark_name:
            properties["name"] = placemark_name
        else:
            properties["name"] = file_label if len(placemarks) == 1 else f"{file_label} {idx}"

        features.append({"type": "Feature", "properties": properties, "geometry": geometry})

    if not features:
        raise HTTPException(status_code=400, detail="The KML file does not contain Polygon geometry.")

    return {"type": "FeatureCollection", "features": features}


def validate_geojson(payload: dict[str, Any], source_filename: str | None = None) -> dict[str, Any]:
    if payload.get("type") != "FeatureCollection":
        raise HTTPException(status_code=400, detail="GeoJSON must be a FeatureCollection.")

    cleaned_features: list[dict[str, Any]] = []
    file_label = make_label_from_filename(source_filename)
    features = payload.get("features", [])
    total = len(features)

    for idx, feature in enumerate(features, start=1):
        geometry = feature.get("geometry")
        if not geometry:
            raise HTTPException(status_code=400, detail=f"Feature {idx} is missing geometry.")
        geom_type = geometry.get("type")
        if geom_type not in {"Polygon", "MultiPolygon"}:
            raise HTTPException(
                status_code=400,
                detail=f"Feature {idx} must be Polygon or MultiPolygon, not {geom_type}.",
            )
        existing_properties = feature.get("properties", {}) or {}
        incoming_name = existing_properties.get("name")
        if is_generic_polygon_name(incoming_name):
            polygon_name = file_label if total == 1 else f"{file_label} {idx}"
        else:
            polygon_name = str(incoming_name).strip()
        polygon_id = existing_properties.get("id") or str(uuid.uuid4())
        cleaned_features.append(
            {
                "type": "Feature",
                "properties": {
                    **existing_properties,
                    "id": polygon_id,
                    "name": polygon_name,
                    "source_file": source_filename,
                },
                "geometry": geometry,
            }
        )
    return {"type": "FeatureCollection", "features": cleaned_features}


# ─── Geocoding ────────────────────────────────────────────────────────────────

def geocode_address(address: str) -> GeocodeResult:
    provider = os.getenv("GEOCODER_PROVIDER", "nominatim").lower()
    if provider == "mapbox":
        token = os.getenv("MAPBOX_TOKEN")
        if not token:
            raise HTTPException(status_code=500, detail="MAPBOX_TOKEN is not configured.")
        url = f"https://api.mapbox.com/geocoding/v5/mapbox.places/{requests.utils.quote(address)}.json"
        response = requests.get(url, params={"access_token": token, "limit": 1}, timeout=20)
        response.raise_for_status()
        data = response.json()
        features = data.get("features", [])
        if not features:
            raise HTTPException(status_code=404, detail="Address not found.")
        best = features[0]
        lng, lat = best["center"]
        return GeocodeResult(lat=lat, lng=lng, display_name=best["place_name"])

    headers = {"User-Agent": os.getenv("GEOCODER_USER_AGENT", "polygon-checker-demo/1.0")}
    response = requests.get(
        "https://nominatim.openstreetmap.org/search",
        params={"q": address, "format": "jsonv2", "limit": 1},
        headers=headers,
        timeout=20,
    )
    response.raise_for_status()
    results = response.json()
    if not results:
        raise HTTPException(status_code=404, detail="Address not found.")
    best = results[0]
    return GeocodeResult(lat=float(best["lat"]), lng=float(best["lon"]), display_name=best["display_name"])


# ─── Email Helpers ────────────────────────────────────────────────────────────

def app_base_url(request: Request | None = None) -> str:
    configured = os.getenv("APP_BASE_URL", "").rstrip("/")
    if configured:
        return configured
    if request is not None:
        return str(request.base_url).rstrip("/")
    return "http://127.0.0.1:8000"


def send_email_message(to_email: str, subject: str, text_body: str) -> bool:
    """Send email via Resend HTTP API (preferred) with SMTP fallback."""
    from_email = os.getenv("SMTP_FROM_EMAIL", "noreply@rightg.com")

    # ── Resend HTTP API (works as long as SMTP_PASSWORD is a re_... key) ──
    resend_api_key = os.getenv("RESEND_API_KEY") or os.getenv("SMTP_PASSWORD", "")
    if resend_api_key.startswith("re_"):
        try:
            resp = requests.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {resend_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": from_email,
                    "to": [to_email],
                    "subject": subject,
                    "text": text_body,
                },
                timeout=10,
            )
            if resp.status_code in (200, 201):
                print(f"[email] Resend API: sent '{subject}' to {to_email}")
                return True
            print(f"[email] Resend API error {resp.status_code}: {resp.text}")
        except Exception as exc:
            print(f"[email] Resend API exception: {exc}")

    # ── SMTP fallback ──────────────────────────────────────────────────────
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    use_tls = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes"}
    if not host:
        print("[email] No email provider configured.")
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email
    msg.set_content(text_body)
    try:
        with smtplib.SMTP(host, port, timeout=8) as server:
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()
            if username and password:
                server.login(username, password)
            server.send_message(msg)
        print(f"[email] SMTP: sent '{subject}' to {to_email}")
        return True
    except Exception as exc:
        print(f"[email] SMTP failed: {exc}")
        return False


def _make_verification_token(user_id: int) -> str:
    """Create a fresh email-verification token in the DB and return the token string."""
    token = secrets.token_urlsafe(32)
    with get_db() as conn:
        conn.execute("DELETE FROM email_verification_tokens WHERE user_id = ? AND used_at IS NULL", (user_id,))
        conn.execute(
            "INSERT INTO email_verification_tokens (user_id, token, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (user_id, token, add_hours_iso(EMAIL_TOKEN_HOURS), utc_now_iso()),
        )
    return token


def _make_reset_token(user_id: int) -> str:
    """Create a fresh password-reset token in the DB and return the token string."""
    token = secrets.token_urlsafe(32)
    with get_db() as conn:
        conn.execute("DELETE FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL", (user_id,))
        conn.execute(
            "INSERT INTO password_reset_tokens (user_id, token, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (user_id, token, add_hours_iso(RESET_TOKEN_HOURS), utc_now_iso()),
        )
    return token


def send_verification_email(email: str, verify_url: str) -> None:
    """Background-safe: send the verification email (called via BackgroundTasks)."""
    body = (
        "Welcome to RightG.\n\n"
        "Please verify your email by opening this link:\n"
        f"{verify_url}\n\n"
        f"This link expires in {EMAIL_TOKEN_HOURS} hours."
    )
    send_email_message(email, "Verify your RightG email", body)


def send_reset_email(email: str, reset_url: str) -> None:
    """Background-safe: send the password-reset email (called via BackgroundTasks)."""
    body = (
        "We received a request to reset your RightG password.\n\n"
        "Open this link to choose a new password:\n"
        f"{reset_url}\n\n"
        f"This link expires in {RESET_TOKEN_HOURS} hour."
    )
    send_email_message(email, "Reset your RightG password", body)


# Keep legacy wrappers for any internal callers
def issue_email_verification(user_id: int, email: str, base_url: str) -> str:
    token = _make_verification_token(user_id)
    verify_url = f"{base_url}/verify-email?token={token}"
    sent = False
    try:
        send_verification_email(email, verify_url)
        sent = True
    except Exception:
        pass
    return None if sent else verify_url


def issue_password_reset(user_id: int, email: str, base_url: str) -> str:
    token = _make_reset_token(user_id)
    reset_url = f"{base_url}/reset-password?token={token}"
    sent = False
    try:
        send_reset_email(email, reset_url)
        sent = True
    except Exception:
        pass
    return None if sent else reset_url


# ─── Page Routes ──────────────────────────────────────────────────────────────

@app.get("/")
def home(request: Request):
    """Landing page for visitors; redirect to dashboard if already logged in."""
    user_id = request.session.get("user_id")
    if user_id:
        return RedirectResponse(url="/dashboard", status_code=303)
    return FileResponse(STATIC_DIR / "home.html")


@app.get("/dashboard")
def dashboard_page(request: Request):
    gate = require_login_page(request)
    if isinstance(gate, RedirectResponse):
        return gate
    return FileResponse(STATIC_DIR / "dashboard.html")


@app.get("/checker")
def checker_page(request: Request):
    gate = require_login_page(request)
    if isinstance(gate, RedirectResponse):
        return gate
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/manage")
def manage_page(request: Request):
    gate = require_login_page(request)
    if isinstance(gate, RedirectResponse):
        return gate
    return FileResponse(STATIC_DIR / "admin.html")


# Keep /admin as backward-compatible alias
@app.get("/admin")
def admin_page(request: Request):
    gate = require_login_page(request)
    if isinstance(gate, RedirectResponse):
        return gate
    return FileResponse(STATIC_DIR / "admin.html")


@app.get("/login")
def login_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/signup")
def signup_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "signup.html")


@app.get("/forgot-password")
def forgot_password_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "forgot_password.html")


@app.get("/reset-password")
def reset_password_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "reset_password.html")


@app.get("/verify-email")
def verify_email_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "verify_email.html")


@app.get("/terms")
def terms_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "terms.html")


@app.get("/privacy")
def privacy_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "privacy.html")


# ─── Auth API ─────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/me", response_model=UserResponse)
def me(request: Request) -> UserResponse:
    return get_current_user(request)


@app.post("/api/signup", response_model=GenericMessage)
def signup(request: Request, background_tasks: BackgroundTasks, payload: SignupRequest) -> GenericMessage:
    email = payload.email.lower().strip()
    with get_db() as conn:
        existing = conn.execute("SELECT id, is_verified FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            if bool(existing["is_verified"]):
                raise HTTPException(status_code=400, detail="An account with that email already exists. Please log in.")
            # Unverified account — auto-verify and let them log in
            conn.execute("UPDATE users SET is_verified = 1 WHERE id = ?", (int(existing["id"]),))
            return GenericMessage(message="Account activated! You can now log in.")
        conn.execute(
            "INSERT INTO users (full_name, email, password_hash, created_at, is_verified) VALUES (?, ?, ?, ?, 1)",
            (payload.full_name.strip(), email, hash_password(payload.password), utc_now_iso()),
        )
    return GenericMessage(message="Account created! You can now log in.")


@app.post("/api/resend-verification", response_model=GenericMessage)
def resend_verification(request: Request, background_tasks: BackgroundTasks, payload: ResendVerificationRequest) -> GenericMessage:
    email = payload.email.lower().strip()
    with get_db() as conn:
        row = conn.execute("SELECT id, is_verified FROM users WHERE email = ?", (email,)).fetchone()
    if not row:
        return GenericMessage(message="If that email exists, a verification link has been sent.")
    if bool(row["is_verified"]):
        return GenericMessage(message="This email is already verified. You can log in.")
    token = _make_verification_token(int(row["id"]))
    verify_url = f"{app_base_url(request)}/verify-email?token={token}"
    background_tasks.add_task(send_verification_email, email, verify_url)
    return GenericMessage(message="Verification email sent. Please check your inbox.")


@app.post("/api/verify-email", response_model=GenericMessage)
def verify_email(request: Request, payload: VerifyEmailRequest) -> GenericMessage:
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT evt.id, evt.user_id, evt.expires_at, evt.used_at, u.full_name, u.email
            FROM email_verification_tokens evt
            JOIN users u ON u.id = evt.user_id
            WHERE evt.token = ?
            """,
            (payload.token,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="Invalid verification link.")
        if row["used_at"]:
            return GenericMessage(message="This email is already verified. You can log in now.")
        if parse_iso(row["expires_at"]) < utc_now():
            raise HTTPException(status_code=400, detail="This verification link has expired.")
        conn.execute("UPDATE users SET is_verified = 1 WHERE id = ?", (row["user_id"],))
        conn.execute("UPDATE email_verification_tokens SET used_at = ? WHERE id = ?", (utc_now_iso(), row["id"]))
    return GenericMessage(message="Email verified successfully. You can log in now.")


@app.post("/api/login", response_model=UserResponse)
def login(request: Request, payload: LoginRequest) -> UserResponse:
    email = payload.email.lower().strip()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not row or not verify_password(payload.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        if not row["is_verified"]:
            conn.execute("UPDATE users SET is_verified = 1 WHERE id = ?", (row["id"],))
        request.session["user_id"] = row["id"]
        row = conn.execute("SELECT * FROM users WHERE id = ?", (row["id"],)).fetchone()
    return row_to_user(row)


@app.post("/api/logout")
def logout(request: Request) -> dict[str, str]:
    request.session.clear()
    return {"message": "Logged out."}


@app.post("/api/forgot-password", response_model=GenericMessage)
def forgot_password(request: Request, background_tasks: BackgroundTasks, payload: ForgotPasswordRequest) -> GenericMessage:
    email = payload.email.lower().strip()
    with get_db() as conn:
        row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if not row:
        return GenericMessage(message="If that email exists, a reset link has been sent.")
    token = _make_reset_token(int(row["id"]))
    reset_url = f"{app_base_url(request)}/reset-password?token={token}"
    background_tasks.add_task(send_reset_email, email, reset_url)
    return GenericMessage(message="If that email exists, a reset link has been sent.")


@app.post("/api/reset-password", response_model=GenericMessage)
def reset_password(payload: ResetPasswordRequest) -> GenericMessage:
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, user_id, expires_at, used_at FROM password_reset_tokens WHERE token = ?",
            (payload.token,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="Invalid reset link.")
        if row["used_at"]:
            raise HTTPException(status_code=400, detail="This reset link has already been used.")
        if parse_iso(row["expires_at"]) < utc_now():
            raise HTTPException(status_code=400, detail="This reset link has expired.")
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(payload.password), row["user_id"]),
        )
        conn.execute(
            "UPDATE password_reset_tokens SET used_at = ? WHERE id = ?",
            (utc_now_iso(), row["id"]),
        )
    return GenericMessage(message="Password reset successfully. You can log in now.")


# ─── Projects API ─────────────────────────────────────────────────────────────

@app.get("/api/projects", response_model=list[ProjectResponse])
def list_projects(request: Request) -> list[ProjectResponse]:
    user = get_current_user(request)
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT p.id, p.name, p.description, p.created_at,
                   COUNT(pp.id) as polygon_count
            FROM projects p
            LEFT JOIN project_polygons pp ON pp.project_id = p.id
            WHERE p.user_id = ?
            GROUP BY p.id
            ORDER BY p.id ASC
            """,
            (user.id,),
        ).fetchall()
    return [
        ProjectResponse(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            created_at=row["created_at"],
            polygon_count=row["polygon_count"],
        )
        for row in rows
    ]


@app.post("/api/projects", response_model=ProjectResponse)
def create_project(request: Request, payload: CreateProjectRequest) -> ProjectResponse:
    user = get_current_user(request)
    with get_db() as conn:
        cursor = conn.execute(
            "INSERT INTO projects (user_id, name, description, created_at) VALUES (?, ?, ?, ?)",
            (user.id, payload.name.strip(), payload.description, utc_now_iso()),
        )
        project_id = cursor.lastrowid
        row = conn.execute(
            "SELECT id, name, description, created_at FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
    return ProjectResponse(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        created_at=row["created_at"],
        polygon_count=0,
    )


@app.delete("/api/projects/{project_id}")
def delete_project(request: Request, project_id: int) -> dict[str, str]:
    user = get_current_user(request)
    get_project_for_user(project_id, user.id)  # ownership check
    with get_db() as conn:
        conn.execute("DELETE FROM project_polygons WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    return {"message": "Project deleted."}


# ─── Project Polygon API ──────────────────────────────────────────────────────

@app.get("/api/projects/{project_id}/polygons")
def get_project_polygons(request: Request, project_id: int) -> dict[str, Any]:
    user = get_current_user(request)
    get_project_for_user(project_id, user.id)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT feature_json FROM project_polygons WHERE project_id = ? ORDER BY created_at",
            (project_id,),
        ).fetchall()
    features = [json.loads(row["feature_json"]) for row in rows]
    return {"type": "FeatureCollection", "features": features}


@app.get("/api/projects/{project_id}/polygon-list", response_model=list[PolygonSummary])
def get_project_polygon_list(request: Request, project_id: int) -> list[PolygonSummary]:
    user = get_current_user(request)
    get_project_for_user(project_id, user.id)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, name, geometry_type, source_file FROM project_polygons WHERE project_id = ? ORDER BY created_at",
            (project_id,),
        ).fetchall()
    return [
        PolygonSummary(
            id=row["id"],
            name=row["name"],
            geometry_type=row["geometry_type"],
            source_file=row["source_file"],
        )
        for row in rows
    ]


@app.post("/api/projects/{project_id}/polygons/upload")
async def upload_project_polygons(request: Request, project_id: int, file: UploadFile = File(...)) -> dict[str, Any]:
    user = get_current_user(request)
    get_project_for_user(project_id, user.id)

    filename = file.filename or ""
    lower_name = filename.lower()
    if not lower_name.endswith((".json", ".geojson", ".kml")):
        raise HTTPException(status_code=400, detail="Upload a .geojson, .json, or .kml file.")

    raw = await file.read()
    if lower_name.endswith(".kml"):
        payload = kml_to_geojson(raw, source_filename=filename)
    else:
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON file.") from exc

    validated = validate_geojson(payload, source_filename=filename)
    features = validated["features"]

    with get_db() as conn:
        for feature in features:
            props = feature.get("properties", {})
            poly_id = props.get("id") or str(uuid.uuid4())
            name = props.get("name", "Unnamed polygon")
            geom_type = feature.get("geometry", {}).get("type", "Unknown")
            source_file = props.get("source_file")
            conn.execute(
                """
                INSERT OR IGNORE INTO project_polygons (id, project_id, name, geometry_type, source_file, feature_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (poly_id, project_id, name, geom_type, source_file, json.dumps(feature), utc_now_iso()),
            )
        total = conn.execute(
            "SELECT COUNT(*) FROM project_polygons WHERE project_id = ?", (project_id,)
        ).fetchone()[0]

    return {
        "message": "Polygons added successfully.",
        "added_count": len(features),
        "total_polygon_count": total,
    }


@app.delete("/api/projects/{project_id}/polygons")
def clear_project_polygons(request: Request, project_id: int) -> dict[str, str]:
    user = get_current_user(request)
    get_project_for_user(project_id, user.id)
    with get_db() as conn:
        conn.execute("DELETE FROM project_polygons WHERE project_id = ?", (project_id,))
    return {"message": "All polygons deleted."}


@app.delete("/api/projects/{project_id}/polygons/{polygon_id}")
def delete_project_polygon(request: Request, project_id: int, polygon_id: str) -> dict[str, Any]:
    user = get_current_user(request)
    get_project_for_user(project_id, user.id)
    with get_db() as conn:
        result = conn.execute(
            "DELETE FROM project_polygons WHERE id = ? AND project_id = ?", (polygon_id, project_id)
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Polygon not found.")
        remaining = conn.execute(
            "SELECT COUNT(*) FROM project_polygons WHERE project_id = ?", (project_id,)
        ).fetchone()[0]
    return {"message": "Polygon deleted.", "remaining_polygon_count": remaining}


# ─── Address Check API ────────────────────────────────────────────────────────

@app.post("/api/projects/{project_id}/check-address", response_model=MatchResponse)
def check_address(request: Request, project_id: int, payload: AddressRequest) -> MatchResponse:
    user = get_current_user(request)
    get_project_for_user(project_id, user.id)

    with get_db() as conn:
        rows = conn.execute(
            "SELECT feature_json FROM project_polygons WHERE project_id = ?", (project_id,)
        ).fetchall()

    features = [json.loads(row["feature_json"]) for row in rows]
    if not features:
        raise HTTPException(status_code=400, detail="No polygons in this project. Upload polygons first.")

    geocode = geocode_address(payload.address)
    point = Point(geocode.lng, geocode.lat)

    matched_names: list[str] = []
    for feature in features:
        geom = shape(feature["geometry"])
        if geom.covers(point):
            matched_names.append(feature.get("properties", {}).get("name", "Unnamed polygon"))

    response = MatchResponse(
        address=payload.address,
        normalized_address=geocode.display_name,
        geocode=geocode,
        matched=bool(matched_names),
        matched_polygon_names=matched_names,
        total_polygons_checked=len(features),
    )

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO address_checks (
                user_id, project_id, input_address, normalized_address, lat, lng,
                matched, matched_polygon_names, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user.id,
                project_id,
                payload.address,
                response.normalized_address,
                response.geocode.lat,
                response.geocode.lng,
                1 if response.matched else 0,
                json.dumps(response.matched_polygon_names),
                utc_now_iso(),
            ),
        )
    return response


@app.get("/api/projects/{project_id}/my-checks")
def project_checks(request: Request, project_id: int) -> list[dict[str, Any]]:
    user = get_current_user(request)
    get_project_for_user(project_id, user.id)
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, input_address, normalized_address, lat, lng, matched, matched_polygon_names, created_at
            FROM address_checks
            WHERE user_id = ? AND project_id = ?
            ORDER BY id DESC LIMIT 20
            """,
            (user.id, project_id),
        ).fetchall()
    return [
        {
            "id": row["id"],
            "input_address": row["input_address"],
            "normalized_address": row["normalized_address"],
            "lat": row["lat"],
            "lng": row["lng"],
            "matched": bool(row["matched"]),
            "matched_polygon_names": json.loads(row["matched_polygon_names"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


# ─── Legacy API (kept for backward compat, uses polygons.geojson) ─────────────

def empty_feature_collection() -> dict[str, Any]:
    return {"type": "FeatureCollection", "features": []}


def load_geojson() -> dict[str, Any]:
    if POLYGONS_FILE.exists():
        return json.loads(POLYGONS_FILE.read_text(encoding="utf-8"))
    return empty_feature_collection()


def save_geojson(payload: dict[str, Any]) -> None:
    POLYGONS_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


@app.get("/api/polygons")
def get_polygons(request: Request) -> dict[str, Any]:
    get_current_user(request)
    return load_geojson()


@app.get("/api/polygon-list", response_model=list[PolygonSummary])
def get_polygon_list(request: Request) -> list[PolygonSummary]:
    get_current_user(request)
    items = []
    for feature in load_geojson().get("features", []):
        props = feature.get("properties", {})
        items.append(PolygonSummary(
            id=props.get("id", ""),
            name=props.get("name", "Unnamed polygon"),
            geometry_type=feature.get("geometry", {}).get("type", "Unknown"),
            source_file=props.get("source_file"),
        ))
    return items


@app.get("/api/my-checks")
def my_checks(request: Request) -> list[dict[str, Any]]:
    user = get_current_user(request)
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, input_address, normalized_address, lat, lng, matched, matched_polygon_names, created_at
            FROM address_checks WHERE user_id = ? ORDER BY id DESC LIMIT 20
            """,
            (user.id,),
        ).fetchall()
    return [
        {
            "id": row["id"],
            "input_address": row["input_address"],
            "normalized_address": row["normalized_address"],
            "lat": row["lat"],
            "lng": row["lng"],
            "matched": bool(row["matched"]),
            "matched_polygon_names": json.loads(row["matched_polygon_names"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]
