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
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
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

app = FastAPI(title="Polygon Address Checker", version="5.0.0")
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

            CREATE TABLE IF NOT EXISTS address_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                input_address TEXT NOT NULL,
                normalized_address TEXT,
                lat REAL NOT NULL,
                lng REAL NOT NULL,
                matched INTEGER NOT NULL,
                matched_polygon_names TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
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

        columns = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "is_verified" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 0")


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


def empty_feature_collection() -> dict[str, Any]:
    return {"type": "FeatureCollection", "features": []}


def load_geojson() -> dict[str, Any]:
    if POLYGONS_FILE.exists():
        return json.loads(POLYGONS_FILE.read_text(encoding="utf-8"))
    return empty_feature_collection()


def save_geojson(payload: dict[str, Any]) -> None:
    POLYGONS_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


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
        "unnamed polygon",
        "untitled",
        "feature",
    }




def parse_kml_coordinates(raw_text: str) -> list[list[float]]:
    coords: list[list[float]] = []
    for chunk in raw_text.strip().split():
        parts = chunk.split(',')
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
    return tag.split('}', 1)[-1] if '}' in tag else tag


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
    if outer_coords_el is None or not (outer_coords_el.text or '').strip():
        raise HTTPException(status_code=400, detail="A KML polygon is missing coordinates.")

    rings = [parse_kml_coordinates(outer_coords_el.text or '')]

    for inner in find_children(polygon_el, "innerBoundaryIs"):
        inner_ring = find_first_child(inner, "LinearRing")
        if inner_ring is None:
            continue
        inner_coords_el = find_first_child(inner_ring, "coordinates")
        if inner_coords_el is None or not (inner_coords_el.text or '').strip():
            continue
        rings.append(parse_kml_coordinates(inner_coords_el.text or ''))

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
        placemark_name = (name_el.text or '').strip() if name_el is not None and name_el.text else None
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


def append_features(new_payload: dict[str, Any]) -> dict[str, Any]:
    existing = load_geojson()
    existing_features = existing.get("features", [])
    new_features = new_payload.get("features", [])
    merged = {"type": "FeatureCollection", "features": [*existing_features, *new_features]}
    save_geojson(merged)
    return merged


def polygon_summaries(geojson: dict[str, Any]) -> list[PolygonSummary]:
    items: list[PolygonSummary] = []
    for feature in geojson.get("features", []):
        props = feature.get("properties", {})
        items.append(
            PolygonSummary(
                id=props.get("id", ""),
                name=props.get("name", "Unnamed polygon"),
                geometry_type=feature.get("geometry", {}).get("type", "Unknown"),
                source_file=props.get("source_file"),
            )
        )
    return items


def geocode_address(address: str) -> GeocodeResult:
    provider = os.getenv("GEOCODER_PROVIDER", "nominatim").lower()

    if provider == "mapbox":
        token = os.getenv("MAPBOX_TOKEN")
        if not token:
            raise HTTPException(status_code=500, detail="MAPBOX_TOKEN is not configured.")
        url = f"https://api.mapbox.com/geocoding/v5/mapbox.places/{requests.utils.quote(address)}.json"
        response = requests.get(
            url,
            params={"access_token": token, "limit": 1},
            timeout=20,
        )
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


def save_check_history(user_id: int, request_address: str, response: MatchResponse) -> None:
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO address_checks (
                user_id, input_address, normalized_address, lat, lng, matched,
                matched_polygon_names, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                request_address,
                response.normalized_address,
                response.geocode.lat,
                response.geocode.lng,
                1 if response.matched else 0,
                json.dumps(response.matched_polygon_names),
                utc_now_iso(),
            ),
        )


def app_base_url(request: Request | None = None) -> str:
    configured = os.getenv("APP_BASE_URL", "").rstrip("/")
    if configured:
        return configured
    if request is not None:
        return str(request.base_url).rstrip("/")
    return "http://127.0.0.1:8000"


def send_email_message(to_email: str, subject: str, text_body: str) -> bool:
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("SMTP_FROM_EMAIL")
    use_tls = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes"}

    if not host or not from_email:
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email
    msg.set_content(text_body)

    with smtplib.SMTP(host, port, timeout=20) as server:
        if use_tls:
            server.starttls()
        if username and password:
            server.login(username, password)
        server.send_message(msg)
    return True


def issue_email_verification(user_id: int, email: str, base_url: str) -> str:
    token = secrets.token_urlsafe(32)
    with get_db() as conn:
        conn.execute("DELETE FROM email_verification_tokens WHERE user_id = ? AND used_at IS NULL", (user_id,))
        conn.execute(
            """
            INSERT INTO email_verification_tokens (user_id, token, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, token, add_hours_iso(EMAIL_TOKEN_HOURS), utc_now_iso()),
        )
    verify_url = f"{base_url}/verify-email?token={token}"
    body = (
        "Welcome to Address Coverage Checker.\n\n"
        "Please verify your email by opening this link:\n"
        f"{verify_url}\n\n"
        f"This link expires in {EMAIL_TOKEN_HOURS} hours."
    )
    sent = send_email_message(email, "Verify your email", body)
    return None if sent else verify_url


def issue_password_reset(user_id: int, email: str, base_url: str) -> str:
    token = secrets.token_urlsafe(32)
    with get_db() as conn:
        conn.execute("DELETE FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL", (user_id,))
        conn.execute(
            """
            INSERT INTO password_reset_tokens (user_id, token, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, token, add_hours_iso(RESET_TOKEN_HOURS), utc_now_iso()),
        )
    reset_url = f"{base_url}/reset-password?token={token}"
    body = (
        "We received a request to reset your password.\n\n"
        "Open this link to choose a new password:\n"
        f"{reset_url}\n\n"
        f"This link expires in {RESET_TOKEN_HOURS} hour."
    )
    sent = send_email_message(email, "Reset your password", body)
    return None if sent else reset_url


def parse_iso(dt_str: str) -> datetime:
    return datetime.fromisoformat(dt_str)


@app.get("/")
def home(request: Request):
    gate = require_login_page(request)
    if isinstance(gate, RedirectResponse):
        return gate
    return FileResponse(STATIC_DIR / "index.html")


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


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/me", response_model=UserResponse)
def me(request: Request) -> UserResponse:
    return get_current_user(request)


@app.post("/api/signup", response_model=GenericMessage)
def signup(request: Request, payload: SignupRequest) -> GenericMessage:
    email = payload.email.lower().strip()
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="An account with that email already exists.")
        cursor = conn.execute(
            "INSERT INTO users (full_name, email, password_hash, created_at, is_verified) VALUES (?, ?, ?, ?, 0)",
            (payload.full_name.strip(), email, hash_password(payload.password), utc_now_iso()),
        )
        user_id = cursor.lastrowid
    preview_url = issue_email_verification(user_id, email, app_base_url(request))
    return GenericMessage(
        message="Account created. Please verify your email before logging in.",
        preview_url=preview_url,
    )


@app.post("/api/resend-verification", response_model=GenericMessage)
def resend_verification(request: Request, payload: ResendVerificationRequest) -> GenericMessage:
    email = payload.email.lower().strip()
    with get_db() as conn:
        row = conn.execute("SELECT id, is_verified FROM users WHERE email = ?", (email,)).fetchone()
    if not row:
        return GenericMessage(message="If that email exists, a verification link has been sent.")
    if bool(row["is_verified"]):
        return GenericMessage(message="This email is already verified.")
    preview_url = issue_email_verification(int(row["id"]), email, app_base_url(request))
    return GenericMessage(
        message="Verification email sent.",
        preview_url=preview_url,
    )


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
    if not bool(row["is_verified"]):
        raise HTTPException(status_code=403, detail="Please verify your email before logging in.")
    request.session["user_id"] = row["id"]
    return row_to_user(row)


@app.post("/api/logout")
def logout(request: Request) -> dict[str, str]:
    request.session.clear()
    return {"message": "Logged out."}


@app.post("/api/forgot-password", response_model=GenericMessage)
def forgot_password(request: Request, payload: ForgotPasswordRequest) -> GenericMessage:
    email = payload.email.lower().strip()
    with get_db() as conn:
        row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if not row:
        return GenericMessage(message="If that email exists, a reset link has been sent.")
    preview_url = issue_password_reset(int(row["id"]), email, app_base_url(request))
    return GenericMessage(
        message="If that email exists, a reset link has been sent.",
        preview_url=preview_url,
    )


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


@app.get("/api/polygons")
def get_polygons(request: Request) -> dict[str, Any]:
    get_current_user(request)
    return load_geojson()


@app.get("/api/polygon-list", response_model=list[PolygonSummary])
def get_polygon_list(request: Request) -> list[PolygonSummary]:
    get_current_user(request)
    return polygon_summaries(load_geojson())


@app.post("/api/polygons/upload")
async def upload_polygons(request: Request, file: UploadFile = File(...)) -> dict[str, Any]:
    get_current_user(request)
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
    merged = append_features(validated)

    return {
        "message": "Polygons added successfully.",
        "added_count": len(validated["features"]),
        "total_polygon_count": len(merged["features"]),
    }


@app.delete("/api/polygons")
def clear_polygons(request: Request) -> dict[str, str]:
    get_current_user(request)
    save_geojson(empty_feature_collection())
    return {"message": "All polygons deleted."}


@app.delete("/api/polygons/{polygon_id}")
def delete_polygon(request: Request, polygon_id: str) -> dict[str, Any]:
    get_current_user(request)
    geojson = load_geojson()
    original = geojson.get("features", [])
    kept = [f for f in original if f.get("properties", {}).get("id") != polygon_id]

    if len(kept) == len(original):
        raise HTTPException(status_code=404, detail="Polygon not found.")

    updated = {"type": "FeatureCollection", "features": kept}
    save_geojson(updated)
    return {
        "message": "Polygon deleted.",
        "remaining_polygon_count": len(kept),
    }


@app.post("/api/check-address", response_model=MatchResponse)
def check_address(request: Request, payload: AddressRequest) -> MatchResponse:
    user = get_current_user(request)
    geojson = load_geojson()
    features = geojson.get("features", [])
    if not features:
        raise HTTPException(status_code=400, detail="No polygons saved. Upload polygons first.")

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
    save_check_history(user.id, payload.address, response)
    return response


@app.get("/api/my-checks")
def my_checks(request: Request) -> list[dict[str, Any]]:
    user = get_current_user(request)
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, input_address, normalized_address, lat, lng, matched, matched_polygon_names, created_at
            FROM address_checks
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 20
            """,
            (user.id,),
        ).fetchall()
    items = []
    for row in rows:
        items.append(
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
        )
    return items
