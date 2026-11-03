#!/usr/bin/env python3
"""
Authentication Architecture & Cryptographic Verification Simulator
An educational cybersecurity laboratory demonstrating modern token lifecycles,
HMAC webhook verification, replay protection, and URL payload parsing.

STRICT SAFETY MANDATE:
- All actions are 100% simulated in local memory and SQLite.
- Never connects to Roblox, Delta, PlatoRelay, or any third-party gateway.
"""

import os
import re
import time
import hmac
import base64
import hashlib
import secrets
import sqlite3
import urllib.parse
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
DB_PATH = os.environ.get("DB_PATH", "auth_sim.db")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "super_secret_signing_key_2026")
REPLAY_WINDOW_SECONDS = 300  # 5-minute threshold for replay mitigation

# In-memory sliding window for simple rate limiting
RATE_LIMIT_STORE = {}

# -----------------------------------------------------------------------------
# Database Setup & Utilities
# -----------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            hwid_hash TEXT NOT NULL,
            status TEXT NOT NULL, /* PENDING, APPROVED, EXPIRED, REJECTED */
            token TEXT,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS processed_webhooks (
            event_id TEXT PRIMARY KEY,
            received_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL, /* INFO, WARNING, ALERT */
            description TEXT NOT NULL
        );
        """)
        conn.commit()

def log_event(event_type: str, severity: str, description: str):
    iso_now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO security_logs (timestamp, event_type, severity, description) VALUES (?, ?, ?, ?)",
            (iso_now, event_type, severity, description)
        )
        conn.commit()

# -----------------------------------------------------------------------------
# Core Rate Limiting Middleware
# -----------------------------------------------------------------------------
def check_rate_limit(ip: str, max_requests: int = 40, window_seconds: int = 60) -> bool:
    now = time.time()
    timestamps = RATE_LIMIT_STORE.get(ip, [])
    # Filter out requests older than window
    timestamps = [t for t in timestamps if now - t < window_seconds]
    if len(timestamps) >= max_requests:
        return False
    timestamps.append(now)
    RATE_LIMIT_STORE[ip] = timestamps
    return True

# -----------------------------------------------------------------------------
# Module 1: URL Payload Explorer API
# -----------------------------------------------------------------------------
@app.route("/api/explore-url", methods=["POST"])
def explore_url():
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "").strip()

    if not raw_url:
        return jsonify({"error": "No URL provided"}), 400

    parsed = urllib.parse.urlparse(raw_url)
    query_params = urllib.parse.parse_qs(parsed.query)

    inspected_params = {}
    for key, values in query_params.items():
        val = values[0] if values else ""
        
        # Check URL encoding status
        unquoted = urllib.parse.unquote(val)
        is_url_encoded = (unquoted != val)

        # Check for potential Base64 structure (safe heuristic)
        b64_candidate = False
        decoded_preview = None
        # Must be valid length and conform to Base64 charset
        if len(val) >= 8 and len(val) % 4 == 0 and re.match(r"^[A-Za-z0-9+/=]+$", val):
            try:
                raw_bytes = base64.b64decode(val, validate=True)
                # Check if decoded payload contains printable UTF-8 characters
                decoded_str = raw_bytes.decode("utf-8", errors="ignore")
                if sum(c.isprintable() for c in decoded_str) / (len(decoded_str) or 1) > 0.8:
                    b64_candidate = True
                    decoded_preview = decoded_str[:250]
            except Exception:
                b64_candidate = False

        inspected_params[key] = {
            "raw_value": val,
            "url_decoded": unquoted,
            "is_url_encoded": is_url_encoded,
            "is_base64_candidate": b64_candidate,
            "decoded_preview": decoded_preview,
            "encoding_warning": (
                "Base64 represents encoding, NOT encryption. Anyone with access to "
                "this string can immediately decode it without a secret key."
            ) if b64_candidate else None
        }

    return jsonify({
        "scheme": parsed.scheme or "none",
        "host": parsed.netloc or "none",
        "path": parsed.path or "/",
        "parameters": inspected_params,
        "educational_notice": "Never assume high-entropy strings are automatically Base64 or decryptable."
    })

# -----------------------------------------------------------------------------
# Module 2: Cryptography Playground API
# -----------------------------------------------------------------------------
@app.route("/api/crypto/hash", methods=["POST"])
def crypto_hash():
    data = request.get_json(silent=True) or {}
    raw_text = data.get("input_string", "").encode("utf-8")
    key = data.get("secret_key", "").encode("utf-8")

    md5_digest = hashlib.md5(raw_text).hexdigest()
    sha256_digest = hashlib.sha256(raw_text).hexdigest()
    hmac_digest = hmac.new(key or b"default_salt", raw_text, hashlib.sha256).hexdigest()

    return jsonify({
        "input_length_bytes": len(raw_text),
        "md5": md5_digest,
        "sha256": sha256_digest,
        "hmac_sha256": hmac_digest,
        "technical_correction": (
            "IMPORTANT ARCHITECTURAL NOTE: A 32-character hexadecimal digest matches the 128-bit output "
            "of MD5, but it is also mathematically compatible with 16 random hex bytes, a truncated SHA-256 "
            "digest, or a custom hash. Format matching alone is not proof of the MD5 algorithm."
        ),
        "irreversibility_concept": (
            "Cryptographic hashes are one-way compression functions. They map arbitrary-length inputs "
            "to a fixed digest size. Information is mathematically destroyed, making mathematical reversal impossible."
        )
    })

@app.route("/api/crypto/generate-token", methods=["GET"])
def generate_token():
    # Demonstrating cryptographically secure pseudo-random generation (CSPRNG)
    random_bytes = secrets.token_bytes(16)
    hex_token = random_bytes.hex()
    session_token = f"SIM_{hex_token}"
    
    return jsonify({
        "token": session_token,
        "hex_digest": hex_token,
        "entropy_bits": 128,
        "generator_method": "secrets.token_bytes(16) [CSPRNG]"
    })

# -----------------------------------------------------------------------------
# Module 3: Authentication Simulator API
# -----------------------------------------------------------------------------
@app.route("/api/auth/session/create", methods=["POST"])
def create_session():
    client_ip = request.remote_addr or "127.0.0.1"
    if not check_rate_limit(client_ip):
        log_event("RATE_LIMIT_EXCEEDED", "ALERT", f"IP {client_ip} exceeded request velocity.")
        return jsonify({"error": "Rate limit exceeded. Please throttle requests."}), 429

    data = request.get_json(silent=True) or {}
    hwid = data.get("hwid", "").strip() or f"HWID_{secrets.token_hex(8)}"
    hwid_hash = hashlib.sha256(hwid.encode("utf-8")).hexdigest()[:32]

    session_id = f"sess_{secrets.token_hex(8)}"
    now = time.time()
    expires_at = now + 120  # 2-minute life window for demonstration

    with get_db() as conn:
        conn.execute(
            "INSERT INTO sessions (session_id, hwid_hash, status, token, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, hwid_hash, "PENDING", None, now, expires_at)
        )
        conn.commit()

    log_event("SESSION_CREATED", "INFO", f"Session {session_id} initialized in PENDING state.")

    # Mint a mock gateway challenge URL
    encoded_payload = base64.urlsafe_b64encode(
        f'{{"session":"{session_id}","hwid_hash":"{hwid_hash}","iat":{int(now)}}}'.encode()
    ).decode()

    simulated_gateway_url = f"https://auth.simulator.internal/verify?d={encoded_payload}"

    return jsonify({
        "session_id": session_id,
        "hwid_hash": hwid_hash,
        "status": "PENDING",
        "created_at": now,
        "expires_at": expires_at,
        "simulated_gateway_url": simulated_gateway_url
    })

@app.route("/api/auth/token/verify", methods=["POST"])
def verify_token():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    hwid_hash = data.get("hwid_hash", "").strip()

    if not token:
        return jsonify({"valid": False, "reason": "No token provided."}), 400

    now = time.time()
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE token = ?", (token,)
        ).fetchone()

        if not row:
            log_event("INVALID_TOKEN_ATTEMPT", "ALERT", f"Lookup failed for token: {token[:16]}...")
            return jsonify({
                "valid": False, 
                "reason": "Token does not exist in backend database. (Offline generation fails here)."
            }), 401

        # Check expiration state
        if now > row["expires_at"]:
            conn.execute("UPDATE sessions SET status = 'EXPIRED' WHERE session_id = ?", (row["session_id"],))
            conn.commit()
            log_event("EXPIRED_TOKEN_ATTEMPT", "WARNING", f"Token for session {row['session_id']} has expired.")
            return jsonify({"valid": False, "reason": "Temporary authorization key has expired."}), 401

        # Check status
        if row["status"] != "APPROVED":
            return jsonify({"valid": False, "reason": f"Session status is {row['status']}, not APPROVED."}), 403

        # Check HWID affinity binding
        if hwid_hash and row["hwid_hash"] != hwid_hash:
            log_event("HWID_MISMATCH", "ALERT", f"Token {token[:12]} submitted from unauthorized HWID.")
            return jsonify({"valid": False, "reason": "HWID binding mismatch. Key belongs to another device."}), 403

    log_event("TOKEN_VALIDATED", "INFO", f"Session {row['session_id']} successfully granted execution ticket.")
    return jsonify({
        "valid": True,
        "session_id": row["session_id"],
        "status": "AUTHORIZED",
        "remaining_seconds": int(row["expires_at"] - now)
    })

# -----------------------------------------------------------------------------
# Module 4: Webhook Simulator & Replay Defense API
# -----------------------------------------------------------------------------
@app.route("/api/webhook/callback", methods=["POST"])
def webhook_callback():
    client_ip = request.remote_addr or "127.0.0.1"
    if not check_rate_limit(client_ip):
        return jsonify({"error": "Rate limit exceeded"}), 429

    signature = request.headers.get("X-Signature", "").strip()
    timestamp_str = request.headers.get("X-Timestamp", "").strip()
    event_id = request.headers.get("X-Event-ID", "").strip()
    raw_body = request.get_data()

    # Defense 1: Header completeness
    if not (signature and timestamp_str and event_id):
        log_event("WEBHOOK_REJECTED", "WARNING", "Missing required security headers (Signature, Timestamp, Event-ID).")
        return jsonify({"error": "Missing required security headers"}), 400

    # Defense 2: Replay Attack Protection via Timestamp Tolerance
    try:
        req_timestamp = float(timestamp_str)
    except ValueError:
        return jsonify({"error": "Invalid timestamp format"}), 400

    current_time = time.time()
    if abs(current_time - req_timestamp) > REPLAY_WINDOW_SECONDS:
        log_event("REPLAY_ATTACK_ATTEMPT", "ALERT", f"Timestamp out of bounds (Delta: {abs(current_time - req_timestamp):.1f}s).")
        return jsonify({"error": "Request timestamp expired or outside tolerance window (Replay Mitigation)."}), 400

    # Defense 3: Cryptographic Signature Verification (HMAC-SHA256)
    expected_message = f"{timestamp_str}.{event_id}.".encode() + raw_body
    computed_sig = hmac.new(WEBHOOK_SECRET.encode(), expected_message, hashlib.sha256).hexdigest()

    # Use constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(computed_sig, signature):
        log_event("INVALID_SIGNATURE", "ALERT", f"Signature mismatch for Event ID: {event_id}.")
        return jsonify({"error": "Cryptographic signature validation failed. Payload tampered or wrong key."}), 403

    # Defense 4: Replay Attack Protection via Nonce / Event ID Caching
    with get_db() as conn:
        existing_event = conn.execute(
            "SELECT 1 FROM processed_webhooks WHERE event_id = ?", (event_id,)
        ).fetchone()

        if existing_event:
            log_event("REPLAY_ATTACK_ATTEMPT", "ALERT", f"Replay detected! Event ID {event_id} already consumed.")
            return jsonify({"error": "Replay attack detected. Event ID has already been processed."}), 409

        # Register event ID immediately
        conn.execute("INSERT INTO processed_webhooks (event_id, received_at) VALUES (?, ?)", (event_id, current_time))

        # Process payload logic
        body_json = request.get_json(silent=True) or {}
        session_id = body_json.get("session_id")
        action = body_json.get("action")  # e.g., "APPROVE", "REJECT"

        session = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        if not session:
            return jsonify({"error": f"Session {session_id} not found."}), 404

        if action == "APPROVE":
            # Mint temporary key (32 hex characters)
            minted_token = f"FREE_{secrets.token_hex(16)}"
            conn.execute(
                "UPDATE sessions SET status = 'APPROVED', token = ? WHERE session_id = ?",
                (minted_token, session_id)
            )
            conn.commit()
            log_event("SESSION_APPROVED", "INFO", f"Session {session_id} marked APPROVED. Token generated.")
            return jsonify({
                "message": "Webhook processed successfully.",
                "session_id": session_id,
                "status": "APPROVED",
                "issued_token": minted_token
            })
        else:
            conn.execute("UPDATE sessions SET status = 'REJECTED' WHERE session_id = ?", (session_id,))
            conn.commit()
            log_event("SESSION_REJECTED", "INFO", f"Session {session_id} marked REJECTED.")
            return jsonify({"message": "Session marked rejected.", "session_id": session_id})

# -----------------------------------------------------------------------------
# Module 5: Security Dashboard & Diagnostic APIs
# -----------------------------------------------------------------------------
@app.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():
    now = time.time()
    with get_db() as conn:
        sessions = conn.execute("SELECT * FROM sessions ORDER BY created_at DESC LIMIT 20").fetchall()
        logs = conn.execute("SELECT * FROM security_logs ORDER BY id DESC LIMIT 25").fetchall()

    session_list = []
    for s in sessions:
        status = s["status"]
        if status == "APPROVED" and now > s["expires_at"]:
            status = "EXPIRED"
        session_list.append({
            "session_id": s["session_id"],
            "hwid_hash": s["hwid_hash"],
            "status": status,
            "token": s["token"],
            "expires_in": max(0, int(s["expires_at"] - now))
        })

    log_list = [{
        "timestamp": l["timestamp"],
        "event_type": l["event_type"],
        "severity": l["severity"],
        "description": l["description"]
    } for l in logs]

    return jsonify({
        "active_sessions": session_list,
        "logs": log_list,
        "server_time": now
    })

# -----------------------------------------------------------------------------
# Frontend Route
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    init_db()
    print("[*] Authentication & Cryptographic Lab initialized on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)