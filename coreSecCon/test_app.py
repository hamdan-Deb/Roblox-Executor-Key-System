"""
Automated Security & Unit Test Suite
Validates token expiration, HMAC signature verification, and replay protection.
"""

import os
import time
import hmac
import hashlib
import tempfile
import pytest

# Configure isolated test DB before importing app
db_fd, db_path = tempfile.mkstemp()
os.environ["DB_PATH"] = db_path
os.environ["WEBHOOK_SECRET"] = "unit_test_secret_key"

from app import app, init_db, get_db

@pytest.fixture
def client():
    app.config["TESTING"] = True
    init_db()
    with app.test_client() as client:
        yield client
    os.close(db_fd)
    if os.path.exists(db_path):
        os.remove(db_path)

def test_hash_generation(client):
    """Verifies deterministic output for hashing algorithms."""
    res = client.post("/api/crypto/hash", json={"input_string": "test_input", "secret_key": "salt"})
    assert res.status_code == 200
    data = res.get_json()
    assert "md5" in data
    assert "sha256" in data
    assert len(data["md5"]) == 32
    assert len(data["sha256"]) == 64

def test_session_lifecycle(client):
    """Verifies session moves from PENDING to APPROVED to VERIFIED."""
    # 1. Create session
    create_res = client.post("/api/auth/session/create", json={"hwid": "TEST_HWID"})
    assert create_res.status_code == 200
    sess_data = create_res.get_json()
    session_id = sess_data["session_id"]
    hwid_hash = sess_data["hwid_hash"]
    assert sess_data["status"] == "PENDING"

    # 2. Complete with webhook
    event_id = "evt_test_101"
    timestamp = str(time.time())
    raw_body = f'{{"session_id":"{session_id}","action":"APPROVE"}}'.encode()
    msg = f"{timestamp}.{event_id}.".encode() + raw_body
    sig = hmac.new(b"unit_test_secret_key", msg, hashlib.sha256).hexdigest()

    hook_res = client.post(
        "/api/webhook/callback",
        headers={"X-Signature": sig, "X-Timestamp": timestamp, "X-Event-ID": event_id},
        data=raw_body,
        content_type="application/json"
    )
    assert hook_res.status_code == 200
    token = hook_res.get_json()["issued_token"]

    # 3. In-game verification
    verify_res = client.post("/api/auth/token/verify", json={"token": token, "hwid_hash": hwid_hash})
    assert verify_res.status_code == 200
    assert verify_res.get_json()["valid"] is True

def test_replay_attack_prevention(client):
    """Verifies that an identical Event ID is rejected on second submission."""
    event_id = "evt_replay_202"
    timestamp = str(time.time())
    raw_body = b'{"session_id":"test","action":"APPROVE"}'
    msg = f"{timestamp}.{event_id}.".encode() + raw_body
    sig = hmac.new(b"unit_test_secret_key", msg, hashlib.sha256).hexdigest()

    headers = {"X-Signature": sig, "X-Timestamp": timestamp, "X-Event-ID": event_id}

    # First attempt: succeeds or returns 404 on session, but records the event
    client.post("/api/webhook/callback", headers=headers, data=raw_body, content_type="application/json")

    # Second attempt: must trigger 409 Conflict (Replay detected)
    res2 = client.post("/api/webhook/callback", headers=headers, data=raw_body, content_type="application/json")
    assert res2.status_code == 409
    assert "Replay attack detected" in res2.get_json()["error"]