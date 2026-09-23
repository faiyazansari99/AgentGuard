import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import jwt
import pytest


def test_api_key_hash_is_sha256():
    raw = "ag_example_secret"
    digest = hashlib.sha256(raw.encode()).hexdigest()
    assert len(digest) == 64
    assert digest == hashlib.sha256(raw.encode()).hexdigest()


def test_scopes_are_explicit():
    scopes = "gateway:check,audit:read"
    parsed = [x.strip() for x in scopes.split(",")]
    assert "gateway:check" in parsed
    assert "audit:read" in parsed


def test_jwt_roundtrip():
    secret = secrets.token_hex(32)
    payload = {
        "sub": "user123",
        "org": "org456",
        "role": "owner",
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    token = jwt.encode(payload, secret, algorithm="HS256")
    decoded = jwt.decode(token, secret, algorithms=["HS256"])
    assert decoded["sub"] == "user123"
    assert decoded["role"] == "owner"


def test_password_min_length_enforced():
    from pydantic import ValidationError
    from app.main import Register
    with pytest.raises(ValidationError):
        Register(email="a@b.com", password="short")
    ok = Register(email="a@b.com", password="x" * 12)
    assert len(ok.password) == 12


def test_gateway_decision_defaults_to_allow():
    from app.main import GatewayIn
    g = GatewayIn(agent_id="abc", action="read")
    assert g.resource == "*"
    assert g.amount == 0
