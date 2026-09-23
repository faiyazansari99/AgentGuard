from __future__ import annotations

import hashlib
import json
import os
import secrets
import uuid
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, create_engine, select, delete
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from passlib.context import CryptContext
from .redis_limiter import rate_limiter

BASE = Path(__file__).resolve().parent.parent
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE/'agentguard.db'}")
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_IN_PRODUCTION")
if JWT_SECRET == "CHANGE_ME_IN_PRODUCTION" and os.getenv("ENV", "development") == "production":
    raise RuntimeError("JWT_SECRET must be changed in production")
JWT_ALG = "HS256"
JWT_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "12"))
ALLOWED_ORIGINS = [x.strip() for x in os.getenv("ALLOWED_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000").split(",") if x.strip()]

pwd = CryptContext(schemes=["argon2"], deprecated="auto")
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    role: Mapped[str] = mapped_column(String(32), default="owner")
    org_id: Mapped[str] = mapped_column(String(32), index=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    model: Mapped[str] = mapped_column(String(200), default="Customer model")
    status: Mapped[str] = mapped_column(String(32), default="active")
    risk: Mapped[int] = mapped_column(Integer, default=0)
    owner: Mapped[str] = mapped_column(String(200), default="Owner")
    org_id: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(200), default="*")
    resource: Mapped[str] = mapped_column(String(500), default="*")
    effect: Mapped[str] = mapped_column(String(32), default="BLOCK")
    threshold: Mapped[float] = mapped_column(Float, default=0)
    org_id: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(32))
    agent: Mapped[str] = mapped_column(String(32), default="")
    action: Mapped[str] = mapped_column(String(200))
    decision: Mapped[str] = mapped_column(String(64))
    details: Mapped[str] = mapped_column(Text, default="")
    integrity_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    org_id: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    agent: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(200))
    amount: Mapped[float] = mapped_column(Float, default=0)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    requested_by: Mapped[str] = mapped_column(String(32))
    org_id: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    key_hash: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="active")
    scopes: Mapped[str] = mapped_column(Text, default="gateway:check")
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    org_id: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Integration(Base):
    __tablename__ = "integrations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    provider: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="connected")
    org_id: Mapped[str] = mapped_column(String(32), index=True)
    external_account: Mapped[str] = mapped_column(String(320), default="")
    token_ciphertext: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    severity: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(32), default="open")
    agent: Mapped[str] = mapped_column(String(32), default="")
    org_id: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


app = FastAPI(title="AgentGuard", version="2.0.0", description="AI Agent Governance & Audit Control Plane")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)


def now() -> datetime:
    return datetime.now(timezone.utc)


def uid() -> str:
    return secrets.token_hex(16)


def db() -> Session:
    return SessionLocal()


def _row(obj) -> dict:
    return {k: v for k, v in obj.__dict__.items() if k != "_sa_instance_state"}


def token(user: User) -> str:
    payload = {
        "sub": user.id,
        "org": user.org_id,
        "role": user.role,
        "exp": now() + timedelta(hours=JWT_HOURS),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def auth(authorization: str | None = Header(None)) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")
    try:
        return jwt.decode(authorization[7:], JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired session")


def require_role(*roles: str):
    def dep(u: dict[str, Any] = Depends(auth)) -> dict[str, Any]:
        if u.get("role") not in roles:
            raise HTTPException(403, "Insufficient role for this operation")
        return u
    return dep


def auth_api_key(x_api_key: str | None = Header(None)) -> dict[str, Any]:
    if not x_api_key or not x_api_key.startswith("ag_"):
        raise HTTPException(401, "API key authentication required")
    h = hashlib.sha256(x_api_key.encode()).hexdigest()
    with db() as s:
        k = s.scalar(select(ApiKey).where(ApiKey.key_hash == h, ApiKey.status == "active"))
        if not k:
            raise HTTPException(401, "Invalid or revoked API key")
        k.last_used = now()
        s.commit()
        return {"org": k.org_id, "api_key_id": k.id, "role": "api_key", "scopes": k.scopes, "sub": k.id}


def audit(dbx: Session, u: dict[str, Any], agent: str, action: str, decision: str, details: Any = ""):
    detail_text = json.dumps(details, sort_keys=True) if not isinstance(details, str) else details
    previous = dbx.scalar(select(Audit).where(Audit.org_id == u["org"]).order_by(Audit.id.desc()))
    prev_hash = previous.integrity_hash if previous else ""
    ts = now().isoformat()
    material = f"{prev_hash}|{u.get('sub','')}|{agent or ''}|{action}|{decision}|{detail_text}|{ts}"
    row = Audit(
        actor=u.get("sub", ""),
        org_id=u["org"],
        agent=agent or "",
        action=action,
        decision=decision,
        details=detail_text,
        integrity_hash=hashlib.sha256(material.encode()).hexdigest(),
    )
    dbx.add(row)


# ─── Pydantic ───

class Register(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12)


class Login(BaseModel):
    email: EmailStr
    password: str


class AgentIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    model: str = "Customer model"
    owner: str = "Owner"


class PolicyIn(BaseModel):
    name: str
    action: str = "*"
    resource: str = "*"
    effect: str = "BLOCK"
    threshold: float = 0


class GatewayIn(BaseModel):
    agent_id: str
    action: str
    resource: str = "*"
    amount: float = 0
    details: dict[str, Any] = {}


class ApprovalDecision(BaseModel):
    status: str = Field(pattern="^(approved|rejected)$")


class MfaCode(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class CheckoutIn(BaseModel):
    price_id: str


# ─── Helpers ───

def _mfa_lib():
    import pyotp
    return pyotp


def _fernet():
    from cryptography.fernet import Fernet
    key = os.getenv("INTEGRATION_ENCRYPTION_KEY", "")
    if not key:
        raise HTTPException(503, "INTEGRATION_ENCRYPTION_KEY is not configured")
    return Fernet(key.encode())


def _oauth_config(provider: str):
    configs = {
        "google": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "auth": "https://accounts.google.com/o/oauth2/v2/auth",
            "token": "https://oauth2.googleapis.com/token",
            "userinfo": "https://openidconnect.googleapis.com/v1/userinfo",
            "scope": "openid email profile",
        },
        "slack": {
            "client_id": os.getenv("SLACK_CLIENT_ID"),
            "client_secret": os.getenv("SLACK_CLIENT_SECRET"),
            "auth": "https://slack.com/oauth/v2/authorize",
            "token": "https://slack.com/api/oauth.v2.access",
            "userinfo": "https://slack.com/api/users.identity",
            "scope": "openid,email,profile",
        },
    }
    c = configs.get(provider)
    if not c or not c["client_id"] or not c["client_secret"]:
        raise HTTPException(503, f"{provider} OAuth is not configured")
    return c


def send_email(to: str, subject: str, body: str):
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("SMTP_FROM", user or "")
    if not host or not sender:
        return False
    import smtplib
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to
    msg.set_content(body)
    with smtplib.SMTP(host, port, timeout=10) as smtp:
        smtp.starttls()
        if user:
            smtp.login(user, password or "")
        smtp.send_message(msg)
    return True


def _post_form(url, data):
    req = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(data).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


# ─── Middleware ───

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ─── Routes ───

@app.get("/")
def home():
    for candidate in [BASE / "static/index.html", BASE / "index.html"]:
        if candidate.exists():
            return FileResponse(candidate)
    raise HTTPException(404, "Dashboard not found")


@app.get("/metrics")
def metrics():
    try:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        from fastapi.responses import Response
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
    except Exception:
        return {"status": "metrics_unavailable", "hint": "Install prometheus-client"}


@app.get("/health")
def health():
    return {"status": "ok", "service": "AgentGuard", "version": "2.0.0", "time": now().isoformat()}


# ─── OAuth (sign-in) ───

@app.get("/api/oauth/{provider}/start")
def oauth_start(provider: str):
    c = _oauth_config(provider)
    redirect = os.getenv("OAUTH_REDIRECT_BASE", "http://localhost:8000") + f"/api/oauth/{provider}/callback"
    state = jwt.encode({"provider": provider, "exp": now() + timedelta(minutes=10)}, JWT_SECRET, algorithm=JWT_ALG)
    params = {"client_id": c["client_id"], "redirect_uri": redirect, "response_type": "code", "scope": c["scope"], "state": state}
    return {"provider": provider, "authorization_url": c["auth"] + "?" + urllib.parse.urlencode(params), "state": state}


@app.get("/api/oauth/{provider}/callback")
def oauth_callback(provider: str, code: str, state: str = ""):
    c = _oauth_config(provider)
    redirect = os.getenv("OAUTH_REDIRECT_BASE", "http://localhost:8000") + f"/api/oauth/{provider}/callback"
    try:
        state_claims = jwt.decode(state, JWT_SECRET, algorithms=[JWT_ALG])
        if state_claims.get("provider") != provider:
            raise ValueError()
    except Exception:
        raise HTTPException(400, "Invalid OAuth state")
    data = _post_form(c["token"], {"client_id": c["client_id"], "client_secret": c["client_secret"], "code": code, "grant_type": "authorization_code", "redirect_uri": redirect})
    access = data.get("access_token")
    if not access:
        raise HTTPException(400, "OAuth token exchange failed")
    req = urllib.request.Request(c["userinfo"], headers={"Authorization": f"Bearer {access}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        profile = json.loads(r.read())
    email = profile.get("email") or profile.get("user", {}).get("email")
    if not email:
        raise HTTPException(400, "OAuth provider did not return an email")
    with db() as s:
        u = s.scalar(select(User).where(User.email == email.lower()))
        if not u:
            u = User(id=uid(), email=email.lower(), password_hash=pwd.hash(secrets.token_urlsafe(24)), role="owner", org_id=uid())
            s.add(u)
            s.commit()
            s.refresh(u)
        return {"access_token": token(u), "user": {"id": u.id, "email": u.email, "role": u.role, "org_id": u.org_id}, "provider": provider}


# ─── Auth ───

@app.post("/api/auth/register", dependencies=[Depends(rate_limiter)])
def register(x: Register):
    with db() as s:
        if s.scalar(select(User).where(User.email == x.email.lower())):
            raise HTTPException(409, "Email already registered")
        u = User(id=uid(), email=x.email.lower(), password_hash=pwd.hash(x.password), role="owner", org_id=uid())
        s.add(u)
        s.commit()
        s.refresh(u)
        return {"access_token": token(u), "mfa_required": False, "user": {"id": u.id, "email": u.email, "role": u.role, "org_id": u.org_id}}


@app.post("/api/auth/login", dependencies=[Depends(rate_limiter)])
def login(x: Login):
    with db() as s:
        u = s.scalar(select(User).where(User.email == x.email.lower()))
        if not u or not pwd.verify(x.password, u.password_hash):
            raise HTTPException(401, "Invalid credentials")
        if u.mfa_enabled:
            challenge = jwt.encode({"sub": u.id, "org": u.org_id, "purpose": "mfa", "exp": now() + timedelta(minutes=5)}, JWT_SECRET, algorithm=JWT_ALG)
            return {"mfa_required": True, "mfa_token": challenge, "user": {"id": u.id, "email": u.email, "role": u.role, "org_id": u.org_id}}
        return {"access_token": token(u), "mfa_required": False, "user": {"id": u.id, "email": u.email, "role": u.role, "org_id": u.org_id}}


@app.post("/api/auth/mfa-login")
def mfa_login(x: MfaCode, mfa_token: str = Header(..., alias="X-MFA-Token")):
    pyotp = _mfa_lib()
    try:
        claims = jwt.decode(mfa_token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired MFA challenge")
    if claims.get("purpose") != "mfa":
        raise HTTPException(401, "Invalid MFA challenge")
    with db() as s:
        u = s.scalar(select(User).where(User.id == claims["sub"], User.org_id == claims["org"]))
        if not u or not u.mfa_secret or not pyotp.TOTP(u.mfa_secret).verify(x.code, valid_window=1):
            raise HTTPException(401, "Invalid MFA code")
        return {"access_token": token(u), "mfa_required": False, "user": {"id": u.id, "email": u.email, "role": u.role, "org_id": u.org_id}}


@app.get("/api/me")
def me(u=Depends(auth)):
    return u


@app.post("/api/mfa/setup")
def mfa_setup(u=Depends(auth)):
    pyotp = _mfa_lib()
    with db() as s:
        user = s.scalar(select(User).where(User.id == u["sub"], User.org_id == u["org"]))
        if not user:
            raise HTTPException(404, "User not found")
        secret = pyotp.random_base32()
        user.mfa_secret = secret
        s.commit()
        uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="AgentGuard")
        return {"secret": secret, "otpauth_uri": uri, "message": "Scan the URI with your authenticator, then verify a code."}


@app.post("/api/mfa/verify")
def mfa_verify(x: MfaCode, u=Depends(auth)):
    pyotp = _mfa_lib()
    with db() as s:
        user = s.scalar(select(User).where(User.id == u["sub"], User.org_id == u["org"]))
        if not user or not user.mfa_secret or not pyotp.TOTP(user.mfa_secret).verify(x.code, valid_window=1):
            raise HTTPException(400, "Invalid MFA code")
        user.mfa_enabled = True
        s.commit()
        return {"enabled": True}


# ─── Agents ───

@app.get("/api/agents")
def agents(u=Depends(auth)):
    with db() as s:
        rows = s.scalars(select(Agent).where(Agent.org_id == u["org"]).order_by(Agent.created_at.desc())).all()
        return [_row(x) for x in rows]


@app.post("/api/agents")
def add_agent(x: AgentIn, u=Depends(require_role("owner", "admin", "developer"))):
    with db() as s:
        a = Agent(id=uid(), name=x.name, model=x.model, owner=x.owner, org_id=u["org"])
        s.add(a)
        s.commit()
        audit(s, u, a.id, "agent.create", "ALLOW", x.name)
        s.commit()
        return {"id": a.id}


@app.post("/api/agents/{aid}/pause")
def pause(aid: str, u=Depends(require_role("owner", "admin", "security"))):
    with db() as s:
        a = s.scalar(select(Agent).where(Agent.id == aid, Agent.org_id == u["org"]))
        if not a:
            raise HTTPException(404, "Agent not found")
        a.status = "paused"
        s.commit()
        audit(s, u, aid, "agent.pause", "ALLOW")
        s.commit()
        return {"status": "paused"}


@app.post("/api/agents/{aid}/resume")
def resume(aid: str, u=Depends(require_role("owner", "admin", "security"))):
    with db() as s:
        a = s.scalar(select(Agent).where(Agent.id == aid, Agent.org_id == u["org"]))
        if not a:
            raise HTTPException(404, "Agent not found")
        a.status = "active"
        s.commit()
        audit(s, u, aid, "agent.resume", "ALLOW")
        s.commit()
        return {"status": "active"}


@app.post("/api/agents/{aid}/kill")
def kill(aid: str, u=Depends(require_role("owner", "admin", "security"))):
    with db() as s:
        a = s.scalar(select(Agent).where(Agent.id == aid, Agent.org_id == u["org"]))
        if not a:
            raise HTTPException(404, "Agent not found")
        a.status = "killed"
        s.commit()
        audit(s, u, aid, "agent.kill", "BLOCK", "Emergency kill switch")
        s.commit()
        return {"status": "killed"}


# ─── Policies ───

@app.get("/api/policies")
def policies(u=Depends(auth)):
    with db() as s:
        rows = s.scalars(select(Policy).where(Policy.org_id == u["org"]).order_by(Policy.created_at.desc())).all()
        return [_row(x) for x in rows]


@app.post("/api/policies")
def add_policy(x: PolicyIn, u=Depends(require_role("owner", "admin", "security", "developer"))):
    if x.effect not in {"ALLOW", "BLOCK", "APPROVAL_REQUIRED"}:
        raise HTTPException(422, "Invalid policy effect")
    with db() as s:
        p = Policy(id=uid(), name=x.name, action=x.action, resource=x.resource, effect=x.effect, threshold=x.threshold, org_id=u["org"])
        s.add(p)
        s.commit()
        audit(s, u, "", "policy.create", "ALLOW", x.name)
        s.commit()
        return {"id": p.id}


# ─── Gateway ───

@app.post("/api/gateway/check")
def gateway(x: GatewayIn, authorization: str | None = Header(None), x_api_key: str | None = Header(None)):
    if x_api_key:
        u = auth_api_key(x_api_key)
        if "gateway:check" not in [v.strip() for v in u.get("scopes", "").split(",")]:
            raise HTTPException(403, "API key lacks gateway:check scope")
    else:
        u = auth(authorization)
    with db() as s:
        a = s.scalar(select(Agent).where(Agent.id == x.agent_id, Agent.org_id == u["org"]))
        if not a:
            raise HTTPException(404, "Agent not found")
        decision = "ALLOW"
        reason = "No policy matched"
        if a.status != "active":
            decision = "BLOCK"
            reason = "Agent is paused"
        else:
            for p in s.scalars(select(Policy).where(Policy.org_id == u["org"])).all():
                if p.action in ("*", x.action) and (p.resource == "*" or p.resource == x.resource) and x.amount >= p.threshold:
                    if p.effect == "BLOCK":
                        decision, reason = "BLOCK", p.name
                        break
                    if p.effect == "APPROVAL_REQUIRED":
                        decision, reason = "APPROVAL_REQUIRED", p.name
                    if p.effect == "ALLOW" and decision == "ALLOW":
                        reason = p.name
            if decision == "APPROVAL_REQUIRED":
                s.add(Approval(id=uid(), agent=x.agent_id, action=x.action, amount=x.amount, status="pending", requested_by=u.get("sub", ""), org_id=u["org"]))
        audit(s, u, x.agent_id, x.action, decision, x.details)
        s.commit()
        return {"decision": decision, "reason": reason}


# ─── Approvals ───

@app.get("/api/approvals")
def approvals(u=Depends(auth)):
    with db() as s:
        rows = s.scalars(select(Approval).where(Approval.org_id == u["org"]).order_by(Approval.created_at.desc())).all()
        return [_row(x) for x in rows]


@app.post("/api/approvals/{aid}/decision")
def approval_decision(aid: str, x: ApprovalDecision, u=Depends(require_role("owner", "admin", "approver"))):
    with db() as s:
        a = s.scalar(select(Approval).where(Approval.id == aid, Approval.org_id == u["org"]))
        if not a:
            raise HTTPException(404, "Approval not found")
        a.status = x.status
        audit(s, u, a.agent, "approval.decision", x.status, {"approval": aid})
        s.commit()
        return {"status": a.status}


# ─── Audit ───

@app.get("/api/audit")
def logs(u=Depends(auth)):
    with db() as s:
        rows = s.scalars(select(Audit).where(Audit.org_id == u["org"]).order_by(Audit.id.desc()).limit(500)).all()
        return [_row(x) for x in rows]


# ─── Integrations ───

@app.get("/api/integrations/oauth/{provider}/start")
def integration_oauth_start(provider: str, u=Depends(auth)):
    c = _oauth_config(provider)
    redirect = os.getenv("OAUTH_REDIRECT_BASE", "http://localhost:8000") + f"/api/integrations/oauth/{provider}/callback"
    state = jwt.encode({"provider": provider, "org": u["org"], "sub": u["sub"], "purpose": "integration", "exp": now() + timedelta(minutes=10)}, JWT_SECRET, algorithm=JWT_ALG)
    params = {"client_id": c["client_id"], "redirect_uri": redirect, "response_type": "code", "scope": c["scope"], "state": state}
    return {"authorization_url": c["auth"] + "?" + urllib.parse.urlencode(params)}


@app.get("/api/integrations/oauth/{provider}/callback")
def integration_oauth_callback(provider: str, code: str, state: str):
    c = _oauth_config(provider)
    redirect = os.getenv("OAUTH_REDIRECT_BASE", "http://localhost:8000") + f"/api/integrations/oauth/{provider}/callback"
    try:
        claims = jwt.decode(state, JWT_SECRET, algorithms=[JWT_ALG])
        if claims.get("purpose") != "integration" or claims.get("provider") != provider:
            raise ValueError()
    except Exception:
        raise HTTPException(400, "Invalid OAuth state")
    data = _post_form(c["token"], {"client_id": c["client_id"], "client_secret": c["client_secret"], "code": code, "grant_type": "authorization_code", "redirect_uri": redirect})
    access = data.get("access_token")
    if not access:
        raise HTTPException(400, "OAuth token exchange failed")
    f = _fernet()
    ciphertext = f.encrypt(access.encode()).decode()
    external_account = provider
    try:
        req = urllib.request.Request(c["userinfo"], headers={"Authorization": f"Bearer {access}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            profile = json.loads(r.read())
        external_account = profile.get("email") or profile.get("team", {}).get("name") or provider
    except Exception:
        pass
    with db() as s:
        row = Integration(id=uid(), provider=provider, status="connected", org_id=claims["org"], external_account=external_account, token_ciphertext=ciphertext)
        s.add(row)
        s.commit()
    return {"connected": True, "provider": provider, "external_account": external_account, "message": "Integration connected. You can close this window."}


@app.get("/api/integrations")
def integrations(u=Depends(auth)):
    with db() as s:
        rows = s.scalars(select(Integration).where(Integration.org_id == u["org"]).order_by(Integration.created_at.desc())).all()
        return [{"id": x.id, "provider": x.provider, "status": x.status, "external_account": x.external_account, "created_at": x.created_at} for x in rows]


@app.delete("/api/integrations/{iid}")
def disconnect_integration(iid: str, u=Depends(require_role("owner", "admin", "security"))):
    with db() as s:
        x = s.scalar(select(Integration).where(Integration.id == iid, Integration.org_id == u["org"]))
        if not x:
            raise HTTPException(404, "Integration not found")
        s.delete(x)
        audit(s, u, "", "integration.disconnect", "ALLOW", iid)
        s.commit()
        return {"disconnected": True}


# ─── Incidents ───

@app.get("/api/incidents")
def incidents(u=Depends(auth)):
    with db() as s:
        rows = s.scalars(select(Incident).where(Incident.org_id == u["org"]).order_by(Incident.created_at.desc())).all()
        return [_row(x) for x in rows]


# ─── API Keys ───

@app.get("/api/api-keys")
def keys(u=Depends(auth)):
    with db() as s:
        rows = s.scalars(select(ApiKey).where(ApiKey.org_id == u["org"])).all()
        return [{"id": x.id, "name": x.name, "status": x.status, "last_used": x.last_used, "created_at": x.created_at, "scopes": x.scopes} for x in rows]


@app.post("/api/api-keys")
def create_key(name: str = "Agent key", scopes: str = "gateway:check", u=Depends(require_role("owner", "admin", "developer"))):
    raw = "ag_" + secrets.token_urlsafe(32)
    with db() as s:
        k = ApiKey(id=uid(), name=name, key_hash=hashlib.sha256(raw.encode()).hexdigest(), scopes=scopes, org_id=u["org"])
        s.add(k)
        s.commit()
        audit(s, u, "", "api_key.create", "ALLOW", name)
        s.commit()
        return {"id": k.id, "key": raw, "warning": "Store this key now. It will not be shown again."}


@app.delete("/api/api-keys/{kid}")
def revoke_key(kid: str, u=Depends(require_role("owner", "admin", "security"))):
    with db() as s:
        k = s.scalar(select(ApiKey).where(ApiKey.id == kid, ApiKey.org_id == u["org"]))
        if not k:
            raise HTTPException(404, "API key not found")
        k.status = "revoked"
        audit(s, u, "", "api_key.revoke", "ALLOW", kid)
        s.commit()
        return {"revoked": True}


# ─── Export / Delete ───

@app.get("/api/export")
def export(u=Depends(auth)):
    with db() as s:
        out = {}
        for model, name in [(Agent, "agents"), (Policy, "policies"), (Audit, "audit"), (Approval, "approvals"), (Incident, "incidents"), (ApiKey, "api_keys"), (Integration, "integrations")]:
            rows = s.scalars(select(model).where(model.org_id == u["org"])).all()
            out[name] = [_row(r) for r in rows]
        return out


@app.delete("/api/account")
def delete_account(u=Depends(auth)):
    with db() as s:
        for model in [Agent, Policy, Audit, Approval, Incident, ApiKey, Integration, User]:
            s.execute(delete(model).where(model.org_id == u["org"]))
        s.commit()
        return {"deleted": True}


# ─── SCIM ───

def scim_auth(token_value: str | None):
    expected = os.getenv("SCIM_BEARER_TOKEN")
    if not expected or token_value != expected:
        raise HTTPException(401, "Invalid SCIM bearer token")


@app.get("/scim/v2/Users")
def scim_users(authorization: str | None = Header(None)):
    scim_auth(authorization.replace("Bearer ", "", 1) if authorization else None)
    org = os.getenv("SCIM_ORG_ID")
    if not org:
        raise HTTPException(503, "SCIM_ORG_ID is not configured")
    with db() as s:
        users = s.scalars(select(User).where(User.org_id == org)).all()
        return {"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "totalResults": len(users), "Resources": [{"id": u.id, "userName": u.email, "active": True} for u in users]}


@app.post("/scim/v2/Users")
def scim_create(payload: dict, authorization: str | None = Header(None)):
    scim_auth(authorization.replace("Bearer ", "", 1) if authorization else None)
    org = os.getenv("SCIM_ORG_ID")
    email = str(payload.get("userName", "")).lower()
    if not org or not email:
        raise HTTPException(400, "SCIM_ORG_ID and userName are required")
    with db() as s:
        if s.scalar(select(User).where(User.email == email)):
            raise HTTPException(409, "User already exists")
        u = User(id=uid(), email=email, password_hash=pwd.hash(secrets.token_urlsafe(32)), role="viewer", org_id=org)
        s.add(u)
        s.commit()
        s.refresh(u)
        return {"id": u.id, "userName": u.email, "active": True}


# ─── Billing ───

@app.post("/api/billing/checkout")
def billing_checkout(x: CheckoutIn, u=Depends(require_role("owner", "admin"))):
    try:
        import stripe
    except ImportError:
        raise HTTPException(503, "Stripe SDK is not installed")
    key = os.getenv("STRIPE_SECRET_KEY")
    if not key:
        raise HTTPException(503, "STRIPE_SECRET_KEY is not configured")
    stripe.api_key = key
    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": x.price_id, "quantity": 1}],
            success_url=os.getenv("STRIPE_SUCCESS_URL", "http://localhost:8000/?billing=success"),
            cancel_url=os.getenv("STRIPE_CANCEL_URL", "http://localhost:8000/?billing=cancel"),
            metadata={"org_id": u["org"]},
        )
        return {"url": session.url, "session_id": session.id}
    except Exception as exc:
        raise HTTPException(400, f"Stripe checkout failed: {exc}")


@app.post("/api/billing/webhook")
async def billing_webhook(request: Request, stripe_signature: str | None = Header(None, alias="Stripe-Signature")):
    try:
        import stripe
    except ImportError:
        raise HTTPException(503, "Stripe SDK is not installed")
    secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(503, "STRIPE_WEBHOOK_SECRET is not configured")
    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(payload, stripe_signature, secret)
    except Exception:
        raise HTTPException(400, "Invalid Stripe webhook")
    return {"received": True, "type": event["type"]}
