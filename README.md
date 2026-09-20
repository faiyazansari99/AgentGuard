# AgentGuard — Enterprise AI Agent Governance & Audit Layer

AgentGuard sits between AI agents and business systems and makes deterministic policy decisions: **ALLOW / APPROVAL_REQUIRED / BLOCK**.

## Included in this build
- FastAPI API + responsive dashboard
- PostgreSQL + SQLite-compatible SQLAlchemy models
- Alembic migrations (no `create_all()` in application startup)
- Argon2 password hashing + JWT sessions
- Real TOTP MFA setup, verification, and MFA login challenge
- Redis-backed distributed rate limiting with explicit local-fallback flag
- Tenant-aware agent registry, pause/resume/kill controls
- Deterministic policy engine and approval workflow
- API keys with hashed storage and gateway scope enforcement
- Hash-chained audit records
- Google + Slack OAuth authorization endpoints (provider credentials required)
- Stripe subscription checkout + signed webhook verification (Stripe credentials required)
- SMTP-ready notification helper
- Prometheus `/metrics` endpoint
- SCIM provisioning boundary for enterprise deployments
- Docker + PostgreSQL + Redis + migration entrypoint
- Nginx reverse-proxy template and PostgreSQL backup script
- Responsive mobile/tablet/desktop UI
- Export/delete controls and security headers

## Run
1. Copy `.env.example` to `.env` and set strong secrets.
2. `docker compose up --build`
3. Open `http://localhost:8000`.

The container runs `alembic upgrade head` before starting FastAPI.

## Important production configuration
Real Google/Slack OAuth, Stripe billing, SMTP, SSO/SAML, SCIM, TLS certificates, DNS, WAF, backups, monitoring alerts, and provider-specific credentials must be configured for each deployment. Never commit `.env` or secrets.

## Security boundary
AgentGuard's deterministic policy engine must remain authoritative. Optional AI risk analysis may add signals, but it must not override a deterministic BLOCK.

## Pre-sale checklist
- Run unit/integration/security tests in CI.
- Configure PostgreSQL, Redis, TLS and WAF.
- Test backup restore.
- Configure OAuth callback URLs and secrets.
- Configure Stripe webhook signing secret.
- Configure SMTP/alerting.
- Complete an independent penetration test/security review appropriate to the customer and deployment.
- Have legal counsel review Terms, Privacy, DPA, SLA and any compliance claims.
