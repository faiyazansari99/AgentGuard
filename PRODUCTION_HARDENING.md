# AgentGuard production hardening

Implemented in this upgrade:
- PostgreSQL-capable SQLAlchemy backend; SQLite remains available for local development.
- Argon2 password hashing (replacing SHA-256 password storage).
- Strict configurable CORS.
- Per-IP application rate limiter; use a Redis/edge limiter for multi-instance production.
- Security response headers and HSTS on HTTPS.
- Role enforcement for sensitive agent/policy/approval/key operations.
- Tenant-scoped database queries.
- Approval creation and decision workflow.
- API-key revocation.
- PostgreSQL + Redis Docker services.
- Daily-backup script and Nginx TLS reverse-proxy template.

Still required before a real public enterprise launch:
1. Run behind HTTPS with a managed WAF/CDN (e.g. Cloudflare) and trusted certificates.
2. Put rate limiting at the edge and/or use Redis atomic counters for multiple application replicas.
3. Use Alembic migrations instead of startup-only table creation.
4. Configure real backups, off-site retention, restore drills, monitoring and alerting.
5. Add a real MFA provider/TOTP enrollment flow and enterprise SAML/OIDC/SCIM integration.
6. Run dependency scanning, SAST, DAST, penetration testing and secret scanning.
7. Complete jurisdiction-specific privacy/terms/legal review and Play Console declarations.
