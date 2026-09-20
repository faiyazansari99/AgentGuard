# AgentGuard final build audit

## Implemented in this package
- Alembic migrations and Docker migration startup
- Redis distributed rate limiting; local fallback is opt-in only
- Argon2 password hashing
- JWT auth + TOTP MFA challenge/login
- API keys: SHA-256 hashed at rest, revocation, gateway scope enforcement
- Agent pause/resume/kill
- Deterministic policy/approval gateway
- Hash-chained audit records
- Google and Slack OAuth sign-in
- Google and Slack OAuth integration connection with encrypted token storage
- Stripe subscription checkout and signed webhook verification
- SMTP helper for notifications
- Prometheus metrics endpoint
- SCIM user provisioning boundary
- Nginx reverse proxy template
- PostgreSQL backup script
- Responsive dashboard and interactive integration/billing/MFA controls

## Requires deployment-specific configuration
- OAuth client registration and HTTPS callback URLs
- Stripe product/price and webhook configuration
- SMTP credentials
- Fernet integration encryption key
- PostgreSQL/Redis/TLS/WAF/DNS
- SAML IdP metadata/certificates and customer-specific group mapping
- SCIM tenant token and organization mapping
- Independent penetration test/security review
- Legal review and jurisdiction-specific compliance work

These are not safe to fake or hard-code in a source ZIP. The application intentionally fails closed when required production security configuration is missing.
