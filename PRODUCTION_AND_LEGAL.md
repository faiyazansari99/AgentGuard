# Production / Legal / Google Play readiness

This document is a launch checklist, not legal advice and not a guarantee of store approval.

## Security
- Managed PostgreSQL + encrypted backups
- Redis/queue if needed
- Secret manager, key rotation, least privilege
- TLS, WAF, rate limits, CSRF/CORS review
- MFA, SSO/SAML/SCIM for enterprise
- Penetration test and dependency scanning
- Centralized logs, metrics, alerts, incident response
- Disaster recovery and restore testing

## Privacy / legal
Prepare and have counsel review: Terms of Service, Privacy Policy, DPA, subprocessors list, security page, acceptable-use policy, data retention/deletion, export process, incident/breach process, cookies/consent where applicable, regional privacy obligations, IP/licensing, refund/billing terms.

## AI governance
Document human oversight, model/provider disclosures, risk controls, prompt-injection defenses, data boundaries, auditability, customer responsibilities, and limitations. Never claim that AI analysis alone is a security guarantee.

## Payments
AgentGuard should not custody customer funds by default. Use customer-owned payment providers with scoped credentials and deterministic thresholds/approvals.

## Google Play / Android
If an Android wrapper is later published, complete the current Play Console requirements applicable to the app: target API level, Data safety, privacy policy, account deletion where accounts exist, permissions, content declarations, billing rules if applicable, developer verification, testing tracks, and store listing disclosures. Requirements change; verify them in Play Console immediately before submission.
