# AgentGuard smoke test

1. Copy `.env.example` to `.env` and set secrets.
2. Start the stack: `docker compose up --build`.
3. Migration runs automatically via `entrypoint.sh`.
4. Open `http://localhost:8000`.
5. Register with a 12+ character password.
6. Create an agent and a BLOCK / APPROVAL_REQUIRED policy.
7. Create an API key with `gateway:check` scope.
8. Call `/api/gateway/check` using `X-API-Key` and confirm deterministic decisions.
9. Pause/kill the agent and confirm gateway returns BLOCK.
10. Enable MFA in the API and verify the two-step login flow.
11. Configure Google/Slack OAuth only after registering exact callback URLs with the provider.
12. Configure Stripe webhook signing and verify checkout/webhook events.
13. Configure SMTP and verify notification delivery in a non-production test mailbox.
14. Verify `/health` and `/metrics` from your monitoring system.
15. Test database backup + restore before accepting production customer data.
