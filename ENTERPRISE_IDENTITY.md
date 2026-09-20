# Enterprise identity

## SSO / SAML
AgentGuard exposes the authentication boundary so a SAML/OIDC provider can be placed in front of the application. Provider-specific metadata, certificates, ACS URL, entity ID, and group-to-role mapping must be configured per customer. Do not ship shared certificates or IdP secrets in source control.

## SCIM
For enterprise provisioning, set `SCIM_BEARER_TOKEN` and use a tenant-specific deployment. A production implementation should map SCIM groups to AgentGuard roles and enforce deprovisioning immediately.

## OAuth
Google and Slack OAuth endpoints are included. Register exact HTTPS callback URLs with each provider and set client credentials through environment variables.
