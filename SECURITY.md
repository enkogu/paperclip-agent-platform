# Security

Report suspected vulnerabilities privately. On GitHub, open the repository's
**Security** tab and use **Report a vulnerability** when that option is
available. Do not include credentials, production URLs, exploit payloads, or
customer data in a public issue.

Maintainers who need to start the private GitHub process can create a
[draft Security Advisory](../../security/advisories/new). If private reporting
is not enabled and no private contact is published, open a non-sensitive issue
titled `Request secure vulnerability reporting channel`. Include no
vulnerability details; wait for a private channel before sending the report.

See the [security policy](skills/system-platform/references/security-policy.md)
for the supported-version and reporting process.

Cloudflare publication is gated on verified Access reconciliation. Service
applications use per-route identities, and release acceptance proves anonymous
denial, intended-token success, and cross-route token denial for every declared
service application.

Host resource admission is read-only and consumes only the six canonical,
non-secret integer thresholds. Deployment checks run before host mutation.
Daytona sandbox images are built only in the pinned CI workflow, so the host
has no build-resource gate or build-context mutation. A live Daytona E2E
derives its sandbox-memory and image-pull reserves from those same six keys.
Failures identify the rejected check without echoing observed host values or
caller environment.
