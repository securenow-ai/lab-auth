# Security policy

Northstar Workspace is a fictional authentication teaching application. Use invented identities and data. Its public instance is operated by SecureNow; cloning this repository does not grant permission to test another deployment.

## Reporting a vulnerability

Use the repository's **Security > Report a vulnerability** flow when available. If private reporting is unavailable, contact SecureNow through [securenow.ai](https://securenow.ai) and request a private reporting channel. Avoid putting credentials, exploit details, personal data, or production access information into a public issue.

Include the affected revision, a minimal reproduction against your own local deployment, expected and observed behavior, and relevant sanitized logs. The current main branch is the maintained version. There is no published response-time commitment.

## Deployment responsibilities

- Generate separate session, audit-pseudonymization, database, and bootstrap-admin secrets for each environment.
- Keep OAuth client secrets, runtime credentials, database backups, and deployment state outside Git and container images. Review staged files before publishing.
- Keep Node, PostgreSQL, Docker images, dependencies, and host packages updated. Review audit results rather than automatically accepting breaking upgrades.
- Apply HTTPS, restrict the origin and trusted proxy boundary, keep PostgreSQL private, and use least-privilege cloud access.
- Treat email verification, password recovery, MFA, persistent account lockouts, and challenge providers as explicit follow-on engineering decisions. Read the [authentication threat model](docs/threat-model-authentication.md) for the implementation's boundaries.

## Teaching exercises

The checked-in baseline uses normal authentication protections. There is no public switch that intentionally disables them. Run destructive or higher-volume experiments only on an isolated deployment that you control. Detection and firewall controls add visibility and response; they do not repair vulnerable password handling, authorization, or OAuth validation.

