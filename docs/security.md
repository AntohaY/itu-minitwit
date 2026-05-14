# Security

## Coverage

This document should cover Session 11 security assessment and hardening, with connections to Session 04 CI/CD, Session 07 quality gates, and Session 12 infrastructure.

It should explain:

- Which security risks were considered.
- Which mitigations were implemented.
- How secrets are handled.
- How TLS, firewall rules, non-root containers, and scanning are used.
- How Trivy and Semgrep fit into CI/CD.
- Which security risks remain open.

## Purpose

Use this page to present a single security story: threat scenarios, mitigations, and remaining risks. Avoid scattering the security assessment only across deployment and CI/CD notes.

## Threat Scenarios

Document relevant risks.

Suggested scenarios:

- Exposed administrative ports.
- Leaked credentials or committed secrets.
- Insecure transport.
- Vulnerable dependencies or container images.
- Excessive container privileges.
- API misuse or missing authentication.
- Logging sensitive data.

## Implemented Mitigations

Describe hardening measures.

Suggested topics:

- UFW or firewall configuration.
- TLS verification.
- Non-root container user, if implemented.
- GitHub Secrets.
- Semgrep.
- Trivy.
- Environment variable handling.

## CI Security Checks

Explain which checks run automatically.

Suggested topics:

- Static analysis severity thresholds.
- Container image scanning.
- Dependency scanning.
- Whether findings block deployment or are informational.

## Secrets Management

Document where secrets live and how they are protected.

Suggested locations:

- Local `.env` files.
- GitHub Secrets.
- Swarm environment variables or secrets.
- Production database credentials.

## Remaining Risks

Examples:

- No full threat model.
- Limited runtime security monitoring.
- Manual secret rotation.
- Incomplete dependency update policy.
- Limited rate limiting or abuse prevention.

## README Material

- The project includes security hardening through firewall rules, TLS checks, secret handling, and automated scanning.
- Remaining risks are documented separately from implemented mitigations.

=====

## Project Facts

### Implemented Mitigations

- The production Docker image is a multi-stage build.
- The runtime image is Alpine-based and runs as a non-root `appuser`.
- The Dockerfile installs CA certificates.
- Sessions are configured with `HttpOnly: true` and `Secure: true`.
- Deployment secrets are read from GitHub Secrets in the deployment workflow.
- Local/provisioning secrets are expected in `.env` or shell environment variables.
- Vagrant provisioning enables UFW and opens only selected ports for SSH, HTTP, Grafana, and Docker Swarm communication.
- TLS/Nginx bootstrap support exists through `remote_files/bootstrap_droplet_tls.sh`.
- The deployment workflow performs optional post-deploy TLS verification when `TLS_DOMAIN` is set.
- Semgrep runs in CI.
- Trivy scans the pushed web image in the deployment workflow.
- `logsanitize.Message` redacts common sensitive key/value patterns and MongoDB connection strings for custom error-tracker messages.
- PR #132 added the `itu-minitwit.me` Nginx/Certbot bootstrap and post-deploy TLS checks: https://github.com/AntohaY/itu-minitwit/pull/132.
- PR #135 added firewall configuration and kept TLS verification in the deployment flow: https://github.com/AntohaY/itu-minitwit/pull/135.
- PR #148 added Semgrep and Trivy as warning-mode security checks: https://github.com/AntohaY/itu-minitwit/pull/148.

### Evidence in the Repository

- `docker/web/Dockerfile`
- `src/main.go`
- `Vagrantfile`
- `remote_files/bootstrap_droplet_tls.sh`
- `.github/workflows/static-analysis.yml`
- `.github/workflows/continous-deployment.yml`
- `src/helpers/logsanitize/logsanitize.go`
- `remote_files/deploy.sh`

### Remaining Risks

- User passwords are stored and compared as plain strings. `CheckPasswordHash` has a TODO for proper hashing.
- Simulator Basic Auth credentials are hard-coded as `simulator` / `super_safe!`.
- Semgrep and Trivy are currently non-blocking because they use `continue-on-error: true`.
- Trivy image scan does not block deployment because deploy depends on `build`, not `scan-images`.
- There is no visible full threat model.
- There is no visible secret rotation policy.
- There is no visible rate limiting or abuse prevention for API/UI routes.
- Runtime security monitoring is limited.
- Grafana port `3000` is opened in the Vagrant firewall setup, although remote Nginx/Grafana sub-path support also exists.

### Known Gaps / Needs Team Evidence

- TLS setup is evidenced by PR #132 and PR #135, but current certificate validity should be confirmed with a recent browser, `curl -I`, or Actions TLS verification log.
- Semgrep/Trivy configuration is evidenced by PR #148; current findings should be taken from the latest Actions run if discussed in the report.
- Need confirmation of actual production firewall state.
- Need a clear statement about whether the plaintext password issue was accepted for course scope or should be fixed before final hand-in.

### Oral Exam Answer

Security hardening exists through non-root containers, GitHub Secrets, UFW rules, TLS bootstrap support, Semgrep, Trivy, and some log sanitization. However, several important risks remain: passwords are not hashed, simulator credentials are hard-coded, and security scans are advisory rather than blocking. The honest DevOps answer is that we added security feedback loops, but not all findings currently stop deployment.
