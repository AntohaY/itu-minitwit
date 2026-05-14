# Project History

## Coverage

This document should cover Session 01 and provide a concise history of how the project evolved from the original MiniTwit baseline to the current implementation.

It should explain:

- What the inherited baseline looked like.
- Why the project was modernized.
- Why the team rewrote or restructured parts of the application.
- How version control, releases, deployment, monitoring, logging, security, and scaling were introduced over time.
- What peer review revealed and how it influenced later changes.

## Purpose

Use this page to tell the engineering story of the project. It should help a new team member understand where the system started, what changed, and why the current design exists.

## Baseline

Describe the starting point of the project.

Suggested topics:

- Original MiniTwit functionality.
- Original language, framework, or architecture.
- Initial deployment or runtime limitations.
- Missing automation, tests, monitoring, logging, or security controls.

## Modernization Timeline

Summarize the major project milestones.

Suggested timeline:

- Session 01: project takeover and baseline assessment.
- Session 02: rewrite and containerization.
- Session 03: simulator API implementation.
- Session 04: deployment and CI/CD.
- Session 05: database abstraction.
- Session 06: monitoring.
- Session 07: testing and static analysis.
- Session 08: logging and peer review.
- Session 09: scaling and availability.
- Session 10: N/A, if no relevant material exists.
- Session 11: security assessment and hardening.
- Session 12: infrastructure provisioning.

## Peer Review Notes

Record peer review findings if they do not justify a separate document.

Suggested topics:

- Issues found by reviewers.
- Changes made after review.
- Lessons learned.
- Risks that remained open.

## README Material

- The project evolved from a baseline MiniTwit implementation into a containerized, deployed, observable, tested, and security-assessed system.
- The project history explains why the current architecture and operational setup exist.

=====

## Project Facts

### Evidence-Backed Timeline

- The current codebase is a Go implementation of MiniTwit.
- The application has been containerized with Docker.
- The project includes Docker Compose for local/CI use and Docker Swarm stack files for production-style deployment.
- Simulator API support is implemented in `src/api/handlers.go`.
- CI/CD is implemented with GitHub Actions.
- Monitoring was added with Prometheus and Grafana.
- Logging was added with JSON `slog`, request IDs, Promtail, Loki, and Grafana.
- UI/E2E testing was added with Selenium/Pytest.
- Infrastructure provisioning was added with Vagrant and DigitalOcean scripts.
- TLS/Nginx bootstrap support was added through `remote_files/bootstrap_droplet_tls.sh`.
- Security scanning was added through Semgrep and Trivy.
- Scaling and rolling-update behavior is represented in the remote Swarm stack with 3 web replicas and `start-first` updates.

### Git History Pointers

- Recent history includes changes for documentation skeletons, security checks, one-line startup/setup, API smoke tests, UI/E2E tests, TLS verification, logging, and Docker Swarm deployment.
- Public Git tags visible from the repository include versions from `0.1.0` through `7.2.0`, plus early `v1.0.0` / `v1.01` tags. The release page is https://github.com/AntohaY/itu-minitwit/releases.
- Useful public PR links for the report timeline:
  - API implementation: https://github.com/AntohaY/itu-minitwit/pull/27
  - Release automation: https://github.com/AntohaY/itu-minitwit/pull/50
  - Monitoring: https://github.com/AntohaY/itu-minitwit/pull/61
  - Remote database: https://github.com/AntohaY/itu-minitwit/pull/78
  - Logging to Grafana/Loki: https://github.com/AntohaY/itu-minitwit/pull/113
  - Docker Swarm: https://github.com/AntohaY/itu-minitwit/pull/115
  - UI/E2E tests: https://github.com/AntohaY/itu-minitwit/pull/131
  - TLS/domain: https://github.com/AntohaY/itu-minitwit/pull/132
  - API smoke tests: https://github.com/AntohaY/itu-minitwit/pull/139
  - Setup automation: https://github.com/AntohaY/itu-minitwit/pull/147
  - Security scans: https://github.com/AntohaY/itu-minitwit/pull/148

### Evidence in the Repository

- `git log --oneline --decorate`
- `src/`
- `docker-compose.yml`
- `remote_files/docker-stack.yml`
- `.github/workflows/`
- `monitoring/`
- `Vagrantfile`
- `setup-swarm.sh`
- `test_itu_minitwit_ui.py`
- `test-api-routes.sh`

### Known Gaps / Needs Team Evidence

- The repository alone does not fully explain the inherited baseline, original architecture, or why each modernization decision was made.
- Peer review findings are not documented here yet.
- Important pull request links have been added above; the team should still choose which ones matter most for the final narrative and add issue/decision links where useful.
- If the final report says "we rewrote the system," it should state what it was rewritten from and why.

### Oral Exam Answer

The project evolved from a baseline MiniTwit assignment into a Go, MongoDB, Dockerized system with CI/CD, monitoring, logging, security scanning, Swarm deployment, and infrastructure provisioning. For the exam, the team should explain not only the final state, but the sequence of changes and why each one improved development, operations, or maintainability.
