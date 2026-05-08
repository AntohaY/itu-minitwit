# Documentation Index

## Coverage

This document should cover the documentation entry point and Session 00 prerequisites. It should help team members find the right topic quickly and understand the expected local development environment.

It should explain:

- Which tools are required to work on the project locally.
- How the documentation is organized.
- Which document covers each project area.
- Which document maps to each course session.
- Where to find operational, deployment, testing, monitoring, logging, and security notes.

## Purpose

Use this page as the starting point for project documentation. The `README.md` should remain the public project summary, while this directory contains the detailed engineering notes.

## Prerequisites

Document the tools required for local development.

Suggested items:

- Docker and Docker Compose.
- Python and test dependencies.
- Vagrant, if the infrastructure workflow is used locally.
- Access to GitHub Actions and repository secrets, if relevant.
- Access to production or staging infrastructure, if relevant.

## Documentation Map

- [Project History](project-history.md): project origin, modernization, and session-by-session evolution.
- [Architecture](architecture.md): system design and component relationships.
- [API](api.md): simulator API, Swagger compliance, and endpoint behavior.
- [Database](database.md): persistence model, MongoDB usage, and data access boundaries.
- [Frontend UI](frontend-ui.md): user-facing MiniTwit workflows and UI behavior.
- [Deployment](deployment.md): application deployment flow and release rollout.
- [Infrastructure](infrastructure.md): Vagrant, provisioning, Swarm bootstrap, and reproducibility.
- [CI/CD](ci-cd.md): GitHub Actions, quality gates, release automation, and deployment automation.
- [Testing](testing.md): local and CI test strategy.
- [Monitoring](monitoring.md): metrics, Prometheus, Grafana dashboards, and health visibility.
- [Logging](logging.md): Loki, Promtail, log queries, and debugging workflows.
- [Operations](operations.md): runbooks for daily maintenance and incident handling.
- [Security](security.md): threat scenarios, mitigations, hardening, and remaining risks.
- [Scaling and Availability](scaling-and-availability.md): replicas, rolling updates, health checks, and uptime expectations.

## Session Coverage

| Session | Main Topic | Primary Documentation |
|---|---|---|
| 00 | Prerequisites and development environment | `docs/index.md` |
| 01 | Baseline and modernization history | `docs/project-history.md` |
| 02 | Rewrite and containerization | `docs/project-history.md`, `docs/architecture.md`, `docs/deployment.md` |
| 03 | Simulator API | `docs/api.md` |
| 04 | CI/CD and deployment | `docs/ci-cd.md`, `docs/deployment.md` |
| 05 | Database abstraction | `docs/database.md`, `docs/architecture.md` |
| 06 | Monitoring | `docs/monitoring.md` |
| 07 | Tests and quality gates | `docs/testing.md`, `docs/ci-cd.md` |
| 08 | Logging and peer review | `docs/logging.md`, `docs/operations.md`, `docs/project-history.md` |
| 09 | Scaling and availability | `docs/scaling-and-availability.md`, `docs/deployment.md` |
| 10 | No material | Mark as N/A if no project work maps to this session |
| 11 | Security assessment and hardening | `docs/security.md` |
| 12 | Infrastructure as Code | `docs/infrastructure.md` |

## README Material

- The detailed project documentation lives in `docs/`.
- Each page starts with its intended coverage so team members can fill in details consistently.
- The final `README.md` should summarize the project and link to these deeper notes.

