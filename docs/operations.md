# Operations

## Coverage

This document should cover operational runbooks connected to Session 04 deployment, Session 06 monitoring, Session 08 logging, Session 09 availability, Session 11 security, and Session 12 infrastructure.

It should explain:

- How to inspect the running system.
- How to check service health.
- How to inspect logs and metrics during incidents.
- How to restart, update, or rollback services.
- How to debug common deployment, database, API, and infrastructure failures.
- Which actions are safe and which require extra care.

## Purpose

Use this page as a practical runbook. It should contain operational commands and troubleshooting flows rather than design rationale.

## Service Status

Document commands for checking the running deployment.

Suggested topics:

- Docker Swarm service status.
- Stack status.
- Replica status.
- Health endpoint checks.

## Logs and Metrics

Link to the deeper observability documents.

- [Monitoring](monitoring.md)
- [Logging](logging.md)

Include the most common operational commands or dashboards here.

## Deployment Recovery

Document what to do when deployment fails.

Suggested topics:

- Check workflow logs.
- Check service update status.
- Inspect container logs.
- Roll back to a previous version.
- Verify health after rollback.

## Database Troubleshooting

Document common database-related failure checks.

Suggested topics:

- Connection string configuration.
- Network access.
- Authentication failures.
- Database availability.

## Incident Checklist

Suggested checklist:

- Confirm whether the service is reachable.
- Check recent deployments.
- Check Grafana metrics.
- Check Loki logs.
- Check Swarm service state.
- Roll back if the new release is the likely cause.
- Record follow-up work.

## README Material

- The project includes operational runbooks for inspecting, debugging, and recovering the deployed system.

=====

## Project Facts

### Operational Entry Points

- The health endpoint is `GET /ping`, implemented in `src/handlers/timeline_handlers.go`.
- The metrics endpoint is `GET /metrics`, registered in `src/main.go`.
- Deployment is performed by `/minitwit/deploy.sh` on the manager node.
- Production stack deployment uses `docker stack deploy -c docker-stack.yml minitwit`.
- Local development and CI use Docker Compose.
- `query-logs.sh` provides helper commands for listing, tailing, searching, and counting logs in an rsyslog-based setup.

### Useful Commands From the Repo

- Local stack: `docker compose up --build`
- Local verification: `make verify`
- UI E2E: `make ui-e2e`
- Swarm setup: `./setup-swarm.sh`
- Remote deploy command used by CI: `cd /minitwit && ./deploy.sh`
- API smoke test: `./test-api-routes.sh --base-url <url>`

### Evidence in the Repository

- `README.md`
- `Makefile`
- `setup-swarm.sh`
- `remote_files/deploy.sh`
- `query-logs.sh`
- `src/handlers/timeline_handlers.go`
- `src/main.go`
- `remote_files/docker-stack.yml`

### Known Gaps / Needs Team Evidence

- The operational runbook still needs concrete production commands such as `docker service ls`, `docker service ps`, `docker service logs`, and rollback commands used by the team.
- No incident records are visible in the repository. The team should add examples from real production issues if they want to reflect on operations.
- `query-logs.sh` may not match the current production logging stack if production uses Promtail/Loki directly instead of `central-rsyslog`.
- Need current dashboard URLs and production SSH/server access details, without committing secrets.

### Oral Exam Answer

Operationally, the team can inspect the system through `/ping`, `/metrics`, Grafana dashboards, logs, GitHub Actions, and Swarm service state. Deployment is automated but recovery still depends on manual inspection and rollback decisions. For the exam, we should be ready to walk through how we would diagnose a failed deployment or production error step by step.
