# Scaling and Availability

## Coverage

This document should cover Session 09 scaling and availability work and connect it to deployment and infrastructure decisions.

It should explain:

- How Docker Swarm replicas are used.
- How rolling updates behave.
- How health checks support safer deployments.
- What downtime expectations exist.
- What failure modes are considered.
- What availability or SLO-style expectations the team has.

## Purpose

Use this page to explain how the system stays available during normal operation and deployment. Keep the mechanics of deploying a release in [Deployment](deployment.md).

## Scaling Model

Describe how the application scales.

Suggested topics:

- Number of replicas.
- Stateless application assumptions.
- Shared database dependency.
- Load balancing through Swarm.

## Rolling Updates

Explain update behavior.

Suggested topics:

- Update order.
- Parallelism.
- Delay between updates.
- Failure handling.
- Rollback behavior.

## Health Checks

Document health check behavior.

Suggested topics:

- Health endpoint.
- Docker or Swarm health check configuration.
- What health checks validate.
- What health checks do not validate.

## Availability Expectations

Describe realistic uptime expectations.

Suggested topics:

- Expected behavior during normal deployment.
- Expected behavior during node failure.
- Database as a dependency.
- Single points of failure.
- Manual recovery assumptions.

## Known Gaps

Examples:

- No formal SLO.
- Limited load testing.
- Database may be a bottleneck or single point of failure.
- Limited automated failover testing.

## README Material

- The project uses Swarm replicas, health checks, and rolling updates to improve availability.
- Current availability expectations and remaining risks are documented explicitly.

=====

## Project Facts

### Scaling Model

- The remote production stack runs the `webserver` service with `replicas: 3`.
- The local Compose setup runs one webserver replica.
- Docker Swarm provides service discovery and load balancing across replicas.
- The web application is mostly stateless from the container perspective because persistent state is in MongoDB.
- Sessions are stored in signed cookies through Gorilla sessions, not in local server memory.
- The `/latest` simulator state is in memory inside each process, so it is not replica-safe.
- PR #115 added Docker Swarm deployment and the replicated production stack design: https://github.com/AntohaY/itu-minitwit/pull/115.

### Rolling Updates

- The remote webserver update configuration uses:
  - `parallelism: 1`
  - `delay: 10s`
  - `order: start-first`
- This means Swarm should start a new task before stopping the old task during updates.
- The deploy script uses `docker stack deploy`, which triggers Swarm to update services when the image or stack definition changes.

### Health Checks

- The remote webserver healthcheck calls `http://localhost:8080/ping`.
- The local MongoDB service has a healthcheck using `mongosh` and `db.adminCommand('ping')`.
- The `/ping` endpoint returns HTTP 200 with `OK`.

### Evidence in the Repository

- `remote_files/docker-stack.yml`
- `docker-compose.yml`
- `src/main.go`
- `src/handlers/timeline_handlers.go`
- `src/api/handlers.go`
- `remote_files/deploy.sh`

### Known Gaps / Needs Team Evidence

- There is no formal SLO or uptime target in the repository.
- There is no visible load test or failover test.
- MongoDB is an external dependency and may be a single point of failure depending on the production database configuration.
- Prometheus, Grafana, and Loki are pinned to the manager node in the remote stack, so observability services may be manager-dependent.
- `/latest` is not shared across replicas and may behave inconsistently under Swarm load balancing.
- The Swarm/replica design is evidenced by PR #115 and `remote_files/docker-stack.yml`, but current production replica status still needs `docker service ls`, `docker service ps`, or dashboard evidence.
- Need production uptime or incident evidence if the report claims specific availability results.

### Oral Exam Answer

Availability is improved by running three web replicas in Docker Swarm, using start-first rolling updates, and checking health through `/ping`. The app is mostly stateless because MongoDB stores persistent data and sessions are cookie-based. The main scaling limitation is that `/latest` is in memory per replica, and the system does not yet have formal SLOs, load testing, or proven automated failover.
