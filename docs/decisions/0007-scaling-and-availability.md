# ADR 0007: Scaling and Availability

## Status

Proposed

## Coverage

This decision should cover Session 09 scaling and availability.

It should explain:

- Why Swarm replicas and rolling updates were used.
- Why this approach was chosen over blue/green or active/standby.
- What uptime expectations the design supports.
- Which single points of failure remain.

## Context

Describe the need for safer updates and better availability.

## Decision

Document the selected availability approach.

## Alternatives

- Single replica deployment.
- Blue/green deployment.
- Active/standby deployment.
- Kubernetes-based orchestration.

## Consequences

Describe positive and negative consequences.

=====

## Project Facts

- The remote webserver service runs with 3 replicas.
- Swarm rolling updates use `parallelism: 1`, `delay: 10s`, and `order: start-first`.
- The webserver has a healthcheck against `/ping`.
- The application stores persistent state in MongoDB and session state in signed cookies.
- The `/latest` simulator state is in memory per webserver process.

### Evidence

- `remote_files/docker-stack.yml`
- `src/handlers/timeline_handlers.go`
- `src/main.go`
- `src/api/handlers.go`
- PR #115 added Docker Swarm deployment and replicated service configuration: https://github.com/AntohaY/itu-minitwit/pull/115

### Needs Team Evidence

- Need production evidence that 3 replicas are actually running; PR #115 proves the design/config history, not the current live state.
- Need load/failover testing evidence if the report claims proven scaling.
- The team should discuss `/latest` as a replica-safety limitation.
- The team should document whether MongoDB is highly available in production.
