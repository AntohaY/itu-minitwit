# Architecture

## Coverage

This document should cover the overall system design, especially Session 02 rewrite decisions, Session 05 persistence boundaries, Session 06 observability integration, and Session 09 scaling considerations.

It should explain:

- The main application components and how they interact.
- The request flow through the MiniTwit application.
- How handlers, services, repositories, and database access are separated.
- How Docker, Swarm, MongoDB, Prometheus, Grafana, Loki, and Promtail fit into the system.
- Which architectural trade-offs shaped the current implementation.

## Purpose

Use this page to describe how the system is organized. Keep deployment commands, operational runbooks, and low-level test details in their dedicated documents.

## System Overview

Describe the high-level architecture.

Suggested components:

- MiniTwit web application.
- Simulator API endpoints.
- MongoDB database.
- Docker containers and Swarm services.
- Monitoring stack.
- Logging stack.
- CI/CD pipeline.

## Request Flow

Explain how a typical request moves through the system.

Suggested flows:

- Browser user request.
- Simulator API request.
- Authentication-protected request.
- Database-backed read or write.

## Application Boundaries

Describe the internal code organization.

Suggested topics:

- HTTP handlers.
- Business logic or service layer, if present.
- Repository or persistence layer.
- Template/static file handling.
- Error handling and validation.

## Observability Integration

Describe how metrics and logs are attached to the architecture.

Link to:

- [Monitoring](monitoring.md)
- [Logging](logging.md)

## Scaling Considerations

Briefly describe how the architecture supports multiple replicas and rolling updates.

Link to:

- [Scaling and Availability](scaling-and-availability.md)
- [Deployment](deployment.md)

## README Material

- The architecture separates application behavior, persistence, deployment, and observability concerns.
- The system is containerized and designed to run as Swarm services with centralized monitoring and logging.

=====

## Project Facts

### What We Implemented

- The current application is a Go web service.
- The HTTP layer uses `net/http` and `github.com/gorilla/mux`.
- Browser UI routes and simulator API routes run in the same webserver process on port `8080`.
- MongoDB is the persistence layer.
- The main database collections are `user`, `message`, and `follower`.
- The app exposes Prometheus metrics at `/metrics`.
- The app exposes a health/readiness endpoint at `/ping`.
- Request IDs are created or propagated by `BeforeAfterMiddleware` and written to response headers as `X-Request-ID`.
- Prometheus metrics are collected by `MetricsMiddleware`, which records request counts and request duration by method, route path, and status.
- Logs are emitted as JSON through Go `slog`.
- The production deployment is containerized and defined in `remote_files/docker-stack.yml`.
- The production stack includes `webserver`, `prometheus`, `grafana`, `loki`, `promtail`, and `discordbot`.
- The remote stack uses Docker Swarm overlay networking.
- The web application is deployed with 3 replicas in the remote stack.
- A separate Discord bot image exists under `src/bot`. It connects to MongoDB and responds to `!users` by counting registered users.

### Internal Boundaries

- `src/main.go` wires configuration, MongoDB, sessions, middleware, routes, and server startup.
- `src/api/handlers.go` contains simulator API behavior.
- `src/handlers/` contains browser UI handlers for authentication, timelines, following, and messages.
- `src/app/app.go` contains shared application helpers, template rendering, query helpers, pagination helpers, and error tracking.
- `src/db_setup/ResolveClientDB.go` creates the MongoDB client and ensures indexes.
- The code has handler/helper separation, but it does not have a strong service/repository layering. Several handlers access MongoDB collections directly.

### Evidence in the Repository

- `src/main.go`
- `src/api/handlers.go`
- `src/handlers/`
- `src/middleware/`
- `src/db_setup/ResolveClientDB.go`
- `docker/web/Dockerfile`
- `docker-compose.yml`
- `remote_files/docker-stack.yml`
- `monitoring/prometheus/prometheus.yml`
- `monitoring/promtail/config.yml`
- `monitoring/grafana/`

### Known Gaps / Needs Team Evidence

- Need a current architecture diagram for the final report.
- Need team explanation for why handler-level database access was considered acceptable, or whether it is technical debt.
- The report should not claim a clean service/repository architecture unless the code is refactored further.
- Need production evidence that all declared stack components are currently running.

### Oral Exam Answer

The architecture is a containerized Go MiniTwit application with both UI and simulator API routes in one webserver. MongoDB stores users, messages, and follow relationships. Observability is built into the service through JSON logs, request IDs, `/metrics`, and `/ping`, while Prometheus, Grafana, Loki, and Promtail run as supporting services in the Swarm stack. The main tradeoff is that the code is pragmatic and handler-driven rather than strongly layered.
