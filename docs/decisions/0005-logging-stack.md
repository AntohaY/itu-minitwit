# ADR 0005: Logging Stack

## Status

Proposed

## Coverage

This decision should cover Session 08 logging work.

It should explain:

- Why Loki and Promtail were selected.
- How the logging stack integrates with Grafana.
- What alternatives were considered.
- What limitations the selected stack has.

## Context

Describe the need for centralized logs in production.

## Decision

Document the selected logging stack.

## Alternatives

- Docker logs only.
- EFK or ELK stack.
- Cloud-provider logging.

## Consequences

Describe positive and negative consequences.

=====

## Project Facts

- The application emits JSON logs using Go `slog`.
- The application attaches/generates request IDs.
- The remote production stack includes Loki and Promtail.
- Promtail is configured to read Docker JSON container logs and push them to Loki.
- Grafana has Loki provisioned as a data source.
- A separate rsyslog-based setup exists in the root `docker-stack.yml` and `query-logs.sh`.

### Evidence

- `src/main.go`
- `src/middleware/BeforeAfterMiddleware.go`
- `monitoring/promtail/config.yml`
- `monitoring/grafana/datasources/datasources.yml`
- `remote_files/docker-stack.yml`
- `docker-stack.yml`
- `query-logs.sh`
- PR #113 added the earlier rsyslog-to-Grafana/Loki logging path: https://github.com/AntohaY/itu-minitwit/pull/113

### Needs Team Evidence

- The team should clarify whether production uses direct Promtail-to-Loki or the rsyslog-based path. The current remote stack points to direct Promtail/Docker-log scraping, while PR #113 and helper scripts show older rsyslog work.
- The team should document retention expectations.
- The team should mention that richer labels and request-ID querying in Loki are not fully implemented yet.
