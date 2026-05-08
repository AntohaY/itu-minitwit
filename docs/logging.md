# Logging

## Coverage

This document should cover the logging work related to Session 08. Although the monitoring documentation may mention Loki and Promtail, this page should treat logging as a first-class operational topic.

It should explain:

- Which logs are collected from the MiniTwit system.
- How application and container logs are shipped to Loki.
- How Promtail is configured and what labels are attached to logs.
- How logs can be queried in Grafana or through helper scripts.
- Common debugging workflows based on logs.
- Log retention assumptions or limitations.
- Known gaps and future improvements for logging.

## Purpose

Logging helps the team investigate runtime behavior, deployment issues, simulator traffic, application errors, and production incidents. The goal is to provide enough context for a team member to answer: "What happened, when did it happen, and which service produced the relevant evidence?"

## Logging Stack

Describe the components used for centralized logging.

- **Log source:** Docker container logs and application output.
- **Collector:** Promtail.
- **Storage and query backend:** Loki.
- **Visualization and exploration:** Grafana.
- **Optional helper tooling:** `query-logs.sh`, if used by the project.

## Log Sources

Document which parts of the system produce logs.

Suggested areas to describe:

- MiniTwit application logs.
- Docker service logs.
- Reverse proxy or TLS-related logs, if applicable.
- Database-related connection or error logs, if available.
- Simulator/API request logs, if the application records them.
- Deployment or startup logs relevant for operations.

## Log Collection Flow

Explain the path from log creation to log querying.

Example flow:

```text
MiniTwit container stdout/stderr
  -> Docker logging layer
  -> Promtail
  -> Loki
  -> Grafana Explore / dashboard queries
```

Add details about where Promtail runs, how it discovers logs, and how it authenticates or connects to Loki if relevant.

## Labels and Structure

Describe the labels used to make logs searchable.

Useful labels may include:

- `container`
- `service`
- `stack`
- `host`
- `environment`
- `level`

Explain which labels are currently implemented and which labels would be useful but are not yet available.

## Querying Logs

Document how to inspect logs during development and production troubleshooting.

Include examples such as:

```logql
{service="minitwit"}
```

```logql
{service="minitwit"} |= "error"
```

```logql
{service="minitwit"} |~ "login|register|timeline"
```

If `query-logs.sh` is used, describe what it does and provide typical commands.

## Common Debugging Workflows

Document practical workflows the team should follow.

Suggested workflows:

- Investigating a failed deployment.
- Checking whether the application started correctly.
- Finding simulator/API errors.
- Debugging failed login, registration, follow, or message posting flows.
- Correlating errors with deployment time.
- Checking whether one replica behaves differently from others.

## Retention and Limitations

Describe how long logs are kept and what limitations exist.

Examples:

- Logs may only be retained for a limited period.
- Logs may depend on container stdout/stderr.
- Full-text search may be more limited than an Elasticsearch-based stack.
- Logs should not contain secrets, tokens, passwords, or connection strings.

## Security and Privacy Considerations

State what must not be logged.

Examples:

- Passwords.
- Authentication tokens.
- Database credentials.
- GitHub secrets.
- Full connection strings.
- Personal data beyond what is required for debugging.

## Known Gaps

List current weaknesses or missing pieces.

Examples:

- Log levels are not fully structured.
- Request IDs are not propagated across components.
- Retention policy is not clearly defined.
- Alerting based on log patterns is not implemented.
- Logs are not yet linked directly from operational runbooks.

## README Material

- The project uses centralized logging with Promtail, Loki, and Grafana.
- Logs help diagnose deployment, runtime, and simulator/API issues.
- Team members can query logs through Grafana or project helper scripts.
- Logging complements metrics-based monitoring by providing event-level debugging context.
