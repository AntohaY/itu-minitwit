# Monitoring

## Coverage

This document should cover Session 06 monitoring work.

It should explain:

- Which metrics are collected.
- How Prometheus scrapes metrics.
- How Grafana dashboards visualize system health.
- Which dashboards are defined as code, if applicable.
- Which metrics matter most for production operation.
- What monitoring gaps remain.

## Purpose

Use this page to document metrics-based visibility into the running system. Keep event-level debugging details in [Logging](logging.md).

## Monitoring Stack

Describe the monitoring components.

Suggested components:

- Application metrics endpoint.
- Prometheus.
- Grafana.
- Dashboard provisioning files.
- Node or container metrics, if collected.

## Metrics Pipeline

Explain how metrics move through the system.

Example flow:

```text
MiniTwit metrics endpoint
  -> Prometheus scrape
  -> Grafana dashboards
```

## Dashboards

Document the available dashboards.

Suggested topics:

- Application health.
- Request rate.
- Error rate.
- Latency.
- Container or host resource usage.

## Operational Use

Explain how monitoring supports operations.

Suggested workflows:

- Checking if the service is up.
- Identifying error spikes.
- Comparing behavior before and after deployment.
- Investigating resource pressure.

## Known Gaps

Examples:

- No alerting rules.
- Limited SLO definitions.
- Missing business-level metrics.
- Dashboard coverage is incomplete.

## README Material

- The project uses Prometheus and Grafana for metrics-based monitoring.
- Monitoring helps verify service health and understand production behavior.

=====

## Project Facts

### What We Implemented

- The Go application exposes Prometheus metrics at `/metrics`.
- Metrics are registered in `src/main.go`.
- Custom HTTP metrics are defined in `src/middleware/metrics.go`.
- The custom metrics are `minitwit_http_responses_total` and `minitwit_http_request_duration_seconds`.
- Metrics are labeled by HTTP method, route path, and status code.
- The Prometheus registry also includes Go runtime metrics and process metrics.
- Prometheus is configured to scrape Prometheus itself at `prometheus:9090` and the MiniTwit webserver at `webserver:8080`.
- Prometheus scrape interval for these jobs is 5 seconds.
- Grafana is provisioned with Prometheus as the default data source.
- Grafana dashboards are stored as JSON files under `monitoring/grafana/dashboards/`.
- Dashboard panels include request rate, error rate, latency percentiles, Go runtime goroutines, memory usage, and response-time related views.
- PR #61 added Prometheus/Grafana monitoring, HTTP request metrics, and dashboards: https://github.com/AntohaY/itu-minitwit/pull/61.
- PR #74 continued Grafana dashboard work: https://github.com/AntohaY/itu-minitwit/pull/74.

### Evidence in the Repository

- `src/main.go`
- `src/middleware/metrics.go`
- `monitoring/prometheus/prometheus.yml`
- `remote_files/prometheus.yml`
- `monitoring/grafana/datasources/datasources.yml`
- `monitoring/grafana/dashboards/`
- `remote_files/docker-stack.yml`

### Known Gaps / Needs Team Evidence

- No Prometheus alert rules are visible in the repository.
- No formal SLOs are visible in the repository.
- Need current Grafana dashboard URL and screenshots for the final report.
- Need production evidence that Prometheus is successfully scraping all web replicas.
- Business-level metrics, such as registrations or messages created, are not visible as custom Prometheus metrics.

### Oral Exam Answer

Monitoring is based on Prometheus and Grafana. The app exposes `/metrics` with request counts, request durations, Go runtime metrics, and process metrics. Prometheus scrapes the webserver and Grafana visualizes request rate, errors, latency, memory, and runtime behavior. The main gap is that alerting and formal SLOs are not implemented.
