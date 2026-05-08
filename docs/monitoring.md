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

