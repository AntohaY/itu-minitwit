# Placeholder: observability-flow.png

Target asset: `observability-flow.png`

Create an observability diagram showing the difference between metrics and logs in production.

Priority: Strongly useful.

## Generative AI Diagram Prompt

```text
Create a focused observability flow diagram for the MiniTwit production system.

Canvas and style:
- Landscape layout.
- Split the diagram into two horizontal lanes:
  1. Metrics pipeline
  2. Logs pipeline
- Use clear directional arrows.
- Use dashed arrows for collection/scraping/pushing.
- Use Grafana as the shared visualization endpoint on the right.
- Keep this diagram focused only on observability; do not include full CI/CD.

Title:
"MiniTwit Observability Flow"

Left side: Runtime sources
Draw these source boxes:
- "webserver replicas x3"
  Labels:
  - "Go MiniTwit app"
  - "UI + simulator API"
  - "exposes /metrics"
  - "writes structured JSON logs to stdout/stderr"
- "discordbot"
  Label:
  - "writes container logs"

Lane 1: Metrics pipeline
Draw:
"webserver replicas x3"
-> "Prometheus"
-> "Grafana"

Labels:
- Arrow webserver -> Prometheus: "scrape webserver:8080/metrics every 5s"
- Prometheus box labels:
  - "request count"
  - "request duration"
  - "status codes"
  - "Go runtime metrics"
  - "process metrics"
  - "volume: minitwit_prometheus_cloud_data"
- Arrow Prometheus -> Grafana: "metrics datasource"

Lane 2: Logs pipeline
Draw:
"webserver replicas + discordbot"
-> "Docker JSON logs on each node"
-> "Promtail global service"
-> "Loki"
-> "Grafana"

Labels:
- Docker logs: "/var/lib/docker/containers/*/*-json.log"
- Promtail: "runs on every Swarm node; reads Docker logs"
- Arrow Promtail -> Loki: "push to http://loki:3100/loki/api/v1/push"
- Loki: "log storage/query backend; volume: loki_data"
- Arrow Loki -> Grafana: "Loki datasource / log queries"

Right side: Grafana
Draw a larger shared box:
"Grafana: https://itu-minitwit.me/grafana"
Inside:
- "Metrics dashboards from Prometheus"
- "Log Explore from Loki"
- "Used for production debugging and report screenshots"
- "volume: minitwit_grafana_cloud_data"

Placement notes:
- Prometheus, Grafana, and Loki are manager-constrained services.
- Promtail is a global Swarm service.
- Production logging path is Promtail -> Loki directly.
- Do not show central rsyslog as active; if mentioned, label it "legacy/not active production path".

Add a small legend:
- Metrics = scraped from /metrics
- Logs = pushed from Docker logs through Promtail
- Grafana displays both metrics and logs
```
