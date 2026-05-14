# Placeholder: swarm-runtime-topology.png

Target asset: `swarm-runtime-topology.png`

Create a runtime topology diagram showing:

- Swarm manager node.
- Worker nodes.
- 3 web replicas.
- Manager-pinned Prometheus/Grafana/Loki services.
- Global Promtail placement if applicable.
- External managed MongoDB.
- Public ingress through Nginx/TLS.

## Generative AI Diagram Prompt

```text
Create a detailed Docker Swarm runtime topology diagram for the MiniTwit production system.

Canvas and style:
- Landscape layout.
- Technical diagram style, not decorative.
- Use a large outer container titled "DigitalOcean Production Environment".
- Inside it, draw a large nested container titled "Docker Swarm overlay network: minitwit-network".
- Use three vertical node columns to make placement clear.
- Use solid arrows for runtime traffic.
- Use dashed arrows for monitoring/logging.
- Use small labels for replicas and placement constraints.

Node columns:
1. "Manager node: minitwit"
2. "Worker node: minitwit-web-1"
3. "Worker node: minitwit-web-2"

At the top, draw:
"Public internet"
-> "Domain: itu-minitwit.me"
-> "Nginx + Let's Encrypt TLS"
-> "Swarm webserver service on port 8080"

Inside the Swarm:
Draw the "webserver service" as 3 replica boxes spread across the manager and two workers:
- "web replica 1"
- "web replica 2"
- "web replica 3"
Labels for the service:
- "Image: webminitwitimage:latest"
- "Replicas: 3"
- "Healthcheck: /ping"
- "Rolling update: start-first"
- "parallelism: 1, delay: 10s"

Add a warning note beside the web replicas:
"/latest is in-memory per replica; not shared centrally"

On the manager node, draw these manager-constrained services:
- "prometheus"
  Labels: "scrapes webserver:8080/metrics", "volume: minitwit_prometheus_cloud_data"
- "grafana"
  Labels: "served at /grafana", "datasources: Prometheus + Loki", "volume: minitwit_grafana_cloud_data"
- "loki"
  Labels: "log storage", "volume: loki_data"
- "discordbot"
  Labels: "1 replica", "uses MONGO_URI + DISCORD_TOKEN"

On every node, draw a small "promtail" box:
- "promtail (global)"
- "reads /var/lib/docker/containers"
- "pushes logs to Loki"

Outside the Swarm but still connected, draw:
"DigitalOcean Managed MongoDB"
Labels:
- "MONGO_URI"
- "users"
- "messages"
- "followers"

Arrows:
- Nginx/TLS -> webserver service, label "HTTPS app/API traffic"
- web replicas -> MongoDB, label "read/write app data"
- discordbot -> MongoDB, label "bot data access"
- Prometheus -> web replicas, dashed, label "scrape /metrics"
- each Promtail -> Loki, dashed, label "push container logs"
- Grafana -> Prometheus, dashed, label "metrics"
- Grafana -> Loki, dashed, label "logs"

Add a small legend:
- Manager-constrained service = runs on minitwit
- Global service = runs on every node
- External managed service = outside Swarm
```

Priority: Strongly useful.
