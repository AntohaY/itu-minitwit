# Placeholder: architecture-overview.png

Target asset: `architecture-overview.png`

Create a system architecture diagram using the description below.

## Diagram Goal

The diagram should explain how the public MiniTwit service is built, deployed, observed, and operated. It should show both the runtime path for users/simulator traffic and the delivery path from GitHub Actions to Docker Swarm.

## Suggested Layout

Use a left-to-right or top-to-bottom structure with these visual zones:

1. External clients.
2. Public entry point and TLS.
3. DigitalOcean Docker Swarm runtime.
4. External managed database.
5. Observability stack.
6. CI/CD and image registry.

Keep the diagram readable: do not draw every endpoint. Group related endpoints as UI/API routes inside the Go MiniTwit service.

## External Clients

Show two external client types:

- **Browser users**
  - Access the web UI at `https://itu-minitwit.me`.
  - Use pages for registration, login, timelines, posting messages, and follow/unfollow.

- **MiniTwit simulator**
  - Calls simulator API endpoints on the same public application domain.
  - Uses routes such as `/register`, `/msgs`, `/msgs/{username}`, `/fllws/{username}`, and `/latest`.
  - Sends `?latest=<command-id>` query values to API routes.

Draw both client arrows toward the public domain/TLS entry point.

## Public Entry Point

Show:

- **Domain:** `itu-minitwit.me`
- **Nginx + Let's Encrypt TLS**
  - Handles HTTPS.
  - Redirects HTTP to HTTPS.
  - Proxies normal application traffic to the MiniTwit webserver service on port `8080`.
  - Serves Grafana under `https://itu-minitwit.me/grafana`.

Suggested labels:

- `HTTPS 443`
- `HTTP -> HTTPS redirect`
- `Nginx reverse proxy`
- `App upstream: webserver:8080 / localhost:8080`
- `Grafana sub-path: /grafana`

## Docker Swarm Runtime

Show the production environment as **DigitalOcean Docker Swarm** with three nodes:

- **Manager node:** `minitwit`
- **Worker node:** `minitwit-web-1`
- **Worker node:** `minitwit-web-2`

Show a Swarm overlay network named:

- `minitwit-network`

Inside the Swarm, show these services.

### MiniTwit Webserver Service

Show:

- **Service:** `webserver`
- **Image:** `${DOCKER_USERNAME}/webminitwitimage:latest`
- **Replicas:** `3`
- **Port:** `8080:8080`
- **Healthcheck:** `GET /ping`
- **Update strategy:** start-first rolling update, `parallelism: 1`, `delay: 10s`

Represent the three web replicas across the Swarm nodes. The exact placement may change at runtime, so label them as Swarm-scheduled replicas rather than fixed containers.

Inside the webserver box, show:

- **Go MiniTwit application**
- **UI routes**
  - `/`
  - `/login`
  - `/register_user`
  - `/timeline`
  - `/user/{username}`
  - `/add_message`
  - `/ping`
- **Simulator API routes**
  - `/latest`
  - `/register`
  - `/msgs`
  - `/msgs/{username}`
  - `/fllws/{username}`
- **Metrics endpoint**
  - `/metrics`

Important note for the diagram:

- `/latest` is currently in memory inside each webserver process. Mark this as a known limitation near the webserver replicas because multiple replicas can hold different latest values.

### Discord Bot Service

Show:

- **Service:** `discordbot`
- **Image:** `${DOCKER_USERNAME}/discordbotimage:latest`
- **Replicas:** `1`
- **Placement:** manager node
- **Uses:** `MONGO_URI` and `DISCORD_TOKEN`

Draw an arrow from `discordbot` to MongoDB. If the report does not discuss the bot in detail, keep this box smaller than the main webserver.

## Database

Show an external database outside the Swarm box:

- **DigitalOcean managed MongoDB**
- **Connection:** `MONGO_URI`
- **Used by:** webserver replicas and Discord bot
- **Data:** users, messages, follower relationships

Draw arrows:

- `webserver replicas -> MongoDB`
- `discordbot -> MongoDB`

Label the database arrow as:

- `MongoDB connection string from GitHub Secrets / .env`

Do not include credentials in the diagram.

## Observability Stack

Show observability inside the Swarm, mostly on the manager node where the stack constrains persistent observability services.

### Prometheus

Show:

- **Service:** `prometheus`
- **Placement:** manager node
- **Scrapes:** `webserver:8080/metrics`
- **Scrape interval:** 5 seconds for the app job
- **Storage volume:** `minitwit_prometheus_cloud_data`

Draw arrow:

- `Prometheus -> webserver replicas /metrics`

Label:

- `HTTP metrics: request count, latency, status codes`
- `Go runtime/process metrics`

### Grafana

Show:

- **Service:** `grafana`
- **Placement:** manager node
- **Public URL:** `https://itu-minitwit.me/grafana`
- **Data sources:** Prometheus and Loki
- **Storage volume:** `minitwit_grafana_cloud_data`

Draw arrows:

- `Grafana -> Prometheus`
- `Grafana -> Loki`
- `Browser users/team -> Grafana via /grafana`

### Loki

Show:

- **Service:** `loki`
- **Placement:** manager node
- **Purpose:** log storage and query backend
- **Storage volume:** `loki_data`

### Promtail

Show:

- **Service:** `promtail`
- **Mode:** global
- **Runs on:** every Swarm node
- **Reads:** Docker JSON logs from `/var/lib/docker/containers`
- **Pushes to:** `http://loki:3100/loki/api/v1/push`

Draw arrows:

- `webserver/discordbot/container logs -> Docker JSON logs`
- `Promtail on each node -> Loki`
- `Grafana -> Loki`

Important note:

- Production logging path is Promtail/Loki directly. Do not draw central rsyslog as an active production component. If you mention rsyslog, mark it as legacy/previous work outside the main runtime path.

## CI/CD and Deployment Flow

Show GitHub and Docker Hub outside the Swarm runtime box.

### GitHub Repository

Show:

- **GitHub repository:** `AntohaY/itu-minitwit`
- **Workflows:**
  - Continuous Integration
  - Automated Release
  - Continuous Deployment

### Continuous Integration

Show CI flow:

```text
Pull request / push
  -> GitHub Actions CI
  -> make verify
  -> simulator test
  -> Go formatting/linting
  -> Dockerfile linting
  -> go test
  -> UI/E2E tests
```

Represent this as a validation path before deployment.

### Release Automation

Show:

```text
Merged PR to main
  -> Automated Release
  -> GitHub release/tag
```

### Deployment

Show:

```text
Push to main / workflow_dispatch
  -> Build web image
  -> Build Discord bot image
  -> Push images to Docker Hub
  -> SSH to Swarm manager
  -> Copy stack/config files
  -> /minitwit/deploy.sh
  -> docker stack deploy -c docker-stack.yml minitwit
```

Draw arrows:

- `GitHub Actions -> Docker Hub`
- `GitHub Actions -> Swarm manager over SSH`
- `Swarm manager -> Docker Hub pull images`
- `Swarm manager -> updates Swarm services`

Show Trivy/Semgrep as advisory security feedback:

- **Semgrep:** runs in CI as non-blocking security feedback.
- **Trivy:** scans Docker image after build as non-blocking security feedback.

Do not draw Semgrep/Trivy as deployment blockers unless the workflow changes.

## Secrets and Configuration

Represent secrets as a small configuration box, not as individual secret values.

Show:

- **GitHub Secrets**
  - Docker Hub credentials.
  - SSH key/user/host.
  - Grafana credentials.
  - DigitalOcean MongoDB credentials.
  - Discord token.
  - TLS domain.

Draw arrows:

- `GitHub Secrets -> GitHub Actions deployment`
- `Deployment workflow -> .env copied to manager`
- `Swarm services consume environment variables`

Do not write actual secret values in the diagram.

## Volumes and Persistent State

Optional but useful labels:

- `prometheus_cloud_data` for Prometheus metrics data.
- `grafana_cloud_data` for Grafana dashboards/settings.
- `loki_data` for logs.
- MongoDB persistence is managed by DigitalOcean outside the Swarm.

## Key Interactions to Show

Use arrows with labels:

1. `Browser -> Nginx/TLS -> webserver replicas`
2. `Simulator -> Nginx/TLS -> API routes on webserver replicas`
3. `webserver replicas -> MongoDB`
4. `discordbot -> MongoDB`
5. `Prometheus -> /metrics on webserver`
6. `Promtail on each node -> Loki`
7. `Grafana -> Prometheus`
8. `Grafana -> Loki`
9. `GitHub Actions -> Docker Hub`
10. `GitHub Actions -> Swarm manager via SSH`
11. `Swarm manager -> docker stack deploy -> webserver/prometheus/grafana/loki/promtail/discordbot`

## Important Diagram Notes

- The main application and simulator API are the same Go service.
- The app is horizontally replicated with 3 webserver replicas.
- Persistent application data is in external DigitalOcean MongoDB.
- Observability is split into metrics through Prometheus and logs through Loki.
- Grafana is the UI for both metrics and logs.
- Promtail/Loki is the active production logging path.
- Security scans are advisory, not blocking.
- `/latest` is a known replica-safety limitation because it is stored in memory per webserver process.

## Generative AI Diagram Prompt

Use this prompt with a diagram-generating AI tool. Ask it to produce a clean technical architecture diagram, not an illustration.

```text
Create a clean technical system architecture diagram for a DevOps course report.

Canvas and style:
- Landscape 16:9 layout.
- White or very light background.
- Use simple rounded rectangles for blocks.
- Each block must contain only the component name. Do not put ports, endpoints, routes, implementation details, credentials, or explanatory text inside any block.
- Use grouped containers with clear titles. Containers may have titles, but the individual blocks inside them must only have names.
- Use solid arrows for runtime traffic and deployment flows.
- Use dashed arrows for observability, metrics, logs, and advisory security feedback.
- Use concise labels on arrows.
- Avoid decorative icons unless they improve clarity.
- Use these color groups:
  - External clients: light gray.
  - Public entry/TLS: light blue.
  - Docker Swarm runtime: light green.
  - Database: light yellow.
  - Observability: light purple.
  - CI/CD and registry: light orange.
  - Secrets/configuration: light red or pink.

Main title:
"MiniTwit Production Architecture"

Left side: External Clients
Draw one block:
- "Browser Users"

Center top: Public Entry Point
Draw two blocks:
- "itu-minitwit.me"
- "Nginx + TLS"

Draw arrows:
- Browser Users -> itu-minitwit.me, label "HTTPS"
- itu-minitwit.me -> Nginx + TLS, label "public entry"

Center: DigitalOcean Docker Swarm
Draw a large container titled:
"DigitalOcean Docker Swarm: minitwit-network"

Inside it show three smaller node containers:
1. "Manager: minitwit"
2. "Worker: minitwit-web-1"
3. "Worker: minitwit-web-2"

Represent the webserver service only through three replica blocks distributed across the Swarm nodes:
- "Web replica 1"
- "Web replica 2"
- "Web replica 3"

Do not draw a separate "webserver service" block. The three web replica blocks already represent the webserver service.

Do not mention "/latest" anywhere in the diagram.

Draw arrow:
- Nginx + TLS -> Web replica 1, label "app traffic"
- Nginx + TLS -> Web replica 2, label "app traffic"
- Nginx + TLS -> Web replica 3, label "app traffic"

Right side: Managed Database
Draw a box outside the Swarm container:
"DigitalOcean Managed MongoDB"

Draw arrows:
- Web replica 1 -> DigitalOcean Managed MongoDB, label "database reads/writes"
- Web replica 2 -> DigitalOcean Managed MongoDB, label "database reads/writes"
- Web replica 3 -> DigitalOcean Managed MongoDB, label "database reads/writes"
- discordbot -> DigitalOcean Managed MongoDB, label "read/write bot data"

Inside Swarm on the manager node, draw:
- "discordbot"

Observability group inside Swarm:
Draw four boxes:
1. "Prometheus"
2. "Grafana"
3. "Loki"
4. "Promtail"

Draw dashed arrows:
- Prometheus -> Web replica 1, label "scrape metrics"
- Prometheus -> Web replica 2, label "scrape metrics"
- Prometheus -> Web replica 3, label "scrape metrics"
- Grafana -> Prometheus, label "metrics"
- Promtail -> Loki, label "push logs"
- Grafana -> Loki, label "log queries"
- Web replica 1 -> Promtail, label "container logs"
- Web replica 2 -> Promtail, label "container logs"
- Web replica 3 -> Promtail, label "container logs"
- discordbot -> Promtail, label "container logs"
- Browser Users -> Grafana, label "view dashboards"

Bottom: CI/CD and Delivery
Draw a separate group:
"GitHub Actions + Docker Hub"

Inside it draw only these blocks:
- "GitHub Repository"
- "Continuous Integration"
- "Automated Release"
- "Continuous Deployment"
- "Docker Hub"
- "Semgrep"
- "Trivy"

Draw arrows:
- GitHub Actions -> Docker Hub, label "build and push images"
- GitHub Actions -> Swarm manager, label "SSH + copy stack/config + deploy.sh"
- Swarm manager -> Docker Hub, label "pull latest images"
- Swarm manager -> Web replica 1, label "deploy stack"
- Swarm manager -> Web replica 2, label "deploy stack"
- Swarm manager -> Web replica 3, label "deploy stack"
- Swarm manager -> Prometheus, label "deploy stack"
- Swarm manager -> Grafana, label "deploy stack"
- Swarm manager -> Loki, label "deploy stack"
- Swarm manager -> Promtail, label "deploy stack"
- Swarm manager -> discordbot, label "deploy stack"
- Semgrep -> Continuous Integration, dashed, label "advisory feedback"
- Trivy -> Continuous Deployment, dashed, label "advisory feedback"

Secrets/config group:
Draw a small box:
"GitHub Secrets / .env"

Draw arrows:
- GitHub Secrets / .env -> GitHub Actions deployment, label "runtime configuration"
- GitHub Secrets / .env -> Swarm services, label "environment variables"

At the bottom corner, add only these two text lines. Do not title it "Legend". Do not put it inside a frame. Do not add any other legend information:
- Solid arrow = user/runtime/deployment path
- Dashed arrow = observability or advisory feedback

Strict exclusions:
- Do not draw MiniTwit Simulator.
- Do not draw a separate "webserver service" block.
- Do not put logic, ports, endpoint names, route names, image names, or implementation details inside blocks.
- Do not mention "/latest".
- Do not draw central rsyslog.
```

Priority: Must have.
