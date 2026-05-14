# ITU-MiniTwit Final Report Draft

TODO: Fill group letter, group members, repository URL, final PDF URL, and official dashboard/logging URLs before moving this into the final `report/` directory.

## 1. Introduction

ITU-MiniTwit is our course project version of MiniTwit, evolved into a deployed Go application with a browser UI, simulator-compatible API, MongoDB persistence, CI/CD, monitoring, logging, and Docker Swarm deployment. The production application is served at `https://itu-minitwit.me`, with Grafana available at `https://itu-minitwit.me/grafana`.

The project repository is `https://github.com/AntohaY/itu-minitwit`. The report focuses on the final system state, the process used to move changes from code to production, and reflections on evolution, operation, maintenance, and DevOps practice.

TODO: Insert the all-in-one diagram once created from `docs/assets/architecture-overview.placeholder.md`.

## 2. System Perspective

The system is a Go web service using `net/http` and `github.com/gorilla/mux`. The same webserver process serves browser UI routes and simulator API routes. UI routes support registration, login/logout, timelines, posting messages, and follow/unfollow workflows. API routes support the MiniTwit simulator through endpoints such as `/latest`, `/register`, `/msgs`, `/msgs/{username}`, and `/fllws/{username}`.

Persistent state is stored in MongoDB. The main collections are `user`, `message`, and `follower`, and startup code creates indexes for unique usernames, unique follow relationships, follower lookup, and timeline queries. Production uses a DigitalOcean managed MongoDB URI assembled from deployment secrets. The web application and Discord bot both connect through `MONGO_URI`.

The production runtime is Docker Swarm on DigitalOcean. The Swarm has one manager node, `minitwit`, and two worker nodes, `minitwit-web-1` and `minitwit-web-2`. The remote stack defines `webserver`, `prometheus`, `grafana`, `loki`, `promtail`, and `discordbot` services on the overlay network `minitwit-network`. The webserver runs with 3 replicas and exposes a `/ping` health endpoint. Nginx and Let's Encrypt provide HTTPS for `itu-minitwit.me`, and Grafana is served from `/grafana`.

Observability is built into the architecture. The Go application emits JSON logs with request IDs and exposes Prometheus metrics at `/metrics`. Prometheus scrapes the webserver service and stores request count, request duration, status-code, Go runtime, and process metrics. Grafana reads Prometheus for metrics dashboards and Loki for log exploration. Promtail runs as a global Swarm service and ships Docker container logs to Loki. The team confirmed the active production logging path is Promtail/Loki directly, not central rsyslog.

Known system limitations remain. Passwords are currently planned to be fixed before final submission. Simulator Basic Auth credentials are hard-coded in source code. Some API error paths return only HTTP status codes rather than structured JSON. `/latest` is held in memory per webserver process, which can be inconsistent with 3 replicas. The code is pragmatic and handler-driven; it does not claim a clean service/repository layering.

TODO: Add production proof:

```sh
curl -I https://itu-minitwit.me/ping
docker node ls
docker service ls
docker service ps minitwit_webserver
docker stack ps minitwit
```

## 3. Process Perspective

### 3.1 CI/CD Pipeline

The project uses GitHub Actions for continuous integration, release automation, and deployment. The main workflows are `.github/workflows/static-analysis.yml`, `.github/workflows/release.yml`, and `.github/workflows/continous-deployment.yml`.

CI runs on pushes and pull requests targeting `development` and `main`. The main verification entry point is `make verify`, which starts the Docker Compose test environment, runs simulator testing, checks Go formatting, runs `golangci-lint`, lints Dockerfiles with Hadolint, runs `go test -v ./...`, and tears down the environment. A separate UI/E2E job installs Firefox and Geckodriver and runs Selenium/Pytest tests against the local Compose environment.

Release automation creates GitHub releases after merged pull requests into `main`, with version bumps based on `major`, `minor`, or `patch` labels. Public repository tags exist up to `7.2.0`, showing versioned release history.

Security checks are included but advisory. Semgrep runs in CI with security-audit, OWASP Top Ten, and Go rulesets. Trivy scans the pushed web image. Both are configured with `continue-on-error: true`, and deployment depends on `build`, not `scan-images`. The team chose this deliberately to keep security feedback visible without blocking delivery during later course work.

Evidence already collected includes successful Continuous Integration run `#84` and Automated Release run `#38` on PR #154's merge commit:

- `https://github.com/AntohaY/itu-minitwit/actions/runs/25637564257`
- `https://github.com/AntohaY/itu-minitwit/actions/runs/25637727773`

TODO: Add latest CI/deployment workflow run links from the final submission week.

### 3.2 Deployment and Release

Deployment is automated from `main`. GitHub Actions logs in to Docker Hub, builds the web image from `docker/web/Dockerfile`, builds the Discord bot image from `src/bot/Dockerfile`, and pushes `${DOCKER_USERNAME}/webminitwitimage:latest` and `${DOCKER_USERNAME}/discordbotimage:latest`. The deployment job then creates a `.env` file from GitHub Secrets, copies stack/config/monitoring files to the Swarm manager over SSH, and runs `/minitwit/deploy.sh`.

The deploy script validates required environment variables, creates persistent volumes, and runs:

```sh
docker stack deploy -c docker-stack.yml minitwit --resolve-image always --with-registry-auth
```

The webserver has a Swarm healthcheck against `http://localhost:8080/ping`, and updates use `parallelism: 1`, `delay: 10s`, and `order: start-first`, so Swarm starts a new task before stopping the old one. Rollback is not fully automated; it should be documented as an operational procedure.

TODO: Add Docker Hub image links or screenshots.

TODO: Add the manual rollback command actually used by the team, for example:

```sh
docker service update --rollback minitwit_webserver
docker service ps minitwit_webserver
```

### 3.3 Monitoring

Monitoring is based on Prometheus and Grafana. The Go service registers custom HTTP metrics in `src/middleware/metrics.go`, including `minitwit_http_responses_total` and `minitwit_http_request_duration_seconds`, labeled by method, route path, and status code. Prometheus also collects Go runtime and process metrics.

Prometheus is configured to scrape `webserver:8080` every 5 seconds in production. Grafana dashboards are provisioned from JSON files under `monitoring/grafana/dashboards/`, with panels for request rate, error rate, latency percentiles, goroutines, memory usage, and service health.

These metrics matter because they help answer whether the application is up, whether deployments changed latency or error behavior, and whether the service shows resource pressure.

TODO: Add current Grafana screenshot:

```text
docs/assets/grafana-monitoring-dashboard.png
```

TODO: Confirm Prometheus target state with a screenshot from Grafana/Prometheus.

### 3.4 Logging

The application uses Go `slog` with JSON output. `BeforeAfterMiddleware` logs request start/end events, propagates or creates request IDs, and attaches `X-Request-ID` to responses. Handlers log validation failures, database failures, successful operations, and selected debug events. Sensitive log message sanitization exists for custom error tracking in `src/helpers/logsanitize`.

Production log aggregation uses Docker container logs, Promtail, Loki, and Grafana. Promtail runs globally on Swarm nodes, reads Docker JSON logs from `/var/lib/docker/containers`, and pushes them to Loki. Grafana is configured with Loki as a data source and exposes logs through the Grafana UI at `/grafana`.

This supports debugging deployment failures, checking whether the app started correctly, finding API/UI errors, and correlating issues with releases. Current limitations are weak log labels, unclear Loki retention policy, and legacy rsyslog-related files that can confuse documentation if not described as historical.

TODO: Add Grafana Loki screenshot:

```text
docs/assets/grafana-loki-logs.png
```

TODO: Add one useful LogQL query used by the team.

### 3.5 Security Hardening

Security hardening includes non-root runtime containers, GitHub Secrets, UFW provisioning rules, TLS/Nginx bootstrap support, optional post-deploy TLS verification, Semgrep, Trivy, and log sanitization. The production Docker image is multi-stage and runs as a non-root `appuser`. Sessions are configured with `HttpOnly: true` and `Secure: true`.

Secrets are not committed to the repository. The deployment workflow reads Docker Hub credentials, SSH credentials, Grafana credentials, database credentials, Discord token, and TLS domain from GitHub Secrets. The generated `.env` is copied to the manager during deployment.

Important risks remain and should be stated honestly. Password hashing is planned before final submission. Simulator Basic Auth credentials are hard-coded. Semgrep and Trivy are advisory rather than blocking. There is no visible full threat model, secret rotation policy, or rate limiting. Grafana port `3000` is opened in the Vagrant firewall setup, even though Grafana is also served through `/grafana`.

TODO: Add TLS proof:

```sh
curl -I https://itu-minitwit.me/ping
echo | openssl s_client -connect itu-minitwit.me:443 -servername itu-minitwit.me 2>/dev/null | grep "Verify return code"
```

TODO: Add firewall proof:

```sh
sudo ufw status verbose
```

### 3.6 Availability and Scaling

Availability is improved through Swarm replicas, healthchecks, and rolling updates. The webserver service runs with 3 replicas across one manager and two worker nodes. The application is mostly stateless because persistent data is in MongoDB and session state is stored in signed cookies, not local server memory.

Swarm update behavior uses start-first rolling updates, which should reduce downtime during deployment. `/ping` provides a health endpoint for the webserver. Observability services such as Prometheus, Grafana, and Loki are placed on the manager node, which is practical but makes observability manager-dependent.

The main availability limitations are lack of formal SLOs, no visible load/failover testing, possible MongoDB single-point-of-failure depending on the managed database configuration, and the in-memory `/latest` value per replica.

TODO: Add evidence that 3 replicas are currently running:

```sh
docker service ls
docker service ps minitwit_webserver
```

## 4. Reflection Perspective

### 4.1 Evolution and Refactoring

The project evolved from a baseline MiniTwit assignment into a Go, MongoDB, Dockerized, observable, tested, security-assessed, and Swarm-deployed system. Important public PRs include API implementation (#27), release automation (#50), monitoring (#61), remote database (#78), logging to Grafana/Loki (#113), Docker Swarm (#115), UI/E2E tests (#131), TLS/domain support (#132), API smoke tests (#139), setup automation (#147), and security scans (#148).

One major evolution issue was moving from a simple application into an operational system. The team added containerization, deployment automation, external MongoDB, observability, and infrastructure scripts step by step. This improved operability but also introduced configuration complexity and several parallel documentation paths. A concrete lesson is that architecture and operational documentation must be maintained continuously; otherwise old files such as rsyslog helpers can conflict with the current Promtail/Loki deployment.

TODO: Add the inherited baseline description: what language/framework/storage did the project start from, and why was Go chosen?

### 4.2 Operation

Operationally, the system can be inspected through `/ping`, `/metrics`, Grafana dashboards, Loki logs, GitHub Actions, and Swarm service state. Deployment is automated, but recovery still depends on manual inspection and rollback decisions.

The most useful operational evidence should combine a recent deployment run, service status output, a Grafana screenshot, and a log query. These artifacts prove that the system is not just configured in the repository but actually running.

TODO: Insert the team's biggest operational incident or deployment problem. Link to issue/PR/workflow/log evidence.

TODO: Add production troubleshooting command list:

```sh
docker node ls
docker service ls
docker service ps minitwit_webserver
docker service logs minitwit_webserver
docker stack ps minitwit
curl -I https://itu-minitwit.me/ping
```

### 4.3 Maintenance

Maintenance was supported by GitHub Actions, Makefile targets, documentation, ADR drafts, and component-specific docs under `docs/`. The test strategy combines simulator testing, static checks, Dockerfile linting, Selenium/Pytest UI tests, and API smoke scripts. This gives useful coverage of critical flows, but there are no visible Go unit tests and no load/failover tests.

The largest maintenance issue is keeping implementation, operations, and documentation aligned. The repository contains strong planning material, but some ADRs are still `Proposed` and several docs started as prompts/skeletons. For final submission, claims should be backed by current code, PRs, commands, screenshots, or explicit known limitations.

### 4.4 DevOps Working Style

The workflow became DevOps-like because the same repository connects application code, tests, Docker images, deployment, monitoring, logging, security checks, and infrastructure scripts. Changes move from PRs to CI checks, then to releases, Docker images, and Swarm deployment. Feedback comes from tests, linters, Semgrep/Trivy, health checks, metrics, logs, and production behavior.

Compared with a project that ends at implementation, this project required the team to think about runtime evidence, rollback, credentials, dashboards, and operational knowledge. The main improvement would be to make runbooks, incident notes, and ADR decisions more complete earlier, rather than reconstructing them near the report deadline.

## 5. Use of Generative AI

Generative AI was used as a support tool for codebase analysis, documentation planning, checklist creation, report skeletons, GitHub evidence mapping, oral-exam preparation, and diagram prompt drafting. AI output was treated as a draft that had to be checked against source files, workflows, GitHub PRs/issues/actions, production evidence, and team knowledge.

The team should document the specific tools used, for example ChatGPT/Codex and any editor AI tools such as GitHub Copilot. Prompt categories included: deriving a report checklist from course material, attaching project facts to component docs, finding evidence from PRs/actions, explaining code risks such as `/latest`, and generating architecture/CI/CD diagram prompts.

AI output should not be presented as independent project evidence. It helped structure and summarize, but final claims must be verified by the team. No secrets, private keys, database passwords, or confidential credentials should be entered into AI tools. If AI appears as a commit co-author, `.mailmap` should map it to `LLM <none>`.

TODO: Fill the final AI-use table from `docs/report-planning/report-skeleton.md`.

## 6. Conclusion

The final system is a deployed, containerized Go MiniTwit application with MongoDB persistence, Docker Swarm scaling, GitHub Actions CI/CD, Prometheus/Grafana monitoring, Promtail/Loki logging, TLS, and advisory security scanning. The strongest process achievement is the path from repository changes to automated validation, image publishing, and production deployment.

The most important lesson is that DevOps work is not only about automation. The team also needs current evidence, operational runbooks, explicit tradeoffs, and honest documentation of limitations. The next improvements should be password hashing, centralizing or accepting `/latest` behavior under replicas, stronger rollback documentation, better branch protection evidence, richer log labels, and more complete ADRs.

