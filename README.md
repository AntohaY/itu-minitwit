# MiniTwit (ITU DevOps)

A Twitter-clone. The original Python/Flask + SQLite app has been rewritten in Go + MongoDB and runs on a Docker Swarm of DigitalOcean droplets, with Prometheus/Grafana/Loki for observability and a Discord bot for alerts.

The service exposes two interfaces on the same port:
- UI — server-rendered HTML for end users (`/`, `/login`, `/timeline`, `/user/{username}`, …)
- Simulator API — JSON endpoints consumed by the simulator (`/register`, `/msgs`, `/fllws/{username}`, `/latest`, …)

Public site: <https://itu-minitwit.me>

---

## Repository layout

| Path | Purpose |
|---|---|
| [src/](src/) | Go application (gorilla/mux router, handlers, middleware, DB helpers) |
| [src/bot/](src/bot/) | Discord bot — separate Go module with its own `go.mod`, built into its own image |
| [docker/](docker/) | Dockerfiles for the web and bot images |
| [monitoring/](monitoring/) | Prometheus, Grafana, Loki, Promtail configs and dashboards |
| [infra/](infra/) | Terraform definition of the production infra (droplets, firewall, MongoDB)|
| [remote_files/](remote_files/) | Files copied to the Swarm manager: authoritative `docker-stack.yml`, `deploy.sh`, TLS bootstrap |
| [.github/workflows/](.github/workflows/) | CI (static analysis, tests, E2E) and CD (build → push → deploy) |
| [Vagrantfile](Vagrantfile), [setup-swarm.sh](setup-swarm.sh) | Legacy provisioning path (still works) |
| [docker-compose.yml](docker-compose.yml) | Local dev stack |
| [report/](report/) | Course report (LaTeX/Pandoc) |

---

## Local development

Requirements: Docker + Docker Compose. Go 1.22+ only needed for running tests outside containers.

```bash
docker compose up --build      # web on :8080, MongoDB, Prometheus, Grafana, Loki, Promtail
docker compose down -v
```

Run the Go service directly (needs a MongoDB on `localhost:27017`):

```bash
cd src && go run main.go
```

Common dev commands:

```bash
make verify                            # full local CI check (build, sim, lint, UI E2E)
make test-sim                          # run the grading simulator against :8080
make ui-e2e                            # Selenium UI tests (needs geckodriver)
./test-api-routes.sh                   # API smoke tests
```

---

## Production infrastructure

Production runs a Docker Swarm of three DigitalOcean droplets (1 manager + 2 workers) with a managed MongoDB cluster. DNS for `itu-minitwit.me` lives at Namecheap (not IaC-managed).

There are two provisioning paths:

### Terraform

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars   # fill in tls_email, discord_token, grafana_admin_password, …
export DIGITALOCEAN_TOKEN=<your-token>
terraform init
terraform plan
terraform apply                                 # ~5–8 min; provisions droplets + MongoDB + deploys the stack
```

Outputs include the manager IP and MongoDB URI needed for the `SSH_HOST` and `MONGO_URI` GitHub Secrets.

### Vagrant

The original path is still functional. Requires the same `DIGITALOCEAN_TOKEN`, an SSH key at `~/.ssh/ssh_key_golang_minitwit` registered in DO under the same name, and a local `.env` with `DOCKER_USERNAME`, `MONGO_URI`, `DISCORD_TOKEN`, `GRAFANA_ADMIN_USER`, `GRAFANA_ADMIN_PASSWORD`.

```bash
vagrant up                              # creates droplets, then runs setup-swarm.sh which deploys the stack
vagrant rsync && ./setup-swarm.sh       # re-deploy onto existing droplets
vagrant provision                       # runs the script in Vagrant file
```

`MONGO_URI` should point to an external managed MongoDB (e.g. DO Managed MongoDB or Atlas).

### TLS / nginx

The reverse proxy (nginx + Let's Encrypt) is bootstrapped once per manager with [remote_files/bootstrap_droplet_tls.sh](remote_files/bootstrap_droplet_tls.sh). It is rerun automatically by the CD workflow's post-deploy verification step.

---

## How to contribute changes

### Branch naming

```
{fix|feature}/{short-message}
```

Examples: `feature/terraform`, `fix/login-redirect`.

### Workflow

1. Branch off `development`.
2. Push your branch and open a PR into `development`. CI runs automatically.
3. Once your PR is merged into `development`, the same checks run again. When a release is ready, `development` is merged into `main`.
4. Pushing to `main` triggers continuous deployment to production.

### CI on push/PR (`development`, `main`)

[`static-analysis.yml`](.github/workflows/static-analysis.yml) builds the images and runs:
- Docker Scout + Trivy + Semgrep security scans
- `make verify` (simulator test, `go fmt`, `golangci-lint`, Hadolint)
- `make ui-e2e` (Selenium UI E2E tests)


### CD on push to `main`

[`continous-deployment.yml`](.github/workflows/continous-deployment.yml):
1. Builds and pushes the web, bot, Prometheus, and Grafana images to Docker Hub
2. SCPs deploy files and a freshly rendered `.env` to the Swarm manager
3. Runs [`remote_files/deploy.sh`](remote_files/deploy.sh) on the manager
4. Verifies the deploy: nginx config, certbot renewal, TLS chain

The required GitHub Secrets are: `DOCKER_USERNAME`, `DOCKERHUB_AUTHTOKEN`, `SSH_HOST`, `SSH_USER`, `SSH_PRIVATE_KEY`, `MONGO_URI`, `DISCORD_TOKEN`, `GRAFANA_ADMIN_USER`, `GRAFANA_ADMIN_PASSWORD`, `TLS_DOMAIN`, `TLS_EMAIL`.

## Observability

- Prometheus scrapes the webserver's `/metrics` (custom counters/histograms in [src/middleware/metrics.go](src/middleware/metrics.go)).
- Grafana is served at `/grafana/` in production (dashboards and datasources provisioned from [monitoring/grafana/](monitoring/grafana/)).
- Loki + Promtail collect container logs; Promtail runs `mode: global` (one per Swarm node) reading `/var/lib/docker/containers/`.
- Discord bot posts alerts to a Discord channel via the token in `DISCORD_TOKEN`.

Each request gets an `X-Request-ID` propagated through context; all user-supplied values are sanitized before logging.

---

## Reports & releases

```bash
make report      # build the course report PDF via pandoc/xelatex
```

The generated PDF is committed back to the repo automatically by [`.github/workflows/report.yml`](.github/workflows/report.yml).
