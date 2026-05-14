# Deployment

## Coverage

This document should cover deployment-related work from Session 02, Session 03, Session 04, Session 09, and Session 12.

It should explain:

- How Docker images are built.
- How the application is deployed to Docker Swarm.
- How releases trigger deployment.
- How health checks, rolling updates, and rollback behavior work.
- How production configuration and endpoints are verified.
- Which deployment steps are automated and which are manual.

## Purpose

Use this page to answer: "How do we publish a new application version to the running environment?"

## Deployment Target

Describe the target runtime environment.

Suggested topics:

- Docker Swarm.
- Manager and worker nodes.
- Stack name and service names.
- Public endpoint.
- TLS or reverse proxy setup, if applicable.

## Build and Release

Document how deployable artifacts are produced.

Suggested topics:

- Docker image build.
- Image tags.
- GitHub release workflow.
- Registry used for images.

## Deployment Flow

Describe the full deployment process.

Suggested flow:

```text
Code change
  -> CI checks
  -> release
  -> image build/push
  -> Swarm stack update
  -> health verification
```

## Health Checks and Rollback

Document how a deployment is validated.

Suggested topics:

- Health check endpoints.
- Swarm update behavior.
- Rollback command or automated rollback.
- Manual verification steps.

## Configuration

Describe where deployment configuration lives.

Suggested references:

- `docker-compose.yml`
- `docker-stack.yml`
- GitHub Secrets.
- Environment variables.

## README Material

- The application is deployed as Docker services in Swarm.
- CI/CD automates release and deployment steps, with health checks and rollback considerations.

=====

## Project Facts

### Deployment Target

- Production deployment is defined in `remote_files/docker-stack.yml`.
- The production target is Docker Swarm.
- The stack name used by the deploy script is `minitwit`.
- The production stack uses an overlay network named `minitwit-network`.
- The remote production stack runs `webserver`, `prometheus`, `grafana`, `loki`, `promtail`, and `discordbot`.
- The production webserver publishes port `8080`.
- TLS and reverse proxy setup are handled separately by Nginx/Certbot bootstrap scripts when `TLS_DOMAIN` and `TLS_EMAIL` are provided.
- PR #132 documents `itu-minitwit.me` as the configured domain and adds Nginx/Certbot plus post-deploy TLS verification: https://github.com/AntohaY/itu-minitwit/pull/132.

### Build and Release

- The web image is built from `docker/web/Dockerfile`.
- The web image is pushed as `${DOCKER_USERNAME}/webminitwitimage:latest`.
- The Discord bot image is built from `src/bot/Dockerfile`.
- The bot image is pushed as `${DOCKER_USERNAME}/discordbotimage:latest`.
- The release workflow creates GitHub releases based on merged PR labels.
- The deployment workflow runs on pushes to `main` and manual dispatch.
- PR #50 introduced automated GitHub release creation from merged PRs: https://github.com/AntohaY/itu-minitwit/pull/50.

### Deployment Flow

```text
Push to main
  -> GitHub Actions continuous deployment workflow
  -> Docker Hub login
  -> build and push web image
  -> build and push Discord bot image
  -> Trivy image scan
  -> copy remote stack/config files by SSH
  -> run /minitwit/deploy.sh
  -> docker stack deploy -c docker-stack.yml minitwit
```

### Health Checks and Rollback

- The production webserver has a Docker healthcheck against `http://localhost:8080/ping`.
- The remote webserver runs 3 replicas.
- Swarm update configuration uses `parallelism: 1`, `delay: 10s`, and `order: start-first`.
- `deploy.sh` validates required environment variables before stack deployment.
- `deploy.sh` triggers `docker stack deploy` with `--resolve-image always` and `--with-registry-auth`.

### Evidence in the Repository

- `.github/workflows/continous-deployment.yml`
- `.github/workflows/release.yml`
- `docker/web/Dockerfile`
- `src/bot/Dockerfile`
- `remote_files/docker-stack.yml`
- `remote_files/deploy.sh`
- `remote_files/bootstrap_droplet_tls.sh`
- `setup-swarm.sh`

### Known Gaps / Needs Team Evidence

- No automated rollback command is visible in the deployment workflow or `deploy.sh`; rollback appears to be a manual operational concern.
- Production URL/domain evidence exists from PR #132 (`itu-minitwit.me`), but current reachability should be confirmed with a recent browser, curl, or deployment workflow log.
- Need current deployment evidence for the report, such as a recent successful deployment workflow run, Swarm service output, or production smoke-test output.
- PR #148 confirms Trivy is currently advisory/non-blocking. Deployment depends on `build`, not `scan-images`, so do not describe Trivy as a deployment gate unless this is changed.
- Need current Docker Hub or image registry link if the report links build artifacts.

### Oral Exam Answer

Deployment is automated from `main`: GitHub Actions builds Docker images, pushes them to Docker Hub, copies stack files to the server over SSH, and runs `docker stack deploy`. The production Swarm stack runs three web replicas with a `/ping` healthcheck and start-first rolling updates. Rollback is not fully automated, so that remains an operational limitation.
