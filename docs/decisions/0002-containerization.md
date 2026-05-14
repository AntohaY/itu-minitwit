# ADR 0002: Containerization

## Status

Proposed

## Coverage

This decision should cover Session 02 containerization work.

It should explain:

- Why Docker was introduced.
- How containerization supports local development and deployment.
- Which alternatives were considered.
- What operational trade-offs containerization introduced.

## Context

Describe the need for reproducible runtime environments.

## Decision

Document the final containerization approach.

## Alternatives

- Run directly on the host.
- Use VM-only deployment.
- Use another container platform.

## Consequences

Describe positive and negative consequences.

=====

## Project Facts

- The application is containerized with Docker.
- Local development and CI use `docker-compose.yml`.
- Production-style deployment uses Docker Swarm stack files.
- The web image uses a multi-stage Dockerfile.
- The runtime image uses Alpine and runs as a non-root `appuser`.
- The CI/CD workflow builds and pushes Docker Hub images for the webserver and Discord bot.

### Evidence

- `docker/web/Dockerfile`
- `src/bot/Dockerfile`
- `docker-compose.yml`
- `docker-stack.yml`
- `remote_files/docker-stack.yml`
- `.github/workflows/continous-deployment.yml`
- Early Docker migration appears in PR #4, and Swarm deployment appears in PR #115: https://github.com/AntohaY/itu-minitwit/pull/4 and https://github.com/AntohaY/itu-minitwit/pull/115

### Needs Team Evidence

- The team should state why Docker was preferred over direct host deployment.
- The team should discuss the operational cost of maintaining Dockerfiles, Compose, Swarm stacks, image tags, and registry credentials.
