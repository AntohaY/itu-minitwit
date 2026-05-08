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

