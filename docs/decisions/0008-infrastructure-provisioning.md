# ADR 0008: Infrastructure Provisioning

## Status

Proposed

## Coverage

This decision should cover Session 12 Infrastructure as Code and provisioning work.

It should explain:

- Why Vagrant and scripts were used.
- Which infrastructure parts are reproducible.
- Which manual steps remain.
- What alternatives were considered.

## Context

Describe the need to make infrastructure setup repeatable.

## Decision

Document the provisioning approach.

## Alternatives

- Fully manual server setup.
- Terraform or cloud-native provisioning.
- Docker Compose only.

## Consequences

Describe positive and negative consequences.

=====

## Project Facts

- Vagrant provisions DigitalOcean droplets.
- The configured droplets are `minitwit`, `minitwit-web-1`, and `minitwit-web-2`.
- Provisioning installs Docker, enables UFW, and opens required ports.
- `setup-swarm.sh` initializes the manager and joins workers to Docker Swarm.
- Optional TLS bootstrap is handled by `remote_files/bootstrap_droplet_tls.sh`.
- Deployment files are synced from `remote_files/`.

### Evidence

- `Vagrantfile`
- `setup-swarm.sh`
- `remote_files/bootstrap_droplet_tls.sh`
- `remote_files/deploy.sh`
- `remote_files/docker-stack.yml`
- PR #147 updated Vagrant/setup scripts for one-line setup direction and Swarm/TLS deployment automation: https://github.com/AntohaY/itu-minitwit/pull/147
- PR #132 added domain/TLS bootstrap work for `itu-minitwit.me`: https://github.com/AntohaY/itu-minitwit/pull/132

### Needs Team Evidence

- DigitalOcean token, SSH key, DNS records, GitHub Secrets, Docker Hub credentials, and production database provisioning remain manual.
- The team should explain why Vagrant/scripts were chosen instead of Terraform or fully manual setup.
- Need evidence from a successful `vagrant up` or current infrastructure state for the report.
