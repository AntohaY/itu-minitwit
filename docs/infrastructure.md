# Infrastructure

## Coverage

This document should cover Session 12 Infrastructure as Code and provisioning work, with supporting context from Session 09 scaling and availability.

It should explain:

- How the infrastructure is provisioned.
- How Vagrant and setup scripts are used.
- How the Docker Swarm cluster is bootstrapped.
- Which parts are reproducible from code.
- Which parts remain manual.
- How firewall, host setup, and service prerequisites are handled.

## Purpose

Use this page to document how the underlying runtime platform is prepared. Keep application rollout details in [Deployment](deployment.md).

## Provisioning Overview

Describe the infrastructure provisioning approach.

Suggested references:

- `Vagrantfile`
- `setup-swarm.sh`
- Files under `remote_files/`
- Docker installation and Swarm initialization scripts.

## Swarm Cluster Setup

Document how the Swarm cluster is created.

Suggested topics:

- Manager node.
- Worker nodes.
- Join tokens.
- Overlay networks.
- Stack deployment prerequisites.

## Reproducibility

Explain what can be recreated from the repository.

Suggested topics:

- VM creation.
- Docker setup.
- Firewall setup.
- Monitoring/logging service setup.
- Manual secrets or credentials.

## Manual Steps

List anything that is not fully automated.

Examples:

- DNS records.
- GitHub Secrets.
- Cloud provider credentials.
- Production database provisioning.

## README Material

- Infrastructure setup is documented through Vagrant and provisioning scripts.
- The project distinguishes application deployment from machine provisioning.

=====

## Project Facts

### What We Implemented

- Infrastructure provisioning is defined in `Vagrantfile` using the DigitalOcean Vagrant provider.
- The Vagrant setup creates three Ubuntu 22.04 droplets: `minitwit`, `minitwit-web-1`, and `minitwit-web-2`.
- The DigitalOcean region is `fra1`.
- The configured droplet size is `s-1vcpu-1gb`.
- The manager node is `minitwit`.
- Worker nodes are `minitwit-web-1` and `minitwit-web-2`.
- Vagrant installs Docker through Docker's official install script.
- UFW is enabled during provisioning.
- Firewall rules allow OpenSSH, HTTP port `80`, Grafana port `3000`, and Docker Swarm communication ports.
- `setup-swarm.sh` initializes Docker Swarm on the manager and joins the worker nodes.
- `setup-swarm.sh` can optionally bootstrap TLS through `remote_files/bootstrap_droplet_tls.sh` when `TLS_DOMAIN` and `TLS_EMAIL` are set.
- Deployment variables are loaded from local `.env` or exported shell variables and passed to the manager.
- `remote_files/` contains files synced to the manager for deployment.
- PR #147 documents the one-line setup direction and updates Vagrant/setup scripts for Swarm, TLS, and deployment automation: https://github.com/AntohaY/itu-minitwit/pull/147.
- PR #132 documents the domain/TLS bootstrap work for `itu-minitwit.me`: https://github.com/AntohaY/itu-minitwit/pull/132.
- PR #78 shows the move to an external DigitalOcean managed MongoDB connection string in deployment: https://github.com/AntohaY/itu-minitwit/pull/78.

### Evidence in the Repository

- `Vagrantfile`
- `setup-swarm.sh`
- `remote_files/deploy.sh`
- `remote_files/docker-stack.yml`
- `remote_files/bootstrap_droplet_tls.sh`
- `remote_files/prometheus.yml`
- `README.md`

### Known Gaps / Needs Team Evidence

- The repo defines the provisioning flow, but it cannot prove which droplets are currently alive.
- DNS/domain setup is evidenced historically by PR #132, but current DNS and DigitalOcean project/database state should still be confirmed near hand-in.
- GitHub Secrets, Docker Hub credentials, `DIGITAL_OCEAN_TOKEN`, SSH keys, TLS domain, and TLS email must be created manually.
- The report should distinguish reproducible infrastructure scripts from manual cloud-provider setup.

### Oral Exam Answer

The infrastructure is mostly reproducible through Vagrant and shell scripts. Vagrant creates three DigitalOcean droplets, installs Docker, enables firewall rules, and then `setup-swarm.sh` turns them into a Swarm cluster. The main limitation is that cloud credentials, DNS, database provisioning, and GitHub secrets are still manual.
