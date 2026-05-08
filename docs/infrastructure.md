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

