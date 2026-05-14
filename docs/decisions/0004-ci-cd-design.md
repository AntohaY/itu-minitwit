# ADR 0004: CI/CD Design

## Status

Proposed

## Coverage

This decision should cover Session 04 CI/CD work and Session 07 quality gates.

It should explain:

- Why GitHub Actions was used.
- Why workflows are split or combined the way they are.
- Which checks are blocking.
- How releases and deployment automation are connected.

## Context

Describe the need for automated validation, releases, and deployment.

## Decision

Document the CI/CD design.

## Alternatives

- Manual testing and deployment.
- One monolithic workflow.
- Separate external CI/CD service.

## Consequences

Describe positive and negative consequences.

=====

## Project Facts

- GitHub Actions is used for CI, release automation, and deployment.
- CI runs on pushes and pull requests to `development` and `main`.
- `make verify` is the main verification entry point.
- Release automation creates GitHub releases after merged pull requests to `main`.
- Deployment runs on pushes to `main` and manual dispatch.
- Deployment builds/pushes Docker images and deploys remotely by SSH.

### Evidence

- `.github/workflows/static-analysis.yml`
- `.github/workflows/release.yml`
- `.github/workflows/continous-deployment.yml`
- `Makefile`
- `remote_files/deploy.sh`
- PR #50 introduced automated release creation: https://github.com/AntohaY/itu-minitwit/pull/50
- PR #131 added UI/E2E testing to CI: https://github.com/AntohaY/itu-minitwit/pull/131
- PR #148 added advisory Semgrep and Trivy security scanning: https://github.com/AntohaY/itu-minitwit/pull/148
- Recent successful CI/release evidence: https://github.com/AntohaY/itu-minitwit/actions/runs/25637564257 and https://github.com/AntohaY/itu-minitwit/actions/runs/25637727773

### Needs Team Evidence

- Need branch protection settings to prove which checks block merges.
- Semgrep and Trivy are configured as non-blocking, and PR #148 gives evidence that they were added as warning-mode feedback. The team should still explain the tradeoff.
- The team should explain why workflows are split into CI, release, and deployment instead of one workflow.
