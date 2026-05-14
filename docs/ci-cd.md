# CI/CD

## Coverage

This document should cover Session 04 CI/CD and release automation, Session 07 quality gates, and the security scanning parts of Session 11.

It should explain:

- Which GitHub Actions workflows exist.
- What each workflow validates or deploys.
- Which checks block merges, releases, or deployments.
- Which checks are informational only.
- How releases and continuous deployment are connected.
- How static analysis, Trivy, and Semgrep fit into the pipeline.

## Purpose

Use this page to document the automated path from code change to verified release and deployment.

## Workflows

Document each workflow and its role.

Suggested files:

- `.github/workflows/static-analysis.yml`
- `.github/workflows/release.yml`
- `.github/workflows/continous-deployment.yml`
- Any test workflow, if present.

## Quality Gates

Explain which checks must pass.

Suggested topics:

- Unit tests.
- UI tests.
- API tests.
- Static analysis.
- Dependency or container scanning.
- Release or deployment conditions.

## Release Automation

Describe how a release is created.

Suggested topics:

- Tagging strategy.
- Image build and push.
- GitHub release artifact.
- Version naming.

## Continuous Deployment

Explain how deployment is triggered and executed.

Suggested topics:

- Branch or release trigger.
- Secrets required for deployment.
- Remote deployment commands.
- Post-deployment verification.

## README Material

- GitHub Actions runs tests, static analysis, release automation, and continuous deployment.
- Quality gates help prevent broken changes from reaching production.

=====

## Project Facts

### Workflows

- `.github/workflows/static-analysis.yml` is named `Continuous Integration`.
- `.github/workflows/release.yml` is named `Automated Release`.
- `.github/workflows/continous-deployment.yml` is named `Continuous Deployment`.

### Continuous Integration

- CI runs on pushes and pull requests targeting `development` and `main`.
- The `verify` job sets up Go using `src/go.mod`.
- The `verify` job sets up Python 3.10.
- The `verify` job installs `golangci-lint`.
- The main verification command is `make verify`.
- `make verify` starts the Docker Compose environment, runs checks, and tears the environment down.
- `make run-checks` executes simulator testing, `go fmt`, `golangci-lint run`, Hadolint for Dockerfiles, and `go test -v ./...`.
- A separate `ui-e2e` job runs after `verify`.
- The UI E2E job installs Firefox and Geckodriver, then runs `make ui-e2e`.
- `make ui-e2e` starts `dbserver` and `webserver` through Docker Compose, waits for `/register_user`, then runs `pytest` against `test_itu_minitwit_ui.py`.

### Security Checks

- The CI workflow runs Semgrep with `p/security-audit`, `p/owasp-top-ten`, and `p/golang`.
- Semgrep has `continue-on-error: true`, so findings are informational unless branch protection or manual review treats them as blocking.
- Continuous deployment scans the pushed web image with Trivy.
- Trivy scans severities `CRITICAL,HIGH,MEDIUM`.
- Trivy also has `continue-on-error: true`, and the deploy job depends on `build`, not `scan-images`. Therefore image scan findings do not currently block deployment.

### Release and Deployment Automation

- PR #50 introduced automated release creation from merged PRs into `main`: https://github.com/AntohaY/itu-minitwit/pull/50.
- `release.yml` runs when a pull request into `main` is closed and merged.
- Release version bumping is based on PR labels `major`, `minor`, or `patch`, defaulting to `patch`.
- Releases are created with `softprops/action-gh-release`.
- `continous-deployment.yml` runs on pushes to `main` and can also be triggered manually.
- Deployment builds and pushes `${DOCKER_USERNAME}/webminitwitimage:latest` and `${DOCKER_USERNAME}/discordbotimage:latest`.
- Deployment copies stack/config files to the server over SSH and runs `/minitwit/deploy.sh`.

### Evidence in the Repository

- `.github/workflows/static-analysis.yml`
- `.github/workflows/release.yml`
- `.github/workflows/continous-deployment.yml`
- `Makefile`
- `test_itu_minitwit_ui.py`
- `test-api-routes.sh`
- `remote_files/deploy.sh`

### Known Gaps / Needs Team Evidence

- Need GitHub branch protection evidence to claim that CI blocks merges.
- PR #148 explicitly added Semgrep and Trivy in warning/non-blocking mode, so the report should call them security feedback rather than strict gates unless changed: https://github.com/AntohaY/itu-minitwit/pull/148.
- Recent public workflow evidence: Continuous Integration run `#84` passed and Automated Release run `#38` passed on PR #154's merge commit: https://github.com/AntohaY/itu-minitwit/actions/runs/25637564257 and https://github.com/AntohaY/itu-minitwit/actions/runs/25637727773.
- Public Git tags exist up to `7.2.0`, which supports the claim that release automation produced versioned repository releases/tags. The release page can be linked as https://github.com/AntohaY/itu-minitwit/releases.
- `go test ./...` currently has no visible `*_test.go` files in `src`, so the main automated behavioral coverage comes from the simulator, API smoke scripts, and Selenium/Pytest UI tests.

### Oral Exam Answer

Our CI/CD pipeline uses GitHub Actions to validate code, create releases, build Docker images, scan them, and deploy to the Swarm host. The strongest gates are the `make verify` checks and UI E2E tests. Security scanning exists through Semgrep and Trivy, but both are currently non-blocking, so they provide feedback rather than fully preventing deployment.
