# ADR 0006: Security Scanning

## Status

Proposed

## Coverage

This decision should cover Session 11 security scanning and its connection to CI/CD.

It should explain:

- Why Semgrep and Trivy were selected.
- Which risks each tool addresses.
- Whether findings block the pipeline.
- What gaps remain after scanning.

## Context

Describe the need for automated security feedback.

## Decision

Document the selected scanning approach.

## Alternatives

- Manual review only.
- Dependency scanning only.
- Container scanning only.
- Different SAST or image scanning tools.

## Consequences

Describe positive and negative consequences.

=====

## Project Facts

- Semgrep runs in the CI workflow.
- Trivy scans the Docker web image in the deployment workflow.
- Semgrep uses security-audit, OWASP Top Ten, and Go rulesets.
- Trivy reports critical, high, and medium severity findings in SARIF format.
- Trivy results are uploaded through GitHub's SARIF upload action.

### Evidence

- `.github/workflows/static-analysis.yml`
- `.github/workflows/continous-deployment.yml`
- PR #148 added Semgrep and Trivy in warning/non-blocking mode: https://github.com/AntohaY/itu-minitwit/pull/148

### Needs Team Evidence

- Both Semgrep and Trivy currently use `continue-on-error: true`; PR #148 confirms this was introduced as warning-mode security feedback.
- The deploy job does not depend on the Trivy scan job.
- The team should explain whether advisory scans are acceptable for course scope or should become blocking before final hand-in.
- The team should add examples of findings or scan results if used in the final report.
