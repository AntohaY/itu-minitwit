# Final Report Skeleton

This skeleton is for planning the final report. It maps the required Process Perspective and Reflection Perspective sections from `final-report-checklist.md` to the existing project documentation under `docs/`.

Keep the final report concise. The required report limit is 2500 words, so each subsection should become a short paragraph unless it contains a necessary diagram or artifact link.

## Front Matter

TODO:

- Group letter:
- Group members:
- Main repository:
- Production URL:
- Monitoring dashboard:
- Logging dashboard:
- Final PDF path: `report/build/MSc_group_[letter].pdf`

## 1. Introduction

TODO:

- Briefly state what ITU-MiniTwit is.
- Briefly state the system's current production state.
- Link to the repository and relevant operational dashboards.
- Explain that the report is structured around system, process, and reflection perspectives.

Source material:

- `README.md`
- `docs/index.md`
- `docs/project-history.md`

## 2. System Perspective

This section is included for report completeness, even though this skeleton focuses mostly on Process and Reflection.

### 2.1 Architecture and Runtime Components

TODO:

- Describe the main application components.
- Include or reference an architecture diagram.
- Explain the request flow through frontend/API, application logic, database, and observability components.

Source material:

- `docs/architecture.md`
- `docs/api.md`
- `docs/frontend-ui.md`

### 2.2 Data and Persistence

TODO:

- Explain the database choice.
- Summarize the data model.
- Explain the persistence boundary and connection management.

Source material:

- `docs/database.md`
- `docs/decisions/0003-database-choice.md`

### 2.3 Infrastructure and Quality State

TODO:

- Summarize infrastructure provisioning.
- Summarize test strategy and quality evidence.
- Mention known gaps that matter for the final assessment.

Source material:

- `docs/infrastructure.md`
- `docs/testing.md`
- `docs/decisions/0008-infrastructure-provisioning.md`

## 3. Process Perspective

The goal of this section is to explain how a change moves from idea to production, and what happens after it is running.

### 3.1 CI/CD Pipeline

TODO:

- Describe the GitHub Actions workflows.
- Explain the pipeline stages: build, test, quality checks, security checks, image publishing, and deployment.
- Explain which stages block a broken change from reaching production.
- Include or reference a CI/CD pipeline diagram.

Source material:

- `docs/ci-cd.md`
- `docs/testing.md`
- `.github/workflows/`
- `docs/decisions/0004-ci-cd-design.md`
- `docs/decisions/0006-security-scanning.md`

Evidence to collect:

- Workflow file names.
- Example successful workflow run.
- Example failed quality gate, if useful.
- Link to relevant pull requests or commits.

### 3.2 Deployment and Release

TODO:

- Explain the deployment target.
- Explain how the application is built and released.
- Explain how deployment is triggered.
- Explain how configuration and secrets are handled.
- Explain health checks and rollback strategy.

Source material:

- `docs/deployment.md`
- `docs/infrastructure.md`
- `docs/scaling-and-availability.md`
- `.github/workflows/continous-deployment.yml`
- `docs/decisions/0002-containerization.md`
- `docs/decisions/0008-infrastructure-provisioning.md`

Evidence to collect:

- Deployment workflow link.
- Production service URL.
- Docker image or registry link, if used.
- Any deployment issue or recovery example.

### 3.3 Monitoring

TODO:

- Explain what metrics are collected.
- Explain why those metrics matter operationally.
- Explain the Prometheus/Grafana flow.
- Explain how dashboards are used to assess system health.

Source material:

- `docs/monitoring.md`
- `docs/architecture.md`
- `monitoring/prometheus/`
- `monitoring/grafana/`

Evidence to collect:

- Monitoring dashboard URL.
- Dashboard screenshot for `report/images/`.
- Key metrics to mention.

### 3.4 Logging

TODO:

- Explain what the system logs.
- Explain how logs are collected and aggregated.
- Explain labels, structure, and common queries.
- Explain how logs support debugging and incident response.
- Mention privacy/security limitations around logs.

Source material:

- `docs/logging.md`
- `docs/operations.md`
- `monitoring/loki` if present.
- `monitoring/promtail/`
- `monitoring/rsyslog/`
- `docs/decisions/0005-logging-stack.md`

Evidence to collect:

- Logging dashboard URL.
- Screenshot or query example for `report/images/`.
- Example incident/debugging workflow where logs helped.

### 3.5 Security Hardening

TODO:

- Describe the main threat scenarios.
- Describe implemented mitigations.
- Explain CI security checks.
- Explain secrets management.
- State remaining risks honestly.

Source material:

- `docs/security.md`
- `docs/ci-cd.md`
- `docs/decisions/0006-security-scanning.md`

Evidence to collect:

- Security scan output or workflow link.
- Examples of hardening commits.
- Known remaining risks and why they remain.

### 3.6 Availability and Scaling

TODO:

- Explain the scaling model.
- Explain rolling updates.
- Explain health checks.
- Explain availability expectations.
- State current limitations.

Source material:

- `docs/scaling-and-availability.md`
- `docs/deployment.md`
- `docs/architecture.md`
- `docs/decisions/0007-scaling-and-availability.md`

Evidence to collect:

- Service replica or deployment configuration.
- Health check configuration.
- Any uptime or recovery observations.

## 4. Reflection Perspective

The goal of this section is to show what we learned from evolving, operating, and maintaining the system.

### 4.1 Evolution and Refactoring

TODO:

- Describe the largest evolution or refactoring issue.
- Explain why it mattered.
- Explain how the team solved it.
- Explain what lesson it created for future changes.
- Link to commits, pull requests, issues, or ADRs.

Possible angles:

- Moving from the original baseline to the current implementation.
- Containerizing the system.
- Introducing or changing the database layer.
- Improving API compatibility.
- Separating application, deployment, and observability concerns.

Source material:

- `docs/project-history.md`
- `docs/architecture.md`
- `docs/api.md`
- `docs/database.md`
- `docs/decisions/0001-go-rewrite.md`
- `docs/decisions/0002-containerization.md`
- `docs/decisions/0003-database-choice.md`

Evidence to collect:

- Key commits or pull requests.
- ADRs that explain the decision.
- Before/after examples if concise.

### 4.2 Operation

TODO:

- Describe the largest operational issue.
- Explain how monitoring, logging, deployment, or runbooks helped.
- Explain what was missing or difficult.
- Explain what the team would improve next.

Possible angles:

- Diagnosing production behavior.
- Recovering from deployment or infrastructure issues.
- Using logs and metrics as feedback.
- Managing configuration and secrets.

Source material:

- `docs/operations.md`
- `docs/monitoring.md`
- `docs/logging.md`
- `docs/deployment.md`
- `docs/infrastructure.md`

Evidence to collect:

- Incident notes.
- Dashboard screenshot.
- Log query.
- Recovery or rollback example.

### 4.3 Maintenance

TODO:

- Describe the largest maintenance issue.
- Explain how documentation, tests, CI, ADRs, and team practices helped or failed.
- Explain what should be improved to make future maintenance easier.

Possible angles:

- Keeping documentation aligned with implementation.
- Avoiding single-person knowledge ownership.
- Making CI failures actionable.
- Maintaining infrastructure scripts.
- Managing technical debt and known gaps.

Source material:

- `docs/testing.md`
- `docs/ci-cd.md`
- `docs/index.md`
- `docs/decisions/`
- `docs/decisions/exam_expectations.md`

Evidence to collect:

- Test or CI history.
- Documentation updates.
- ADR examples.
- Known gaps listed in component docs.

### 4.4 DevOps Working Style

TODO:

- Explain what was DevOps-like about the team's work.
- Explain how work moved from idea to production.
- Explain how development and operations responsibilities were shared.
- Explain how the team used feedback from tests, logs, metrics, and production.
- Compare this with previous development projects.

Source material:

- `docs/project-history.md`
- `docs/ci-cd.md`
- `docs/operations.md`
- `docs/decisions/exam_expectations.md`

Evidence to collect:

- Examples of automated feedback loops.
- Examples of shared operational work.
- Examples of changes made because of monitoring, logging, review, or CI feedback.

## 5. Use of Generative AI

TODO:

- State which generative AI tools were used.
- Explain which tasks they supported.
- Explain how outputs were reviewed.
- Reflect on benefits and problems.
- Ensure AI co-author identities are mapped in `.mailmap` as `LLM <none>`.

Source material:

- Commit history.
- Team notes.
- `.mailmap`

## 6. Conclusion

TODO:

- Summarize the final system state.
- Summarize the most important process achievement.
- Summarize the most important lesson learned.
- State the most important improvement the team would make next.

## Component-to-Report Mapping

| Component document | Report use |
|---|---|
| `docs/architecture.md` | System architecture, request flow, observability integration, scaling context |
| `docs/api.md` | Simulator API behavior, compatibility, endpoint testing |
| `docs/frontend-ui.md` | User-facing workflows and UI scope |
| `docs/database.md` | Database choice, data model, persistence boundary |
| `docs/infrastructure.md` | Provisioning, Swarm setup, reproducibility, manual steps |
| `docs/ci-cd.md` | Pipeline stages, quality gates, release automation, deployment automation |
| `docs/testing.md` | Test strategy, local tests, CI tests, quality gaps |
| `docs/deployment.md` | Deployment target, build/release flow, health checks, rollback, configuration |
| `docs/monitoring.md` | Metrics, Prometheus, Grafana dashboards, operational health |
| `docs/logging.md` | Log sources, collection flow, querying, debugging, limitations |
| `docs/operations.md` | Runbooks, recovery, troubleshooting, incident checklist |
| `docs/security.md` | Threat scenarios, mitigations, CI security checks, secrets, remaining risks |
| `docs/scaling-and-availability.md` | Scaling model, rolling updates, health checks, availability gaps |
| `docs/project-history.md` | Evolution timeline, peer review notes, lessons learned |
| `docs/decisions/*.md` | Rationale, alternatives, consequences, reflection evidence |

## Meeting Agenda

- [ ] Agree on the final report outline and word budget.
- [ ] Assign owners for Process Perspective subsections.
- [ ] Assign owners for Reflection Perspective subsections.
- [ ] Decide which diagrams and screenshots are needed.
- [ ] Collect artifact links for commits, pull requests, issues, dashboards, and workflows.
- [ ] Identify claims that need evidence before they can go into the report.
- [ ] Decide what to cut if the draft exceeds 2500 words.
