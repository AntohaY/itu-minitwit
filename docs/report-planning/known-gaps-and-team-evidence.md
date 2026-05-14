# Known Gaps and Team Evidence Checklist

Use this document during the report-construction meeting to decide what needs to be fixed, confirmed, evidenced, or honestly described as a limitation.

## How to Read This

### Known Gaps

These are limitations that can be seen from the repository. We should either fix them before the final hand-in or describe them honestly in the report and oral exam.

### Needs Team Evidence

These are claims that may be true, but the repository alone does not prove them. The team should confirm them with screenshots, dashboard links, command output, GitHub Actions runs, pull requests, issues, commits, or team knowledge.

### Meeting Output

For each item, decide one of:

- **Fix before report:** We will change code/config/docs.
- **Evidence collected:** We have proof and can use the claim in the report.
- **Mention as limitation:** We will not fix it, but we can explain the tradeoff.
- **Remove from report:** We do not have enough evidence and should not claim it.

### GitHub Evidence Pass

Evidence collected from the public GitHub repository can prove implementation history, merged decisions, successful CI runs, and release/deployment automation. It does **not** by itself prove that the current production server is healthy, that current DNS/TLS still works, or that current Swarm replicas are running unless the linked workflow or command output explicitly checks those runtime conditions.

=====

## API

Source: `docs/api.md`

### Known Gaps

- **Simulator Basic Auth credentials are hard-coded as `simulator` / `super_safe!`.**  
  This is visible in `src/api/handlers.go`. It means the credentials are not managed as secrets and cannot easily be rotated per environment. In the report, avoid claiming strong API secret management unless this is changed.

- **Some API error paths may not return structured JSON bodies.**  
  Some handlers return only an HTTP status for missing resources or bad requests. If the report says “all API errors are represented as JSON,” we need to verify and possibly adjust that claim.

- **`/latest` is stored in memory.**  
  The latest simulator command value is held inside each running process. In production with multiple replicas, different replicas may hold different latest values. This is a scaling and correctness limitation.

### Needs Team Evidence

- **Current simulator compatibility evidence.**  
  **Evidence collected:** Continuous Integration run `#84` passed on PR #154's merge commit, and the CI `make verify` path includes `minitwit_simulator.py`: https://github.com/AntohaY/itu-minitwit/actions/runs/25637564257. PR #139 added the API smoke-test script, and PR #154 expanded API smoke coverage: https://github.com/AntohaY/itu-minitwit/pull/139 and https://github.com/AntohaY/itu-minitwit/pull/154.

- **Swagger/OpenAPI compliance evidence.**  
  The route names match the spec, but exact behavior, status codes, and error payloads should be checked against `swagger3.json` before making strong claims.
  Evidence to collect: output from `make verify`, `./test-api-routes.sh --base-url <url>`, or another endpoint-by-endpoint check showing status codes and response bodies for the Swagger-defined routes.

=====

## Architecture

Source: `docs/architecture.md`

### Known Gaps

- **The code is not strongly layered into service/repository boundaries.**  
  Several handlers access MongoDB collections directly. The report should not claim a clean service/repository architecture unless the code is refactored.

- **Handler-level database access may be technical debt.**  
  This can make testing, future database migration, and separation of concerns harder.

### Needs Team Evidence

- **Current architecture diagram.**  
  The final report should include an architecture illustration. We need a current diagram matching the actual Go app, MongoDB, Swarm, Prometheus, Grafana, Loki, Promtail, and deployment flow.
  Evidence to collect: exported diagram image/PDF committed under `docs/` or `docs/report-planning/`, plus a short source note saying which files/configs it reflects.

- **Team rationale for the current internal structure.**  
  The team should decide whether handler-level database access was an intentional pragmatic choice or just unfinished refactoring.
  Evidence to collect if available: issue, PR discussion, ADR update, or report paragraph explaining why this structure was kept.

=====

## CI/CD

Source: `docs/ci-cd.md`

### Known Gaps

- **Security scans are advisory rather than blocking.**  
  Semgrep and Trivy both use `continue-on-error: true`, and the deploy job depends on `build`, not `scan-images`. This means security findings are feedback for review rather than hard deployment gates.

### Needs Team Evidence

- **Branch protection settings.**  
  We need GitHub settings or screenshots to prove which checks actually block merges to `main` or `development`.
  Evidence to collect: screenshots from GitHub repository settings for branch rules/rulesets, or `gh`/API output listing required status checks and protected branches.

- **Current workflow run links.**  
  **Evidence collected:** PR #154's merge commit has successful Continuous Integration run `#84` and Automated Release run `#38`: https://github.com/AntohaY/itu-minitwit/actions/runs/25637564257 and https://github.com/AntohaY/itu-minitwit/actions/runs/25637727773.
  Public tags are visible up to `7.2.0`, and the release page is https://github.com/AntohaY/itu-minitwit/releases.

- **Decision on advisory versus blocking security scans.**  
  **Evidence collected:** PR #148 explicitly added Semgrep and Trivy in warning/non-blocking mode, so the report should frame them as advisory security feedback loops unless the workflow is changed: https://github.com/AntohaY/itu-minitwit/pull/148.

=====

## Database

Source: `docs/database.md`

### Known Gaps

- **Database name mismatch needs clarification.**  
  `docker-compose.yml` sets `MONGO_INITDB_DATABASE=minitwit`, but the Go code always uses `dbClient.Database("test")`. This may be harmless in MongoDB, but the team should understand and explain it.

- **No migration framework is visible.**  
  Indexes are created at startup, but there is no explicit schema migration/versioning system.

### Needs Team Evidence

- **Production database configuration, backup, and high availability.**  
  **Partly evidenced:** PR #78 moved deployment toward a DigitalOcean managed MongoDB URI and GitHub Secrets for database credentials: https://github.com/AntohaY/itu-minitwit/pull/78. The team still needs to confirm current provider settings, health, backups, ownership, and whether the database is single-node or highly available.
  Evidence to collect: DigitalOcean database overview screenshot, backup/restore settings screenshot, connection/cluster status with secrets hidden, and a short note on who owns recovery.

=====

## Deployment

Source: `docs/deployment.md`

### Known Gaps

- **Rollback is not fully automated.**  
  No automatic rollback command appears in the GitHub Actions deployment workflow or `remote_files/deploy.sh`.

### Needs Team Evidence

- **Production URL.**  
  **Partly evidenced:** PR #132 documents the registered domain `itu-minitwit.me`, DNS setup, and TLS bootstrap/verification work: https://github.com/AntohaY/itu-minitwit/pull/132. Current reachability, DNS resolution, and HTTPS certificate validity still need a recent browser, `curl`, or workflow-log result.
  Evidence to collect: browser screenshot of the production site, `curl -I https://itu-minitwit.me/ping`, DNS lookup output, and certificate verification output or successful Actions TLS verification log.

- **Docker Hub or image registry link.**  
  If the report links deployable artifacts, we need the exact image repository links.
  Evidence to collect: Docker Hub repository URLs or screenshots for `webminitwitimage` and `discordbotimage`, including tags used by deployment.

- **Rollback procedure used by the team.**  
  If rollback is manual, the team should document the actual commands and decision process.
  Evidence to collect: runbook section or command snippet showing rollback commands, plus any past workflow/commit/issue where rollback or redeploy was used.

=====

## Frontend UI

Source: `docs/frontend-ui.md`

### Known Gaps

- **Visible placeholder/joke text exists in the UI.**  
  `src/templates/timeline.html` contains text such as `Public Timeline Really really good` and `SHREEEEEEEK`. The team should decide whether this is acceptable for final hand-in.

- **Frontend depends on external Bootstrap CDN.**  
  If the CDN is unavailable, styling may degrade. This is usually acceptable for a course project, but it is still an operational dependency.

### Needs Team Evidence

- **Screenshots for the report.**  
  Only needed if the final report wants to show the UI. Make sure screenshots represent polished current behavior.
  Evidence to collect: current screenshots of public timeline, login/register, personal timeline, posting, and follow/unfollow if those flows are discussed in the report.

- **Manual browser checks.**  
  **Partly evidenced:** PR #131 added Selenium/Pytest UI/E2E tests for registration, login/logout, duplicate username validation, posting, and follow/unfollow flows: https://github.com/AntohaY/itu-minitwit/pull/131. Manual layout/responsiveness screenshots remain useful if the report shows the UI.
  Evidence to collect: browser/version note and screenshots for desktop/mobile widths if the report claims the UI was manually checked.

=====

## Infrastructure

Source: `docs/infrastructure.md`

### Known Gaps

- **Not everything is reproducible from code.**  
  The repo provisions droplets and Swarm, but cloud account setup, DNS, external database setup, secrets, and credentials remain manual.

- **Manual secrets and credentials are required.**  
  `DIGITAL_OCEAN_TOKEN`, SSH keys, Docker Hub credentials, GitHub Secrets, TLS domain/email, and database credentials must be created outside the repo.

### Needs Team Evidence

- **Which parts are reproducible versus manual.**  
  **Evidence collected:** PR #147 documents the one-line setup direction through Vagrant and setup scripts, while also showing that `.env`, TLS variables, DNS, and credentials remain external/manual: https://github.com/AntohaY/itu-minitwit/pull/147.

=====

## Logging

Source: `docs/logging.md`

### Known Gaps

- **Two logging approaches exist in the repo.**  
  `remote_files/docker-stack.yml` uses Promtail/Loki directly, while root `docker-stack.yml` and `query-logs.sh` refer to a central rsyslog setup. This can confuse the report and exam explanation.

- **Promtail labels are limited.**  
  The current Promtail config reads Docker JSON logs and container IDs, but it does not clearly add labels such as service, stack, environment, or request ID.

- **Retention policy is unclear.**  
  No explicit production Loki retention settings are visible.

### Needs Team Evidence

- **Which logging path is actually deployed.**  
  **Partly evidenced:** PR #113 added rsyslog-to-Promtail/Loki work, while later deployment changes removed the central rsyslog service from the remote stack and use Promtail against Docker logs. The team should confirm which path is actually running now: https://github.com/AntohaY/itu-minitwit/pull/113.
  Evidence to collect: `docker service ls`, `docker stack ps minitwit`, and Promtail/Loki service output showing whether production uses direct Promtail Docker-log scraping or rsyslog.

- **Logging screenshots or query examples.**  
  Useful report evidence: one Grafana Explore screenshot or query showing app logs.
  Evidence to collect: Grafana Explore screenshot with a Loki query, preferably showing MiniTwit app logs around a request or deployment.

- **Retention expectations.**  
  If asked in the exam, we should know whether logs are kept for a defined period or just default/local retention.
  Evidence to collect: Loki configuration showing retention settings, Grafana/Loki admin setting screenshot, or repository config showing that default retention is used.

=====

## Monitoring

Source: `docs/monitoring.md`

### Known Gaps

- **No alert rules are visible.**  
  The repo has Prometheus/Grafana dashboards but no Prometheus alerting rules.

- **No business-level custom metrics are visible.**  
  The app has HTTP metrics, Go runtime metrics, and process metrics, but not custom counters for registrations/messages/follows.

### Needs Team Evidence

- **Dashboard URLs for monitoring and logging.**  
  Confirm the current Grafana URL, including where to see metrics dashboards and where to inspect Loki logs. Needed for report links, course URL registration, and `misc_urls.py`.
  Evidence to collect: current Grafana URL, dashboard URLs, and log Explore URL if shareable without credentials; otherwise sanitized screenshots and the URL pattern.

- **Dashboard screenshots.**  
  The report should include screenshots only if they show meaningful current data.
  Evidence to collect: Grafana screenshots showing request rate, error rate, latency, service health, and logs with timestamps close to the report date.

- **Which metrics matter operationally.**  
  **Evidence collected:** PR #61 added Prometheus/Grafana dashboards and app HTTP metrics for request counts, latency, errors, Go runtime, memory, and service health: https://github.com/AntohaY/itu-minitwit/pull/61. The team should still agree which of these are the main exam/report metrics.

=====

## Operations

Source: `docs/operations.md`

### Known Gaps

- **Operational runbook is incomplete.**  
  The docs mention operations generally, but concrete production commands and rollback steps still need to be written.

### Needs Team Evidence

- **Current production runtime evidence.**  
  Combine evidence for deployed infrastructure and stack health here: current droplet status, recent deployment workflow run, production smoke-test output, `docker service ls`, `docker service ps`, `docker stack ps minitwit`, proof of 3 web replicas, proof that declared services such as `webserver`, `prometheus`, `grafana`, `loki`, `promtail`, and `discordbot` are running, and evidence that Prometheus is scraping the production service.
  Evidence to collect: DigitalOcean droplet screenshot, latest deployment Actions run, `docker node ls`, `docker service ls`, `docker service ps minitwit_webserver`, `docker stack ps minitwit`, `curl -I <production-url>/ping`, and Prometheus target screenshot.

- **Production commands used by the team.**  
  Examples: `docker service ls`, `docker service ps`, `docker service logs`, `docker stack ps minitwit`, rollback commands, and health-check commands.
  Evidence to collect: cleaned terminal transcript or runbook section with the exact commands the team uses for status, logs, redeploy, rollback, and health checks.

- **Incident examples.**  
  The report asks for reflection on operations. Real examples are stronger than generic statements.
  Evidence to collect: issue/PR/workflow failure/log excerpt connected to one operational problem, plus the fix commit or PR that resolved it.

- **Production SSH/server access details without secrets.**  
  The report should not expose secrets, but the team should know which host/manager is used and how operations are performed.
  Evidence to collect: sanitized host/role map, SSH command template without private keys or usernames if sensitive, and which node is Swarm manager.

=====

## Project History

Source: `docs/project-history.md`

### Known Gaps

- **The inherited baseline is not fully described.**  
  The repo shows the current system, but the report needs a short story of where the project started.

- **Peer review findings are not documented yet.**  
  The report requirement asks for lessons and links. Peer review can be useful evidence if recorded.

### Needs Team Evidence

- **Links to important PRs, commits, issues, and decisions.**  
  **Evidence collected:** Useful report links include API implementation PR #27, release automation PR #50, monitoring PR #61, remote database PR #78, logging PR #113, Docker Swarm PR #115, UI/E2E PR #131, TLS PR #132, firewall/TLS verification PR #135, API smoke tests PR #139, setup automation PR #147, and security scans PR #148.

- **Major lessons learned.**  
  This needs team reflection, not just code inspection.
  Evidence to collect if available: PR review comments, issue threads, failed workflow links, or incident notes that support the lessons.

=====

## Scaling and Availability

Source: `docs/scaling-and-availability.md`

### Known Gaps

- **No formal SLO or uptime target is visible.**  
  We can discuss availability mechanisms, but not claim a formal reliability target unless the team defines one.

- **No load/failover testing is visible.**  
  The repo configures replicas and rolling updates, but does not prove behavior under load or failure.

- **MongoDB may be a single point of failure.**  
  The real risk depends on the production MongoDB setup, which needs confirmation.

- **Observability services may be manager-dependent.**  
  Prometheus, Grafana, and Loki are placed on the manager node in the stack.

### Needs Team Evidence

- **Current availability behavior.**  
  If the report claims low downtime or reliable rolling updates, we need deployment observations or tests.
  Evidence to collect: deployment workflow logs, Swarm update output, uptime/health-check screenshots during deployment, or a small load/failover test transcript if one was performed.

=====

## Security

Source: `docs/security.md`

### Known Gaps

- **Passwords are not hashed.**  
  `CheckPasswordHash` contains a TODO, and user documents store `pw` and `hashedpw` as plain values. This affects database storage, UI login/registration, and overall security.

- **No full threat model is visible.**  
  The repo has mitigations, but not a complete threat-model document.

- **No secret rotation policy is visible.**  
  Secrets are used, but rotation is not documented.

- **No visible rate limiting or abuse prevention.**  
  API/UI routes do not appear to have rate limiting.

- **Grafana port `3000` is opened in the Vagrant firewall setup.**  
  This may be intentional, but if Grafana is intended to be served through `/grafana` behind Nginx, the open port should be justified or closed.

### Needs Team Evidence

- **Current Semgrep/Trivy results.**  
  **Evidence collected for configuration:** PR #148 added Semgrep and Trivy. Current results should be taken from the latest Actions run if the report discusses actual findings.
  Evidence to collect: latest Semgrep job link, latest Trivy job link, SARIF/security tab screenshot if available, and whether findings were accepted or fixed.

- **Actual production firewall state.**  
  Vagrant shows intended UFW rules, but production should be confirmed.
  Evidence to collect: `sudo ufw status verbose` from the production host, cloud firewall screenshot if DigitalOcean firewall is used, and any Nginx/Grafana exposure evidence.

- **Decision on plaintext passwords.**  
  The team should either fix password hashing or explicitly state it as a known limitation.
  Evidence to collect: fix PR/commit if password hashing is implemented, or an issue/ADR/report note explicitly accepting it as a known limitation.

=====

## Testing

Source: `docs/testing.md`

### Known Gaps

- **No visible Go unit tests.**  
  The pipeline runs `go test`, but there are no `*_test.go` files under `src`.

- **Database failure and concurrency scenarios are lightly covered.**  
  E2E tests cover happy-path and some validation flows, but not many failure modes.

- **`test-api-routes.sh` is not visibly run in CI.**  
  It is useful, but the GitHub Actions workflow does not clearly call it.

### Needs Team Evidence

- **Which tests the team actually ran manually.**  
  If API smoke tests or production smoke tests were manual, record when and against which URL.
  Evidence to collect: terminal output from `./test-api-routes.sh --base-url <url>`, `curl` smoke tests, browser smoke-test screenshots, and date/URL of the run.

- **Coverage claims.**  
  Avoid saying “high test coverage” unless there is coverage output. Better: say which user/API flows are covered.
  Evidence to collect: `go test ./...` output, CI test job links, Selenium/Pytest output, simulator output, and coverage output only if the team decides to measure it.

=====

## Decision Records / ADR Evidence

Sources: `docs/decisions/0001-go-rewrite.md` through `docs/decisions/0008-infrastructure-provisioning.md`

These are cross-cutting because they support oral exam questions like “why did you choose this?”

### Known Gaps

- **ADR statuses are still `Proposed`.**  
  If these decisions are final, consider changing status to `Accepted`.

- **Several ADRs still contain prompt text.**  
  The fact sections help, but the Context/Decision/Consequences sections should eventually be filled or the report should not rely on them as finished ADRs.

### Needs Team Evidence

- **Go rewrite rationale.**  
  Explain the inherited baseline, why Go was chosen, and what tradeoffs it introduced.
  Evidence to collect if available: early migration PRs/issues, commit links, ADR update, or report paragraph connecting the original baseline to the Go rewrite.

- **Docker rationale.**  
  Explain why Docker was preferred over direct host deployment or VM-only deployment.
  Evidence to collect if available: containerization PRs/issues, Dockerfile/Compose/Swarm links, ADR update, or report paragraph explaining the tradeoff.

- **MongoDB rationale.**  
  Explain why MongoDB was chosen over PostgreSQL or another storage option.
  Evidence to collect if available: database PRs/issues, ADR update, or report paragraph explaining data-model and managed-database tradeoffs.

- **CI/CD design rationale.**  
  Explain why GitHub Actions was used and why workflows are split into CI, release, and deployment.
  Evidence to collect if available: workflow PRs/issues, ADR update, or report paragraph explaining the split between CI, release, and deployment.

- **Logging stack rationale.**  
  Explain why Loki/Promtail/Grafana were chosen over Docker logs only, ELK/EFK, or cloud-provider logging.
  Evidence to collect if available: logging PRs/issues, Grafana/Loki config links, ADR update, or report paragraph explaining the tool choice.

- **Scaling/availability rationale.**  
  Explain why Docker Swarm replicas and rolling updates were chosen instead of blue/green, active/standby, or Kubernetes.
  Evidence to collect if available: Swarm PRs/issues, stack config links, ADR update, or report paragraph explaining the orchestration choice.

- **Infrastructure provisioning rationale.**  
  Explain why Vagrant/scripts were chosen instead of Terraform or manual setup.
  Evidence to collect if available: Vagrant/setup PRs/issues, setup script links, ADR update, or report paragraph explaining the provisioning tradeoff.

=====

## Highest-Priority Meeting Questions

- [ ] Are we fixing password hashing before final hand-in, or documenting it as a limitation?
- [ ] Are Semgrep and Trivy supposed to block deployment, or are they advisory?
- [ ] Which logging path is actually active in production: Promtail/Loki directly or rsyslog-based collection?
- [ ] Is `/latest` being in memory acceptable with 3 replicas, or should it be stored centrally?
- [ ] What are the real production URLs for app, Grafana, and logs?
- [ ] Can we prove the current deployment is running with 3 web replicas?
- [ ] What was our biggest operational incident or deployment problem?
- [ ] Which PRs/commits/issues should the report cite for the reflection section?
- [ ] What exact commands do we use for production troubleshooting and rollback?
- [ ] Which diagrams and screenshots do we need for the final report?
