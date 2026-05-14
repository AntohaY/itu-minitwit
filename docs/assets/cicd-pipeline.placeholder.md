# Placeholder: cicd-pipeline.png

Target asset: `cicd-pipeline.png`

Create a pipeline diagram showing:

- Pull request or push.
- CI checks through `make verify`.
- UI/E2E tests.
- Release creation.
- Docker image build and push.
- Semgrep and Trivy scans.
- Deployment over SSH.
- `docker stack deploy`.
- Health/TLS verification.

## Generative AI Diagram Prompt

```text
Create a CI/CD and deployment pipeline diagram for the MiniTwit project.

Canvas and style:
- Horizontal left-to-right pipeline.
- Use numbered stages.
- Use rectangular blocks for jobs and artifacts.
- Use solid arrows for required flow.
- Use dashed arrows for advisory/non-blocking security scans.
- Use warning/annotation badges for non-blocking scans.
- Keep labels short enough for a report figure.

Title:
"MiniTwit CI/CD and Deployment Pipeline"

Stage 1: Source Control
Block: "GitHub Repository: AntohaY/itu-minitwit"
Inputs:
- "Pull request"
- "Push to main"
- "workflow_dispatch"

Stage 2: Continuous Integration
Block: "GitHub Actions: Continuous Integration"
Inside the block list:
- "make verify"
- "Start Docker Compose test environment"
- "Simulator test"
- "go fmt"
- "golangci-lint"
- "Hadolint Dockerfiles"
- "go test ./..."
- "UI/E2E: Selenium + Pytest"

Arrow from Stage 1 to Stage 2:
"validate changes"

Stage 3: Automated Release
Block: "Automated Release"
Labels:
- "Merged PR to main"
- "Version bump from PR label"
- "GitHub release/tag"

Arrow from Stage 2 to Stage 3:
"merge to main"

Stage 4: Build Images
Block: "Continuous Deployment: Build"
Inside:
- "Build web image"
- "Build Discord bot image"
- "Docker Buildx"

Stage 5: Image Registry
Block: "Docker Hub"
Inside:
- "webminitwitimage:latest"
- "discordbotimage:latest"

Arrow Stage 4 -> Stage 5:
"push images"

Stage 6: Advisory Security Feedback
Draw two dashed side blocks connected after image build:
- "Trivy image scan"
- "Semgrep static security scan"
Label both:
"Advisory / non-blocking"
Draw dashed arrows from these scan blocks back to GitHub Actions or PR review:
"security feedback"
Do not make these arrows block deployment.

Stage 7: Remote Deploy
Block: "Deploy over SSH"
Inside:
- "Create .env from GitHub Secrets"
- "scp stack/config/monitoring files"
- "ssh to Swarm manager"
- "run /minitwit/deploy.sh"

Draw arrow:
Docker Hub -> Remote Deploy, label "images available"
GitHub Actions -> Remote Deploy, label "SSH + config copy"

Stage 8: Docker Swarm Update
Block: "Docker Swarm manager: minitwit"
Inside:
- "docker stack deploy -c docker-stack.yml minitwit"
- "pull latest images"
- "update webserver/grafana/prometheus/loki/promtail/discordbot"
- "rolling update: start-first, parallelism 1"

Stage 9: Post-deploy Verification
Block: "Health and TLS verification"
Inside:
- "nginx -t"
- "systemctl is-active nginx"
- "certbot certificates"
- "HTTP -> HTTPS redirect"
- "curl https://itu-minitwit.me/ping"
- "openssl certificate chain check"

Final block:
"Production: https://itu-minitwit.me"
Sub-label:
"Grafana: /grafana"

Secrets block:
Place below the pipeline:
"GitHub Secrets"
List:
- "DOCKER_USERNAME / DOCKER_PASSWORD"
- "SSH key/user/host"
- "MongoDB credentials"
- "Grafana credentials"
- "DISCORD_TOKEN"
- "TLS_DOMAIN"

Draw arrows from GitHub Secrets to:
- Build Images
- Remote Deploy
- Post-deploy Verification

Add legend:
- Solid arrow = required pipeline flow
- Dashed arrow = advisory feedback
- Semgrep/Trivy are intentionally non-blocking
```

Priority: Must have.
