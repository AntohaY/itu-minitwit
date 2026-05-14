# Report and README Asset Index

Use this folder for diagrams, screenshots, and command-output files that support the final report, README, and oral exam preparation.

The `.placeholder.md` files are temporary collection notes. Replace each placeholder with the real asset when it is ready, using the suggested target filename.

## Suggested Priority

### Must Have

1. `architecture-overview.png`  
   System architecture overview showing users/simulator, Go MiniTwit, MongoDB, Docker Swarm, observability, CI/CD, Docker Hub, DigitalOcean, and TLS/Nginx.

2. `cicd-pipeline.png`  
   CI/CD flow from PR/push through CI checks, release, image build/push, deployment, Swarm update, and health/TLS checks.

3. `grafana-monitoring-dashboard.png`  
   Current Grafana dashboard screenshot showing meaningful production metrics such as request rate, error rate, latency, service health, memory, or goroutines.

4. `production-health-curl.txt`  
   Current command output proving the production endpoint is reachable, for example `curl -I https://itu-minitwit.me/ping`.

### Strongly Useful

5. `swarm-runtime-topology.png`  
   Runtime topology showing Swarm manager/worker nodes, 3 web replicas, manager-pinned observability services, and external MongoDB.

6. `grafana-loki-logs.png`  
   Grafana Explore/Loki screenshot showing real MiniTwit logs from the production stack.

7. `docker-service-ls.txt`  
   Sanitized Swarm command output proving current services and replica counts.

8. `digitalocean-database-status.png`  
   DigitalOcean managed MongoDB overview/status/backup screenshot with secrets hidden.

9. `tls-certificate-proof.png`  
   Browser certificate view, TLS verification output, or screenshot proving HTTPS certificate validity.

### Optional

10. `ui-public-timeline.png`  
    Browser screenshot of the public timeline.

11. `ui-auth-flow.png`  
    Browser screenshot covering registration/login flow.

12. `ui-message-follow-flow.png`  
    Browser screenshot covering posting and follow/unfollow behavior.

13. `docker-hub-images.png`  
    Docker Hub image repository screenshot showing deployed image names/tags.

14. `github-actions-success.png`  
    GitHub Actions screenshot showing successful CI/release/deployment runs.

15. `security-scan-results.png`  
    Semgrep/Trivy workflow or security tab screenshot showing current scan results.

## Collection Rules

- Hide secrets, tokens, private keys, database passwords, and private IPs if they are not needed for the report.
- Prefer screenshots with visible timestamps or recent data.
- Prefer command-output `.txt` files for terminal evidence because they are easier to quote and review than screenshots.
- Keep final filenames stable so README/report links do not need to change later.
