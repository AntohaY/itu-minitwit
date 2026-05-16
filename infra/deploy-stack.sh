#!/usr/bin/env bash
set -euo pipefail

# Invoked by Terraform's null_resource.deploy after the swarm is ready.
#
# Required env vars (populated by Terraform's local-exec):
#   SSH_KEY, MANAGER_IP, REPO_ROOT
#   DOCKER_USERNAME, MONGO_URI, DISCORD_TOKEN
#   GRAFANA_ADMIN_USER, GRAFANA_ADMIN_PASSWORD, COOKIE_SECURE

: "${SSH_KEY:?missing}"
: "${MANAGER_IP:?missing}"
: "${REPO_ROOT:?missing}"

SSH_OPTS=(-i "${SSH_KEY}" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)

echo "==> Creating /minitwit on manager..."
ssh "${SSH_OPTS[@]}" "root@${MANAGER_IP}" 'mkdir -p /minitwit'

echo "==> Uploading stack files..."
scp "${SSH_OPTS[@]}" -r \
  "${REPO_ROOT}/remote_files/docker-stack.yml" \
  "${REPO_ROOT}/remote_files/deploy.sh" \
  "${REPO_ROOT}/remote_files/prometheus.yml" \
  "${REPO_ROOT}/monitoring" \
  "root@${MANAGER_IP}:/minitwit/"

echo "==> Writing .env..."
TMPENV=$(mktemp)
cat > "${TMPENV}" <<EOF
DOCKER_USERNAME=${DOCKER_USERNAME}
MONGO_URI="${MONGO_URI}"
DISCORD_TOKEN=${DISCORD_TOKEN}
GRAFANA_ADMIN_USER=${GRAFANA_ADMIN_USER}
GRAFANA_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}
COOKIE_SECURE=${COOKIE_SECURE}
EOF
scp "${SSH_OPTS[@]}" "${TMPENV}" "root@${MANAGER_IP}:/minitwit/.env"
rm "${TMPENV}"

echo "==> Running deploy.sh on manager..."
ssh "${SSH_OPTS[@]}" "root@${MANAGER_IP}" 'chmod +x /minitwit/deploy.sh && cd /minitwit && ./deploy.sh'

echo "==> Stack deployed."
