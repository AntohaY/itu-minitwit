#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

MANAGER="minitwit"
WORKERS=(
  "minitwit-web-1"
  "minitwit-web-2"
)

MANAGER_DEPLOY_ENV_VARS=(
  "DOCKER_USERNAME"
  "MONGO_URI"
  "DISCORD_TOKEN"
  "GRAFANA_ADMIN_USER"
  "GRAFANA_ADMIN_PASSWORD"
)

manager_ssh() {
  vagrant ssh "${MANAGER}" -c "$1"
}

worker_ssh() {
  local worker="$1"
  local command="$2"
  vagrant ssh "${worker}" -c "${command}"
}

load_local_deploy_env() {
  if [[ -f ".env" ]]; then
    echo "Loading deployment variables from local .env..."
    set -a
    # shellcheck disable=SC1091
    source ".env"
    set +a
  fi
}

validate_manager_deploy_env() {
  local missing=()
  local var

  for var in "${MANAGER_DEPLOY_ENV_VARS[@]}"; do
    if [[ -z "${!var:-}" ]]; then
      missing+=("${var}")
    fi
  done

  if (( ${#missing[@]} > 0 )); then
    echo "ERROR: Missing deployment environment variables: ${missing[*]}" >&2
    echo "Add them to the local .env file or export them before running ./setup-swarm.sh." >&2
    exit 1
  fi
}

build_manager_deploy_env_prefix() {
  local assignments=()
  local var
  local quoted_value

  for var in "${MANAGER_DEPLOY_ENV_VARS[@]}"; do
    printf -v quoted_value '%q' "${!var}"
    assignments+=("${var}=${quoted_value}")
  done

  printf '%s ' "${assignments[@]}"
}

deploy_application_stack() {
  echo "Deploying application stack on ${MANAGER}..."

  load_local_deploy_env
  validate_manager_deploy_env

  local remote_env_prefix
  remote_env_prefix="$(build_manager_deploy_env_prefix)"
  manager_ssh "${remote_env_prefix}bash -lc 'chmod +x /minitwit/deploy.sh && cd /minitwit && ./deploy.sh'"
}

echo "======================================="
echo "1. Initializing Swarm on Master..."
echo "======================================="

MANAGER_IP=$(manager_ssh "curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address" | tr -d '\r')
MANAGER_SWARM_STATE=$(manager_ssh "docker info --format '{{.Swarm.LocalNodeState}}'" | tr -d '\r')

if [[ "${MANAGER_SWARM_STATE}" != "active" ]]; then
  manager_ssh "docker swarm init --advertise-addr ${MANAGER_IP}"
else
  echo " -> Swarm already active on ${MANAGER}, skipping init."
fi

JOIN_TOKEN=$(manager_ssh "docker swarm join-token worker -q" | tr -d '\r')

echo " -> Master IP: ${MANAGER_IP}"
echo ""

echo "======================================="
echo "2. Joining Workers to the Swarm..."
echo "======================================="

for worker in "${WORKERS[@]}"; do
  echo "Connecting ${worker}..."
  WORKER_SWARM_STATE=$(worker_ssh "${worker}" "docker info --format '{{.Swarm.LocalNodeState}}'" | tr -d '\r')

  if [[ "${WORKER_SWARM_STATE}" == "active" ]]; then
    echo " -> ${worker} is already part of a swarm, skipping join."
    continue
  fi

  worker_ssh "${worker}" "docker swarm join --token ${JOIN_TOKEN} ${MANAGER_IP}:2377"
done

echo ""
echo "======================================="
echo "3. Bootstrapping Manager Services..."
echo "======================================="

if [[ -n "${TLS_DOMAIN:-}" && -n "${TLS_EMAIL:-}" ]]; then
  echo "Bootstrapping TLS on ${MANAGER} for ${TLS_DOMAIN}..."
  manager_ssh "chmod +x /minitwit/bootstrap_droplet_tls.sh && sudo DOMAIN='${TLS_DOMAIN}' EMAIL='${TLS_EMAIL}' APP_UPSTREAM_PORT='${APP_UPSTREAM_PORT:-8080}' /minitwit/bootstrap_droplet_tls.sh"
else
  echo "TLS_DOMAIN/TLS_EMAIL not set, skipping TLS bootstrap."
fi

deploy_application_stack

echo ""
echo "Swarm Setup Complete! Current Nodes:"
manager_ssh "docker node ls"