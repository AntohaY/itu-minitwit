#!/bin/bash
source ~/.bash_profile
cd /minitwit

# 1. Safely load and export variables
set -a
source .env
set +a

# 2. PRE-Launch CHECK: Ensure critical variables are not empty
REQUIRED_VARS=(
  "DOCKER_USERNAME"
  "MONGO_URI"
  "DISCORD_TOKEN"
  "GRAFANA_ADMIN_USER"
  "GRAFANA_ADMIN_PASSWORD"
)

for VAR in "${REQUIRED_VARS[@]}"; do
  if [ -z "${!VAR}" ]; then
    echo "ERROR: Required environment variable '$VAR' is missing or empty!"
    echo "Aborting deployment to prevent downtime."
    exit 1
  fi
done

docker image prune -af --filter "until=24h"

# Prune stopped containers and unused networks
docker system prune -f --volumes --filter "until=24h"

echo "All critical variables are present. Proceeding with deployment..."

# 3. Deploy/Update the Swarm stack immediately
# --resolve-image always forces Swarm to check the registry for a newer :latest tag
# --with-registry-auth passes Docker Hub login down to the worker nodes
docker stack deploy -c docker-stack.yml minitwit \
  --resolve-image always \
  --with-registry-auth

echo "Deployment triggered! Swarm is executing a rolling update."