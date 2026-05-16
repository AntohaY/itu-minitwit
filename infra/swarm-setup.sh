#!/usr/bin/env bash
set -euo pipefail

# Invoked by Terraform's null_resource.swarm. Mirrors setup-swarm.sh
# but reaches the droplets over plain SSH (no Vagrant in the loop).
#
# Required env vars (populated by Terraform's local-exec):
#   SSH_KEY     - path to the private key matching the DO ssh key
#   MANAGER_IP  - public IPv4 of the manager droplet
#   WORKER_IPS  - space-separated public IPv4s of the worker droplets

: "${SSH_KEY:?missing}"
: "${MANAGER_IP:?missing}"
: "${WORKER_IPS:?missing}"

SSH_OPTS=(-i "${SSH_KEY}" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)

ssh_node() {
  local host="$1"
  shift
  ssh "${SSH_OPTS[@]}" "root@${host}" "$@"
}

wait_for_ssh() {
  local host="$1"
  for i in $(seq 1 60); do
    if ssh "${SSH_OPTS[@]}" -o BatchMode=yes "root@${host}" true 2>/dev/null; then
      return 0
    fi
    sleep 5
  done
  echo "SSH never came up on ${host}" >&2
  return 1
}

echo "==> Waiting for SSH on manager (${MANAGER_IP})..."
wait_for_ssh "${MANAGER_IP}"
ssh_node "${MANAGER_IP}" "cloud-init status --wait" >/dev/null

echo "==> Initializing swarm on manager..."
MANAGER_STATE=$(ssh_node "${MANAGER_IP}" "docker info --format '{{.Swarm.LocalNodeState}}'" | tr -d '\r')
if [[ "${MANAGER_STATE}" != "active" ]]; then
  ssh_node "${MANAGER_IP}" "docker swarm init --advertise-addr ${MANAGER_IP}"
else
  echo "    -> already active, skipping"
fi

JOIN_TOKEN=$(ssh_node "${MANAGER_IP}" "docker swarm join-token worker -q" | tr -d '\r')

for worker in ${WORKER_IPS}; do
  echo "==> Joining worker ${worker}..."
  wait_for_ssh "${worker}"
  ssh_node "${worker}" "cloud-init status --wait" >/dev/null

  WORKER_STATE=$(ssh_node "${worker}" "docker info --format '{{.Swarm.LocalNodeState}}'" | tr -d '\r')
  if [[ "${WORKER_STATE}" == "active" ]]; then
    echo "    -> already in a swarm, skipping"
    continue
  fi
  ssh_node "${worker}" "docker swarm join --token ${JOIN_TOKEN} ${MANAGER_IP}:2377"
done

echo "==> Swarm ready. Manager node list:"
ssh_node "${MANAGER_IP}" "docker node ls"
