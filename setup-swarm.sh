#!/usr/bin/env bash

echo "======================================="
echo "1. Initializing Swarm on Master..."
echo "======================================="

# Get Master IP and initialize
MANAGER_IP=$(vagrant ssh minitwit -c "curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address" | tr -d '\r')
vagrant ssh minitwit -c "docker swarm init --advertise-addr $MANAGER_IP"

# Get the join token
JOIN_TOKEN=$(vagrant ssh minitwit -c "docker swarm join-token worker -q" | tr -d '\r')

echo " -> Master IP: $MANAGER_IP"
echo " -> Join Token: $JOIN_TOKEN"
echo ""

echo "======================================="
echo "2. Joining Workers to the Swarm..."
echo "======================================="

WORKERS=(
  "minitwit-web-1"
  "minitwit-web-2"
)

for worker in "${WORKERS[@]}"; do
  echo "Connecting $worker..."
  vagrant ssh "$worker" -c "docker swarm join --token $JOIN_TOKEN $MANAGER_IP:2377"
done

echo ""
echo "Swarm Setup Complete! Current Nodes:"
vagrant ssh minitwit -c "docker node ls"