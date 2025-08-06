#!/bin/bash
echo "Shutting down containers..."
docker compose -f examples/nginx-dev/docker-compose.yml down

# Force remove containers if they're still around
echo "Force removing any lingering containers..."
CONTAINER_ID=$(docker ps -a | grep nginx-dev-nginx | awk '{print $1}')
if [ ! -z "$CONTAINER_ID" ]; then
    docker rm -f $CONTAINER_ID
fi

echo "Cleaning up unused Docker resources..."
# Remove dangling images (untagged)
docker image prune -f
# Remove unused volumes
docker volume prune -f --filter "label!=keep"
# Remove build cache older than 24h
docker builder prune -f --filter "until=24h"

echo "Building containers..."
docker compose -f examples/nginx-dev/docker-compose.yml build --no-cache

echo "Starting containers..."
docker compose -f examples/nginx-dev/docker-compose.yml up -d

echo "Environment is ready!"
