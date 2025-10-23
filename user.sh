#!/bin/bash

# User Management CLI Wrapper Script
# Executes user management commands inside the Docker container

CONTAINER_NAME="caddy-admin-ui"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Error: Container '${CONTAINER_NAME}' is not running"
    echo "Start it with: docker-compose up -d"
    exit 1
fi

# Check if command needs interactive input (add without password, reset-password without password)
NEEDS_TTY=false
if [[ "$1" == "add" ]] && [[ ! "$@" =~ "-password" ]]; then
    NEEDS_TTY=true
elif [[ "$1" == "reset-password" ]] && [[ ! "$@" =~ "-password" ]]; then
    NEEDS_TTY=true
fi

# Execute usermgmt command in container
if [ "$NEEDS_TTY" = true ]; then
    docker exec -it $CONTAINER_NAME ./usermgmt "$@"
else
    docker exec $CONTAINER_NAME ./usermgmt "$@"
fi
