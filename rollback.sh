#!/bin/bash

# Caddy Admin UI Rollback Script
# This script rolls back to a previous Docker image

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

CONTAINER_NAME="caddy-admin-ui"
IMAGE_NAME="caddy-admin-ui"

echo -e "${RED}======================================${NC}"
echo -e "${RED}  Caddy Admin UI Rollback Script${NC}"
echo -e "${RED}======================================${NC}"
echo ""

# Check for docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed!${NC}"
    exit 1
fi

echo -e "${YELLOW}Available images:${NC}"
docker images | grep $IMAGE_NAME || echo "No previous images found"
echo ""

echo -e "${YELLOW}Current container status:${NC}"
docker ps -a | grep $CONTAINER_NAME || echo "Container not found"
echo ""

# Get backup images
BACKUP_IMAGES=$(docker images --format "{{.ID}} {{.CreatedAt}}" | grep -v "^$IMAGE_NAME" | head -5)

if [ -z "$BACKUP_IMAGES" ]; then
    echo -e "${RED}No backup images found. Cannot rollback.${NC}"
    echo "Run 'docker images' to see available images"
    exit 1
fi

echo -e "${YELLOW}Select an image to rollback to:${NC}"
echo "1. Previous build (if available)"
echo "2. Rebuild from current code"
echo "3. Cancel"
echo ""
read -p "Enter choice (1-3): " choice

case $choice in
    1)
        echo -e "${YELLOW}Rolling back to previous build...${NC}"
        # Get the previous image ID
        PREV_IMAGE=$(docker images --format "{{.ID}}" | head -2 | tail -1)

        if [ -z "$PREV_IMAGE" ]; then
            echo -e "${RED}No previous image found${NC}"
            exit 1
        fi

        echo -e "${YELLOW}Stopping current container...${NC}"
        docker stop $CONTAINER_NAME 2>/dev/null || true
        docker rm $CONTAINER_NAME 2>/dev/null || true

        echo -e "${YELLOW}Starting with previous image: $PREV_IMAGE${NC}"
        docker run -d --name $CONTAINER_NAME \
            --network host \
            --restart unless-stopped \
            --env-file .env \
            -v /etc/caddy/cloudflare.env:/etc/caddy/cloudflare.env:ro \
            $PREV_IMAGE

        echo -e "${GREEN}✓ Rollback complete${NC}"
        ;;

    2)
        echo -e "${YELLOW}Rebuilding from current code...${NC}"
        ./deploy.sh
        ;;

    3)
        echo -e "${BLUE}Rollback cancelled${NC}"
        exit 0
        ;;

    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${YELLOW}Checking container status...${NC}"
sleep 2
docker ps | grep $CONTAINER_NAME

echo ""
echo -e "${YELLOW}Recent logs:${NC}"
docker logs --tail 20 $CONTAINER_NAME

echo ""
echo -e "${GREEN}Rollback operation complete!${NC}"
