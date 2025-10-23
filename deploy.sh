#!/bin/bash

# Caddy Admin UI Deployment Script
# This script builds and deploys the Caddy Admin UI to caddy.biswas.me

set -e  # Exit on any error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
CONTAINER_NAME="caddy-admin-ui"
IMAGE_NAME="caddy-admin-ui"
COMPOSE_FILE="compose.yaml"

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}  Caddy Admin UI Deployment Script${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Check if we're in the correct directory
if [ ! -f "main.go" ] || [ ! -f "Dockerfile" ]; then
    echo -e "${RED}Error: main.go or Dockerfile not found!${NC}"
    echo "Please run this script from the caddy-admin directory"
    exit 1
fi

# Check if docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed!${NC}"
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}Error: Docker Compose is not installed!${NC}"
    exit 1
fi

# Use docker compose (v2) or docker-compose (v1)
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
else
    DOCKER_COMPOSE="docker-compose"
fi

echo -e "${YELLOW}Step 1: Checking environment...${NC}"
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}Warning: .env file not found. Using .env.example as template...${NC}"
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${YELLOW}Please edit .env file with your credentials before continuing.${NC}"
        echo -e "${YELLOW}Press Enter to continue after editing .env, or Ctrl+C to cancel...${NC}"
        read
    else
        echo -e "${RED}Error: .env.example not found!${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓ Environment file found${NC}"
echo ""

echo -e "${YELLOW}Step 2: Stopping existing container...${NC}"
if docker ps -a | grep -q $CONTAINER_NAME; then
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true
    echo -e "${GREEN}✓ Stopped and removed existing container${NC}"
else
    echo -e "${GREEN}✓ No existing container found${NC}"
fi
echo ""

echo -e "${YELLOW}Step 3: Building Docker image...${NC}"
$DOCKER_COMPOSE build --no-cache
echo -e "${GREEN}✓ Docker image built successfully${NC}"
echo ""

echo -e "${YELLOW}Step 4: Starting container...${NC}"
$DOCKER_COMPOSE up -d
echo -e "${GREEN}✓ Container started${NC}"
echo ""

echo -e "${YELLOW}Step 5: Waiting for application to start...${NC}"
sleep 3

# Check if container is running
if docker ps | grep -q $CONTAINER_NAME; then
    echo -e "${GREEN}✓ Container is running${NC}"
else
    echo -e "${RED}✗ Container failed to start!${NC}"
    echo "Checking logs..."
    docker logs $CONTAINER_NAME
    exit 1
fi
echo ""

echo -e "${YELLOW}Step 6: Checking application health...${NC}"
# Try to connect to the application
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8084/login | grep -q "200"; then
    echo -e "${GREEN}✓ Application is responding${NC}"
else
    echo -e "${YELLOW}⚠ Application might still be starting up...${NC}"
fi
echo ""

echo -e "${YELLOW}Step 7: Displaying container status...${NC}"
docker ps | grep $CONTAINER_NAME || echo -e "${RED}Container not found in running processes${NC}"
echo ""

echo -e "${YELLOW}Step 8: Displaying recent logs...${NC}"
docker logs --tail 20 $CONTAINER_NAME
echo ""

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}  Deployment Complete!${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""
echo -e "${BLUE}Access the application at:${NC}"
echo -e "  ${GREEN}https://caddy.biswas.me${NC}"
echo -e "  ${GREEN}http://localhost:8084${NC} (local)"
echo ""
echo -e "${BLUE}Useful commands:${NC}"
echo -e "  View logs:        ${YELLOW}docker logs -f $CONTAINER_NAME${NC}"
echo -e "  Restart:          ${YELLOW}docker restart $CONTAINER_NAME${NC}"
echo -e "  Stop:             ${YELLOW}docker stop $CONTAINER_NAME${NC}"
echo -e "  Shell access:     ${YELLOW}docker exec -it $CONTAINER_NAME sh${NC}"
echo -e "  View status:      ${YELLOW}docker ps | grep $CONTAINER_NAME${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo -e "  1. Ensure Caddy reverse proxy is configured for caddy.biswas.me"
echo -e "  2. Ensure DNS record exists: caddy.biswas.me CNAME anshuman.duckdns.com"
echo -e "  3. Login with your credentials"
echo -e "  4. Generate API keys via the web UI"
echo ""
