#!/bin/bash

# Caddy Admin UI Management Script
# Quick commands for managing the Caddy Admin UI service

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

CONTAINER_NAME="caddy-admin-ui"

# Function to show usage
usage() {
    echo -e "${BLUE}Caddy Admin UI Management Script${NC}"
    echo ""
    echo "Usage: ./manage.sh [command]"
    echo ""
    echo "Commands:"
    echo -e "  ${GREEN}status${NC}      - Show container status and health"
    echo -e "  ${GREEN}logs${NC}        - View live logs (Ctrl+C to exit)"
    echo -e "  ${GREEN}logs-tail${NC}   - View last 50 lines of logs"
    echo -e "  ${GREEN}restart${NC}     - Restart the container"
    echo -e "  ${GREEN}stop${NC}        - Stop the container"
    echo -e "  ${GREEN}start${NC}       - Start the container"
    echo -e "  ${GREEN}shell${NC}       - Open shell in container"
    echo -e "  ${GREEN}rebuild${NC}     - Rebuild and redeploy"
    echo -e "  ${GREEN}clean${NC}       - Remove container and images"
    echo -e "  ${GREEN}health${NC}      - Check application health"
    echo ""
}

# Function to check if container exists
container_exists() {
    docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"
}

# Function to check if container is running
container_running() {
    docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"
}

case "${1:-help}" in
    status)
        echo -e "${BLUE}Container Status:${NC}"
        if container_exists; then
            docker ps -a | grep $CONTAINER_NAME
            echo ""
            echo -e "${BLUE}Container Details:${NC}"
            docker inspect $CONTAINER_NAME --format '
Status: {{.State.Status}}
Started: {{.State.StartedAt}}
Restarts: {{.RestartCount}}
Image: {{.Config.Image}}
'
        else
            echo -e "${RED}Container does not exist${NC}"
        fi
        ;;

    logs)
        echo -e "${BLUE}Showing live logs (Ctrl+C to exit)...${NC}"
        docker logs -f $CONTAINER_NAME
        ;;

    logs-tail)
        echo -e "${BLUE}Last 50 lines of logs:${NC}"
        docker logs --tail 50 $CONTAINER_NAME
        ;;

    restart)
        echo -e "${YELLOW}Restarting container...${NC}"
        docker restart $CONTAINER_NAME
        echo -e "${GREEN}✓ Container restarted${NC}"
        sleep 2
        docker ps | grep $CONTAINER_NAME
        ;;

    stop)
        echo -e "${YELLOW}Stopping container...${NC}"
        docker stop $CONTAINER_NAME
        echo -e "${GREEN}✓ Container stopped${NC}"
        ;;

    start)
        echo -e "${YELLOW}Starting container...${NC}"
        if container_exists; then
            docker start $CONTAINER_NAME
            echo -e "${GREEN}✓ Container started${NC}"
            sleep 2
            docker ps | grep $CONTAINER_NAME
        else
            echo -e "${RED}Container does not exist. Run ./deploy.sh first${NC}"
        fi
        ;;

    shell)
        echo -e "${BLUE}Opening shell in container...${NC}"
        if container_running; then
            docker exec -it $CONTAINER_NAME sh
        else
            echo -e "${RED}Container is not running${NC}"
        fi
        ;;

    rebuild)
        echo -e "${YELLOW}Rebuilding and redeploying...${NC}"
        ./deploy.sh
        ;;

    clean)
        echo -e "${RED}This will remove the container and all images!${NC}"
        read -p "Are you sure? (yes/no): " confirm
        if [ "$confirm" == "yes" ]; then
            echo -e "${YELLOW}Stopping and removing container...${NC}"
            docker stop $CONTAINER_NAME 2>/dev/null || true
            docker rm $CONTAINER_NAME 2>/dev/null || true

            echo -e "${YELLOW}Removing images...${NC}"
            docker images | grep caddy-admin-ui | awk '{print $3}' | xargs docker rmi -f 2>/dev/null || true

            echo -e "${GREEN}✓ Cleanup complete${NC}"
        else
            echo -e "${BLUE}Cleanup cancelled${NC}"
        fi
        ;;

    health)
        echo -e "${BLUE}Checking application health...${NC}"
        echo ""

        if ! container_running; then
            echo -e "${RED}✗ Container is not running${NC}"
            exit 1
        fi

        echo -e "${GREEN}✓ Container is running${NC}"

        # Check if application responds on port 8084
        if curl -s -o /dev/null -w "%{http_code}" http://localhost:8084/login | grep -q "200"; then
            echo -e "${GREEN}✓ Application responds on port 8084${NC}"
        else
            echo -e "${RED}✗ Application not responding on port 8084${NC}"
        fi

        # Check if accessible via domain
        if curl -s -o /dev/null -w "%{http_code}" https://caddy.biswas.me 2>/dev/null | grep -q "200\|301\|302"; then
            echo -e "${GREEN}✓ Application accessible via caddy.biswas.me${NC}"
        else
            echo -e "${YELLOW}⚠ caddy.biswas.me not accessible (may need DNS/Caddy config)${NC}"
        fi

        # Show recent errors
        echo ""
        echo -e "${BLUE}Recent errors (if any):${NC}"
        docker logs --tail 100 $CONTAINER_NAME 2>&1 | grep -i "error\|fail\|fatal" | tail -5 || echo "No recent errors found"
        ;;

    help|--help|-h)
        usage
        ;;

    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo ""
        usage
        exit 1
        ;;
esac
