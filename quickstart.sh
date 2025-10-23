#!/bin/bash

# Quick Start Setup Script
# This script guides you through first-time setup of Caddy Admin UI

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Caddy Admin UI - Quick Start Setup       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker not found${NC}"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi
echo -e "${GREEN}✓ Docker installed${NC}"

# Check Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}✗ Docker Compose not found${NC}"
    echo "Please install Docker Compose"
    exit 1
fi
echo -e "${GREEN}✓ Docker Compose installed${NC}"

# Check if running as root or with docker permissions
if ! docker ps &> /dev/null; then
    echo -e "${RED}✗ Cannot access Docker${NC}"
    echo "You may need to run with sudo or add your user to docker group"
    exit 1
fi
echo -e "${GREEN}✓ Docker accessible${NC}"

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Step 1: Environment Configuration
echo -e "${YELLOW}Step 1: Environment Configuration${NC}"
echo ""

if [ -f ".env" ]; then
    echo -e "${YELLOW}⚠ .env file already exists${NC}"
    read -p "Overwrite existing .env? (y/N): " overwrite
    if [[ $overwrite =~ ^[Yy]$ ]]; then
        cp .env.example .env
    fi
else
    echo -e "${BLUE}Creating .env file from template...${NC}"
    cp .env.example .env
    echo -e "${GREEN}✓ .env file created${NC}"
fi

echo ""
echo -e "${BLUE}Please configure the following:${NC}"
echo ""

# Generate session secret
SESSION_SECRET=$(openssl rand -base64 32 | tr -d '\n' 2>/dev/null || head -c 32 /dev/urandom | base64 | tr -d '\n')
echo -e "${YELLOW}Generated session secret key${NC}"

# Prompt for passwords
read -sp "Enter admin password: " ADMIN_PASS
echo ""
read -sp "Enter user password: " USER_PASS
echo ""

# Prompt for Cloudflare token
echo ""
echo -e "${BLUE}Cloudflare API Token:${NC}"
echo "Get your token from: https://dash.cloudflare.com/profile/api-tokens"
read -p "Enter Cloudflare API token (or press Enter to skip): " CF_TOKEN

# Update .env file
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/SESSION_SECRET_KEY=.*/SESSION_SECRET_KEY=$SESSION_SECRET/" .env
    sed -i '' "s/ADMIN_PASSWORD=.*/ADMIN_PASSWORD=$ADMIN_PASS/" .env
    sed -i '' "s/USER_PASSWORD=.*/USER_PASSWORD=$USER_PASS/" .env
    if [ -n "$CF_TOKEN" ]; then
        sed -i '' "s/CLOUDFLARE_API_TOKEN=.*/CLOUDFLARE_API_TOKEN=$CF_TOKEN/" .env
    fi
else
    # Linux
    sed -i "s/SESSION_SECRET_KEY=.*/SESSION_SECRET_KEY=$SESSION_SECRET/" .env
    sed -i "s/ADMIN_PASSWORD=.*/ADMIN_PASSWORD=$ADMIN_PASS/" .env
    sed -i "s/USER_PASSWORD=.*/USER_PASSWORD=$USER_PASS/" .env
    if [ -n "$CF_TOKEN" ]; then
        sed -i "s/CLOUDFLARE_API_TOKEN=.*/CLOUDFLARE_API_TOKEN=$CF_TOKEN/" .env
    fi
fi

echo -e "${GREEN}✓ Environment configured${NC}"
echo ""

# Step 2: Build and Deploy
echo -e "${YELLOW}Step 2: Build and Deploy${NC}"
echo ""
read -p "Ready to build and deploy? (Y/n): " deploy_now

if [[ ! $deploy_now =~ ^[Nn]$ ]]; then
    echo -e "${BLUE}Starting deployment...${NC}"
    ./deploy.sh
else
    echo -e "${YELLOW}Skipping deployment. Run './deploy.sh' when ready.${NC}"
    exit 0
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Step 3: Configure Caddy Proxy
echo -e "${YELLOW}Step 3: Configure Caddy Reverse Proxy${NC}"
echo ""
echo "You need to configure Caddy to proxy requests to the admin UI."
echo ""
echo "Choose a method:"
echo "1. Manual - I'll configure Caddy myself"
echo "2. Auto - Add to Caddyfile automatically"
echo "3. Skip - I'll do it later"
echo ""
read -p "Enter choice (1-3): " caddy_choice

case $caddy_choice in
    2)
        CADDYFILE="/etc/caddy/Caddyfile"
        if [ -f "$CADDYFILE" ]; then
            echo ""
            echo "Adding to $CADDYFILE..."
            echo ""
            echo "caddy.biswas.me {" | sudo tee -a $CADDYFILE
            echo "    reverse_proxy localhost:8084" | sudo tee -a $CADDYFILE
            echo "}" | sudo tee -a $CADDYFILE
            echo ""
            echo "Reloading Caddy..."
            sudo caddy reload --config $CADDYFILE
            echo -e "${GREEN}✓ Caddy configured${NC}"
        else
            echo -e "${RED}Caddyfile not found at $CADDYFILE${NC}"
            echo "Please configure manually. See CADDY_CONFIG.md"
        fi
        ;;
    1|3)
        echo ""
        echo "See CADDY_CONFIG.md for configuration instructions"
        ;;
esac

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Step 4: Verify Setup
echo -e "${YELLOW}Step 4: Verification${NC}"
echo ""

sleep 2

# Check if container is running
if docker ps | grep -q caddy-admin-ui; then
    echo -e "${GREEN}✓ Container is running${NC}"
else
    echo -e "${RED}✗ Container is not running${NC}"
    echo "Check logs: ./manage.sh logs-tail"
fi

# Check local access
if curl -s -o /dev/null -w "%{http_code}" http://localhost:8084/login | grep -q "200"; then
    echo -e "${GREEN}✓ Application accessible on localhost:8084${NC}"
else
    echo -e "${RED}✗ Cannot access application on localhost:8084${NC}"
fi

# Check domain access
if curl -s -o /dev/null -w "%{http_code}" https://caddy.biswas.me 2>/dev/null | grep -q "200\|301\|302"; then
    echo -e "${GREEN}✓ Application accessible at caddy.biswas.me${NC}"
else
    echo -e "${YELLOW}⚠ caddy.biswas.me not yet accessible${NC}"
    echo "  This is normal if you haven't configured Caddy proxy yet"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Setup Complete! 🎉                ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Access your Caddy Admin UI:${NC}"
echo -e "  Local:  ${GREEN}http://localhost:8084${NC}"
echo -e "  Domain: ${GREEN}https://caddy.biswas.me${NC}"
echo ""
echo -e "${BLUE}Login credentials:${NC}"
echo -e "  Username: ${GREEN}admin${NC} or ${GREEN}anshuman${NC}"
echo -e "  Password: ${GREEN}(the password you set)${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  1. Login to the web UI"
echo "  2. Click 'Manage API Keys' to generate an API key"
echo "  3. Add your services"
echo "  4. Configure DNS records"
echo ""
echo -e "${BLUE}Useful commands:${NC}"
echo -e "  Status:    ${YELLOW}./manage.sh status${NC}"
echo -e "  Logs:      ${YELLOW}./manage.sh logs${NC}"
echo -e "  Health:    ${YELLOW}./manage.sh health${NC}"
echo -e "  Restart:   ${YELLOW}./manage.sh restart${NC}"
echo -e "  Help:      ${YELLOW}./manage.sh help${NC}"
echo ""
echo -e "${BLUE}Documentation:${NC}"
echo "  Deployment:  DEPLOYMENT.md"
echo "  API Usage:   API_USAGE.md"
echo "  Caddy Setup: CADDY_CONFIG.md"
echo "  Architecture: CLAUDE.md"
echo ""
