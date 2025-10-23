# Deployment Guide

Complete guide for deploying the Enhanced Caddy Admin UI to production at caddy.biswas.me.

## Prerequisites

- Docker and Docker Compose installed
- Caddy server running on the host
- Cloudflare account with API token
- DNS access for biswas.me domain
- Ports 80 and 443 accessible from internet

## Quick Start

### 1. Initial Setup

```bash
# Clone or navigate to the repository
cd /opt/stacks/caddy

# Copy environment template
cp .env.example .env

# Edit environment variables
nano .env
```

**Required environment variables in `.env`:**
```bash
SESSION_SECRET_KEY=your-32-character-random-secret-key-here
ADMIN_PASSWORD=your-secure-admin-password
USER_PASSWORD=your-secure-user-password
CADDY_ADMIN_URL=http://localhost:2019
CLOUDFLARE_API_TOKEN=your-cloudflare-api-token-here
```

### 2. Deploy the Application

```bash
# Make scripts executable (if not already)
chmod +x deploy.sh manage.sh rollback.sh

# Run deployment
./deploy.sh
```

The deployment script will:
1. Check prerequisites
2. Build the Docker image
3. Stop any existing container
4. Start the new container
5. Verify the deployment
6. Display access information

### 3. Configure Caddy Reverse Proxy

**Option A: Using Caddyfile (Recommended)**

Add to `/etc/caddy/Caddyfile`:
```caddyfile
caddy.biswas.me {
    reverse_proxy localhost:8084
}
```

Reload Caddy:
```bash
sudo caddy reload --config /etc/caddy/Caddyfile
```

**Option B: Use the Admin UI itself**

1. Access http://localhost:8084
2. Login with your credentials
3. Add new service with subdomain "caddy" and port "8084"
4. The DNS and Caddy config will be created automatically

See [CADDY_CONFIG.md](CADDY_CONFIG.md) for more options.

### 4. Verify Deployment

```bash
# Check application health
./manage.sh health

# View logs
./manage.sh logs-tail

# Test local access
curl -I http://localhost:8084/login

# Test via domain
curl -I https://caddy.biswas.me
```

## Management Commands

### Using manage.sh

```bash
# View status
./manage.sh status

# View live logs
./manage.sh logs

# View recent logs
./manage.sh logs-tail

# Restart service
./manage.sh restart

# Stop service
./manage.sh stop

# Start service
./manage.sh start

# Open shell in container
./manage.sh shell

# Rebuild and redeploy
./manage.sh rebuild

# Check health
./manage.sh health

# Clean up (removes container and images)
./manage.sh clean
```

### Direct Docker Commands

```bash
# View logs
docker logs -f caddy-admin-ui

# Restart container
docker restart caddy-admin-ui

# Stop container
docker stop caddy-admin-ui

# Remove container
docker rm caddy-admin-ui

# View container status
docker ps | grep caddy-admin-ui

# Execute commands in container
docker exec -it caddy-admin-ui sh
```

## Rollback

If something goes wrong after deployment:

```bash
./rollback.sh
```

Options:
1. Rollback to previous Docker image
2. Rebuild from current code
3. Cancel

## Updating

### Standard Update

```bash
# Pull latest changes
git pull

# Rebuild and deploy
./deploy.sh
```

### Update with Backup

```bash
# Create backup of current state
docker tag caddy-admin-ui:latest caddy-admin-ui:backup-$(date +%Y%m%d)

# Deploy new version
./deploy.sh

# If issues occur, rollback
./rollback.sh
```

## Monitoring

### View Logs

```bash
# Live logs
./manage.sh logs

# Last 50 lines
./manage.sh logs-tail

# Search for errors
docker logs caddy-admin-ui 2>&1 | grep -i error

# Save logs to file
docker logs caddy-admin-ui > /tmp/caddy-admin-ui.log
```

### Check Health

```bash
# Run health check
./manage.sh health

# Check if container is running
docker ps | grep caddy-admin-ui

# Check resource usage
docker stats caddy-admin-ui --no-stream
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
./manage.sh logs-tail

# Check if port 8084 is already in use
netstat -tlnp | grep 8084

# Verify .env file exists
cat .env

# Check Docker service
sudo systemctl status docker
```

### Can't Access via Domain

```bash
# Check DNS resolution
dig caddy.biswas.me +short
nslookup caddy.biswas.me

# Check Caddy proxy configuration
curl http://localhost:2019/config/apps/http/servers/srv0/routes | jq

# Verify local access works
curl -I http://localhost:8084/login

# Check firewall
sudo ufw status
```

### DNS Records Not Creating

```bash
# Check Cloudflare credentials
cat .env | grep CLOUDFLARE

# Test Cloudflare API access
curl -X GET "https://api.cloudflare.com/client/v4/zones" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json"

# Check container has access to credentials
docker exec caddy-admin-ui env | grep CLOUDFLARE

# View application logs for DNS errors
docker logs caddy-admin-ui | grep -i dns
```

### API Keys Not Working

```bash
# Generate new API key via UI
# Access http://localhost:8084
# Click "Manage API Keys" → "Generate New API Key"

# Test API key
curl -H "X-API-Key: cak_your_key" http://localhost:8084/api/dns

# Check API key handler logs
docker logs caddy-admin-ui | grep -i "api key"
```

## Security Best Practices

### 1. Secure Environment Variables

```bash
# Ensure .env has proper permissions
chmod 600 .env

# Don't commit .env to git
echo ".env" >> .gitignore

# Use strong passwords
openssl rand -base64 32  # For SESSION_SECRET_KEY
```

### 2. Regular Updates

```bash
# Update system packages
sudo apt update && sudo apt upgrade

# Update Docker images
docker pull golang:1.25.0-alpine
docker pull alpine:latest

# Rebuild application
./deploy.sh
```

### 3. Backup API Keys

API keys are stored in-memory and will be lost on restart. Save generated keys securely:

```bash
# Save to password manager or secure vault
# Never commit keys to git
```

### 4. Monitor Access Logs

```bash
# Monitor for suspicious activity
./manage.sh logs | grep -i "failed\|unauthorized\|forbidden"

# Set up log rotation
docker run -d \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  ...
```

## Production Checklist

Before going to production:

- [ ] Environment variables configured in `.env`
- [ ] Strong passwords set for all users
- [ ] Cloudflare API token configured
- [ ] DNS record for caddy.biswas.me created
- [ ] Caddy reverse proxy configured
- [ ] SSL certificate obtained (Caddy does this automatically)
- [ ] Application accessible via https://caddy.biswas.me
- [ ] Firewall configured (ports 80, 443 open)
- [ ] Monitoring set up (logs, health checks)
- [ ] Backup strategy defined
- [ ] API keys generated and stored securely
- [ ] Documentation reviewed by team

## Automated Monitoring

Create a simple health check cron job:

```bash
# Add to crontab (crontab -e)
*/5 * * * * curl -f http://localhost:8084/login > /dev/null 2>&1 || systemctl restart docker
```

Or use a monitoring service:

```bash
# Example with Uptime Kuma, Prometheus, etc.
# Configure to check https://caddy.biswas.me
```

## Support

For issues and questions:

- Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) (if available)
- Review application logs: `./manage.sh logs-tail`
- Check Caddy logs: `sudo journalctl -u caddy -n 50`
- Review [API_USAGE.md](API_USAGE.md) for API documentation
- Review [CADDY_CONFIG.md](CADDY_CONFIG.md) for proxy configuration

## Additional Resources

- [README.md](README.md) - Project overview
- [API_USAGE.md](API_USAGE.md) - API documentation
- [CADDY_CONFIG.md](CADDY_CONFIG.md) - Reverse proxy configuration
- [CLAUDE.md](CLAUDE.md) - Technical architecture documentation
