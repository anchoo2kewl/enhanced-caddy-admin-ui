# Caddy Reverse Proxy Configuration

This document explains how to configure your main Caddy server to proxy requests to the Caddy Admin UI at `caddy.biswas.me`.

## Option 1: Using Caddyfile (Recommended)

Add this to your main Caddyfile (usually at `/etc/caddy/Caddyfile`):

```caddyfile
caddy.biswas.me {
    reverse_proxy localhost:8084
}
```

Then reload Caddy:
```bash
sudo caddy reload --config /etc/caddy/Caddyfile
```

## Option 2: Using Caddy Admin API

You can add the route dynamically using the Caddy Admin API:

```bash
curl -X POST http://localhost:2019/config/apps/http/servers/srv0/routes \
  -H "Content-Type: application/json" \
  -d '{
    "@id": "caddy-admin-ui",
    "match": [{"host": ["caddy.biswas.me"]}],
    "handle": [{
      "handler": "reverse_proxy",
      "upstreams": [{"dial": "localhost:8084"}]
    }]
  }'
```

## Option 3: Using the Admin UI Itself

Once the Caddy Admin UI is running, you can use it to add itself to Caddy:

1. Access the UI at http://localhost:8084
2. Login with your credentials
3. Click "Add New Service"
4. Fill in:
   - **Subdomain**: `caddy`
   - **Port**: `8084`
   - **Description**: `Caddy Admin Interface`
5. Save

This will automatically:
- Create the DNS record: `caddy.biswas.me CNAME anshuman.duckdns.com`
- Add the reverse proxy route to Caddy

## DNS Configuration

Ensure your DNS is configured correctly:

```
caddy.biswas.me CNAME anshuman.duckdns.com
```

You can verify DNS propagation:
```bash
dig caddy.biswas.me +short
nslookup caddy.biswas.me
```

## Testing the Configuration

### Test local access:
```bash
curl -I http://localhost:8084/login
```

Expected: HTTP 200 OK

### Test via Caddy proxy:
```bash
curl -I https://caddy.biswas.me
```

Expected: HTTP 200 OK (or 301/302 redirect to login)

### Test DNS resolution:
```bash
curl -H "Host: caddy.biswas.me" http://localhost
```

## Troubleshooting

### Issue: 502 Bad Gateway

**Cause**: Caddy can't reach the backend on port 8084

**Solutions**:
1. Check if the container is running:
   ```bash
   ./manage.sh status
   ```

2. Check if port 8084 is listening:
   ```bash
   netstat -tlnp | grep 8084
   # or
   ss -tlnp | grep 8084
   ```

3. Check container logs:
   ```bash
   ./manage.sh logs-tail
   ```

### Issue: DNS not resolving

**Cause**: DNS record not created or not propagated

**Solutions**:
1. Check DNS:
   ```bash
   dig caddy.biswas.me +short
   ```

2. Manually create DNS record via Cloudflare dashboard

3. Use the Admin UI to create the DNS record via API

### Issue: SSL certificate error

**Cause**: Caddy hasn't obtained SSL certificate yet

**Solutions**:
1. Wait a few minutes for Caddy to obtain certificate
2. Check Caddy logs:
   ```bash
   sudo journalctl -u caddy -n 50
   # or
   docker logs caddy
   ```

3. Ensure port 443 is open and accessible from internet

### Issue: Application not accessible from outside

**Cause**: Firewall or network configuration

**Solutions**:
1. Check if port 80/443 are open:
   ```bash
   sudo ufw status
   # or
   sudo iptables -L -n
   ```

2. Ensure your router forwards ports 80 and 443 to your server

3. Verify DuckDNS is updating your IP:
   ```bash
   curl "https://www.duckdns.org/update?domains=anshuman&token=YOUR_TOKEN&ip="
   ```

## Security Recommendations

1. **Use HTTPS only**: Ensure Caddy is configured to automatically redirect HTTP to HTTPS

2. **Restrict access**: Consider adding IP whitelist if accessing from specific locations:
   ```caddyfile
   caddy.biswas.me {
       @allowed {
           remote_ip 192.168.1.0/24  # Your network
       }
       reverse_proxy @allowed localhost:8084
   }
   ```

3. **Rate limiting**: Add rate limiting to prevent brute force:
   ```caddyfile
   caddy.biswas.me {
       rate_limit {
           zone dynamic {
               key {remote_host}
               events 100
               window 1m
           }
       }
       reverse_proxy localhost:8084
   }
   ```

## Complete Example Caddyfile

Here's a complete example with all recommended settings:

```caddyfile
{
    email your-email@example.com
}

caddy.biswas.me {
    # Enable compression
    encode gzip

    # Security headers
    header {
        # Enable HSTS
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        # Prevent clickjacking
        X-Frame-Options "SAMEORIGIN"
        # Prevent MIME sniffing
        X-Content-Type-Options "nosniff"
        # XSS Protection
        X-XSS-Protection "1; mode=block"
        # Referrer Policy
        Referrer-Policy "strict-origin-when-cross-origin"
    }

    # Proxy to Caddy Admin UI
    reverse_proxy localhost:8084 {
        # Health check
        health_uri /login
        health_interval 10s
        health_timeout 5s
    }

    # Logging
    log {
        output file /var/log/caddy/caddy-admin-ui.log
        level INFO
    }
}
```

## Automated Setup Script

You can also use this quick setup script:

```bash
#!/bin/bash
# Quick setup for caddy.biswas.me reverse proxy

# Add to Caddyfile
echo "caddy.biswas.me {
    reverse_proxy localhost:8084
}" | sudo tee -a /etc/caddy/Caddyfile

# Reload Caddy
sudo caddy reload --config /etc/caddy/Caddyfile

# Wait for Caddy to start
sleep 2

# Test the configuration
curl -I https://caddy.biswas.me

echo "Setup complete! Access your admin UI at https://caddy.biswas.me"
```
