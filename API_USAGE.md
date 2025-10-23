# API Usage Guide

## API Key Management

### Generate API Key (Web UI)
1. Login to the Caddy Admin UI
2. Click "🔑 Manage API Keys" button
3. Click "➕ Generate New API Key"
4. Copy the generated key (it will only be shown once!)

### API Key Endpoints

**List API Keys (Authenticated)**
```bash
curl -X GET http://localhost:8084/api/keys \
  -H "Cookie: session-name=YOUR_SESSION_COOKIE"
```

**Generate New API Key (Authenticated)**
```bash
curl -X POST http://localhost:8084/api/keys \
  -H "Cookie: session-name=YOUR_SESSION_COOKIE"
```

**Delete API Key (Authenticated)**
```bash
curl -X DELETE http://localhost:8084/api/keys \
  -H "Content-Type: application/json" \
  -H "Cookie: session-name=YOUR_SESSION_COOKIE" \
  -d '{"id": 0}'
```

## DNS Management API

All DNS endpoints require API key authentication.

### Authentication Methods

**Using Header:**
```bash
curl -H "X-API-Key: cak_your_api_key_here" ...
```

**Using Query Parameter:**
```bash
curl "http://localhost:8084/api/dns?api_key=cak_your_api_key_here"
```

### DNS Endpoints

**List All DNS Records**
```bash
curl -X GET http://localhost:8084/api/dns \
  -H "X-API-Key: cak_your_api_key_here"
```

Response:
```json
{
  "status": "success",
  "records": [
    {
      "id": "abc123",
      "type": "CNAME",
      "name": "test.biswas.me",
      "content": "anshuman.duckdns.com",
      "ttl": 1,
      "proxied": false
    }
  ],
  "count": 1
}
```

**Create DNS Record**
```bash
curl -X POST http://localhost:8084/api/dns \
  -H "X-API-Key: cak_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{"subdomain": "myapp"}'
```

This will create: `myapp.biswas.me CNAME anshuman.duckdns.com`

Response:
```json
{
  "status": "success",
  "message": "DNS record for myapp.biswas.me created"
}
```

**Delete DNS Record**
```bash
curl -X DELETE http://localhost:8084/api/dns \
  -H "X-API-Key: cak_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{"subdomain": "myapp"}'
```

Response:
```json
{
  "status": "success",
  "message": "DNS record for myapp.biswas.me deleted"
}
```

## Example Workflow

1. **Generate an API key via the web UI**
   - Login to http://localhost:8084
   - Click "Manage API Keys"
   - Generate new key: `cak_abc123xyz...`

2. **List existing DNS records**
   ```bash
   curl -X GET http://localhost:8084/api/dns \
     -H "X-API-Key: cak_abc123xyz..."
   ```

3. **Create a new DNS record**
   ```bash
   curl -X POST http://localhost:8084/api/dns \
     -H "X-API-Key: cak_abc123xyz..." \
     -H "Content-Type: application/json" \
     -d '{"subdomain": "newservice"}'
   ```

4. **Verify it was created**
   ```bash
   curl -X GET http://localhost:8084/api/dns \
     -H "X-API-Key: cak_abc123xyz..."
   ```

5. **Delete when no longer needed**
   ```bash
   curl -X DELETE http://localhost:8084/api/dns \
     -H "X-API-Key: cak_abc123xyz..." \
     -H "Content-Type: application/json" \
     -d '{"subdomain": "newservice"}'
   ```

## Security Notes

- API keys are prefixed with `cak_` (Caddy Admin Key)
- Keys are 32 characters long (plus prefix)
- Keys are generated using crypto/rand for security
- Store API keys securely - they provide full DNS management access
- Keys are only shown once when generated
- API keys are stored in-memory and will be lost on application restart
- For production use, consider implementing persistent storage for API keys

## Environment Variables

Make sure to set the following environment variables:

```bash
CLOUDFLARE_API_TOKEN=your_cloudflare_token
```

Or the token can be read from `/etc/caddy/cloudflare.env`:
```
CLOUDFLARE_API_TOKEN=your_cloudflare_token
```
