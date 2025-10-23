# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Enhanced Caddy Admin UI - A Go-based web administration interface for managing Caddy reverse proxy services with automatic DNS record creation via Cloudflare. The application provides a modern web UI for adding, editing, and deleting services while automatically managing corresponding CNAME DNS records and Caddy reverse proxy configurations.

## Build and Run Commands

**Build the application:**
```bash
go build -o caddy-admin main.go
```

**Run locally:**
```bash
./caddy-admin
# Access at http://localhost:8084
```

**Build and run with Docker:**
```bash
docker build -t caddy-admin-ui .
docker-compose up -d
```

**View logs:**
```bash
docker logs -f caddy-admin-ui
```

## Architecture

### Core Components

1. **main.go** - Monolithic Go application containing:
   - HTTP server and route handlers (main.go:689-707)
   - Session-based authentication using gorilla/sessions (main.go:18, main.go:95-108)
   - Service management API endpoints (main.go:388-494)
   - Caddy Admin API proxy (main.go:527-559)
   - Cloudflare DNS integration (main.go:192-300)
   - Service health testing (main.go:302-317)
   - API key management (main.go:48-51, main.go:624-687)

2. **html/index.html** - Single-page frontend application with:
   - Vanilla JavaScript (no framework dependencies)
   - Service CRUD operations via REST API
   - Real-time service testing
   - Modal-based forms for add/edit operations

### Key Data Structures

- **Service** (main.go:25-34): Represents a reverse proxy service with subdomain, port, and metadata
- **User** (main.go:20-23): Authentication credentials (bcrypt hashed)
- **DNSRecord** (main.go:36-41): Cloudflare DNS record structure

### Integration Points

**Caddy Admin API Integration:**
- Constant CADDY_ADMIN_URL (main.go:90) defaults to http://localhost:2019
- Function updateCaddyConfig (main.go:161-190) adds routes to Caddy's HTTP server via API
- Proxy endpoint /caddy-api/* (main.go:527-559) forwards requests to Caddy Admin API

**Cloudflare DNS Integration:**
- Zone: biswas.me (main.go:91)
- CNAME target: anshuman.duckdns.com (main.go:92)
- API token read from environment or /etc/caddy/cloudflare.env (main.go:199-212)
- Zone ID: e4fc98969ca8030635e47c03085169cb (main.go:214)
- Function createDNSRecord (main.go:192-195) creates CNAME records (currently stubbed)
- Function deleteDNSRecord (main.go:197-300) removes DNS records via Cloudflare API

### Authentication Model

- Two-tier authentication:
  - Session-based auth for web UI using requireAuth middleware (main.go:150-159)
  - API key auth for programmatic access using requireAPIKey middleware (main.go:121-148)
- Users initialized with bcrypt-hashed passwords in init() (main.go:95-108)
- Default users: "admin" and "anshuman" with hardcoded passwords (main.go:104-107)
- API keys stored in-memory (main.go:48-51) with generation endpoint at /api/keys (main.go:624-687)

### Service Management Flow

When adding/editing a service:
1. Frontend POST/PUT to /api/services or /api/services/{id}
2. Service validation and ID assignment (main.go:401, main.go:402)
3. DNS record created via createDNSRecord (main.go:409-411)
4. Caddy route added via updateCaddyConfig (main.go:413-415)
5. Service added to in-memory services slice (main.go:417)
6. Frontend refreshes service list

When deleting a service:
1. Frontend DELETE to /api/services/{id}
2. DNS record deleted via deleteDNSRecord (main.go:479-481)
3. Service removed from slice (main.go:483)

### Configuration

Environment variables (see .env.example):
- SESSION_SECRET_KEY: Session encryption key (currently hardcoded in main.go:18)
- ADMIN_PASSWORD, USER_PASSWORD: User credentials (currently hardcoded)
- CADDY_ADMIN_URL: Caddy Admin API endpoint (defaults to localhost:2019)
- CLOUDFLARE_API_TOKEN: API token for DNS operations
- CLOUDFLARE_ZONE_ID: Zone identifier for biswas.me

Domain configuration hardcoded in constants (main.go:89-93):
- CLOUDFLARE_ZONE should be changed to match your domain
- CNAME_TARGET should point to your actual server

## Development Notes

**State Management:**
- All services stored in-memory in services slice (main.go:53-87)
- No persistent database - service data lost on restart
- API keys stored in-memory (main.go:48-51)

**Security Considerations:**
- Session secret key hardcoded as "your-secret-key-here" (main.go:18)
- User passwords hardcoded in init() (main.go:104-107)
- Cloudflare zone ID exposed in code (main.go:214)
- No CSRF protection
- API keys stored in plain text in memory
- Secure flag set to false for cookies (main.go:100)

**Service Testing:**
- Health check endpoint /api/test-service (main.go:496-525)
- Performs HEAD request to https://{service.name} (main.go:304)
- Returns HTTP status code and success boolean

**Frontend Architecture:**
- No build process or bundler required
- Pure HTML/CSS/JavaScript served from html/index.html
- REST API calls using fetch API
- Modal-based UI for forms
- Toast notifications for user feedback

## Docker Configuration

- Multi-stage build: golang:1.25.0-alpine builder → alpine:latest runtime
- Network mode: host (allows access to localhost services)
- Serves on port 8084 (main.go:706)
- HTML files copied to /root/html/ in container
- Watchtower enabled for auto-updates

## Common Customizations

**To change the target domain:**
1. Update CLOUDFLARE_ZONE constant (main.go:91)
2. Update CNAME_TARGET to your server (main.go:92)
3. Update zone ID (main.go:214)
4. Update all references to "biswas.me" in html/index.html

**To add persistence:**
- Replace in-memory services slice with database (e.g., SQLite, PostgreSQL)
- Implement CRUD operations with DB queries
- Add data migration on startup

**To enable actual DNS creation:**
- Implement createDNSRecord function (currently stubbed at main.go:192-195)
- Follow pattern from deleteDNSRecord for Cloudflare API calls

**To secure the application:**
- Move SESSION_SECRET_KEY to environment variable (replace main.go:18)
- Move user credentials to environment or external auth system
- Remove hardcoded passwords from init() (main.go:104-107)
- Enable HTTPS and set cookie Secure flag to true (main.go:100)
- Add CSRF tokens to forms
