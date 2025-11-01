# Caddy Admin UI

A modern, feature-rich web interface for managing Caddy reverse proxy with integrated Cloudflare DNS management, user authentication, and two-factor authentication.

## Overview

Caddy Admin UI is a self-hosted administration interface built with Go that simplifies managing your Caddy reverse proxy server. It provides an intuitive web dashboard for managing services, configuring reverse proxy routes, syncing DNS records with Cloudflare, and managing users with enterprise-grade security features.

### Key Features

- **Service Management** - Visual dashboard for all your reverse-proxied services
- **Automatic Caddy Configuration** - Dynamically configures Caddy routes via the Admin API
- **Cloudflare DNS Integration** - Automated DNS record creation and deletion
- **User Management** - Multi-user support with role-based access control (admin/regular users)
- **Configuration Management** - Built-in settings UI to manage Cloudflare credentials and DNS defaults
- **Two-Factor Authentication (2FA)** - TOTP-based 2FA with QR code setup
- **API Key Authentication** - Generate API keys for programmatic access
- **Service Testing** - Built-in health checks for your services
- **Protocol Service Support** - Distinguish between web services and protocol services (e.g., RustDesk, game servers)
- **Session Management** - Secure cookie-based sessions with HTTPS support
- **Modern UI** - Clean, responsive interface with service cards and modals

## Screenshots

The interface provides:
- Service cards with status indicators
- One-click DNS sync and Caddy configuration
- User management for admins
- 2FA setup with QR codes
- API key management
- Service health testing

## Architecture

```
┌─────────────────┐
│   Browser UI    │
└────────┬────────┘
         │ HTTPS
         ▼
┌─────────────────┐      ┌──────────────────┐
│  Caddy Admin UI │◄────►│  Caddy Server    │
│   (Port 8084)   │      │  (Admin API)     │
└────────┬────────┘      └──────────────────┘
         │
         │ API Calls
         ▼
┌─────────────────┐
│  Cloudflare DNS │
└─────────────────┘
```

## Prerequisites

- Docker and Docker Compose
- Caddy server with Admin API enabled (default port 2019)
- Cloudflare account with API token
- A domain managed by Cloudflare

## Quick Start

### 1. Clone and Configure

```bash
cd /opt/stacks/caddy
cp .env.example .env
```

### 2. Configure Environment Variables

Edit `.env` with your Cloudflare credentials:

```bash
# Cloudflare Configuration
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token_here
CLOUDFLARE_ZONE_ID=your_cloudflare_zone_id_here
CNAME_TARGET=your-target-domain.example.com

# Caddy Admin API URL (optional, defaults to http://localhost:2019)
CADDY_ADMIN_URL=http://localhost:2019
```

**Getting Cloudflare Credentials:**

1. **API Token**: Cloudflare Dashboard → My Profile → API Tokens → Create Token
   - Use "Edit zone DNS" template
   - Grant permissions: Zone.DNS (Edit)

2. **Zone ID**: Cloudflare Dashboard → Select your domain → Overview (right sidebar)

3. **CNAME Target**: The domain/hostname your DNS records should point to (e.g., your DuckDNS domain or server IP)

### 3. Deploy

```bash
docker compose up -d
```

The application will be available at `http://localhost:8084`

### 4. Create First User

```bash
# Create an admin user
./user.sh add admin_username

# Or use the Docker exec method
docker exec -it caddy-admin-ui ./usermgmt add admin_username
```

Follow the prompts to set a password. The first user should be an admin.

## Configuration

### Service Configuration

Services are defined in `main.go`. Each service includes:

```go
{
    ID:            1,
    Name:          "myapp.example.com",
    Subdomain:     "myapp",
    Port:          "8080",
    DestinationIP: "localhost",  // or specific IP like "192.168.1.100"
    Description:   "My Application",
    Status:        "running",
    Icon:          "🚀",
    Category:      "Apps",
    IsWebService:  true,  // false for protocol services (RustDesk, etc.)
}
```

**Service Types:**
- **Web Services** (`IsWebService: true`) - HTTP/HTTPS services that can be reverse-proxied
- **Protocol Services** (`IsWebService: false`) - Custom protocol services that only need DNS

### Caddy Requirements

Your Caddy server must have the Admin API enabled. In your Caddyfile:

```
{
    admin 0.0.0.0:2019
}
```

Or via JSON config:
```json
{
  "admin": {
    "listen": "0.0.0.0:2019"
  }
}
```

## Usage

### Managing Services

1. **View Services** - Dashboard shows all configured services
2. **Add Service** - Click "Add New Service" button
3. **Edit Service** - Click "Edit" on any service card
4. **Delete Service** - Click "Delete" (removes Caddy config and DNS)
5. **Sync DNS** - Click "Sync DNS" to create/update Cloudflare DNS records
6. **Test Service** - Click "Test" to check if the service is responding

### Service Workflow

When you add or sync a service:
1. DNS CNAME record is created in Cloudflare (subdomain.yourdomain.com → CNAME_TARGET)
2. Caddy reverse proxy route is configured (for web services)
3. Service becomes accessible via HTTPS (Caddy handles SSL automatically)

### Two-Factor Authentication (2FA)

**Enable 2FA:**
1. Log in to the dashboard
2. Click "Manage 2FA" button
3. Click "Set Up Two-Factor Authentication"
4. Scan QR code with authenticator app (Google Authenticator, Authy, etc.)
5. Or manually enter the code shown
6. Enter verification code to enable

**Login with 2FA:**
1. Enter username and password
2. Enter 6-digit code from authenticator app
3. Access granted

**Disable 2FA:**
1. Click "Manage 2FA"
2. Enter your password to disable

**Supported Authenticator Apps:**
- Google Authenticator
- Authy
- Microsoft Authenticator
- 1Password
- Any TOTP-compatible app

### User Management

**Admin users can:**
- Create/delete users
- Promote/demote admin status
- View all users
- Reset user passwords

**User Management Commands:**

```bash
# Add user (interactive)
./user.sh add username

# Add user with password
./user.sh add username password

# Delete user
./user.sh delete username

# List users
./user.sh list

# Make user admin
./user.sh promote username

# Remove admin privileges
./user.sh demote username
```

### API Keys

Generate API keys for programmatic access:

1. Click "Manage API Keys"
2. Enter key name and click "Generate"
3. Copy the key (shown only once!)
4. Use in API requests:

```bash
curl -H "X-API-Key: your-api-key-here" \
  http://localhost:8084/api/services
```

## API Documentation

### Authentication

**Session-based (Web):**
```bash
# Login returns session cookie
curl -X POST http://localhost:8084/login \
  -d "username=admin&password=yourpass"
```

**API Key:**
```bash
curl -H "X-API-Key: your-key" http://localhost:8084/api/services
```

### Endpoints

#### Services

```bash
# List all services
GET /api/services

# Get specific service
GET /api/services/{id}

# Create service
POST /api/services
{
  "subdomain": "myapp",
  "port": "8080",
  "destination_ip": "localhost",
  "description": "My App",
  "is_web_service": true
}

# Update service
PUT /api/services/{id}

# Delete service
DELETE /api/services/{id}

# Test service health
POST /api/test-service
{"service_name": "myapp.example.com"}
```

#### DNS Management

```bash
# List DNS records
GET /api/dns

# Create DNS record (also configures Caddy for web services)
POST /api/dns
{"subdomain": "myapp"}

# Delete DNS record
DELETE /api/dns
{"subdomain": "myapp"}
```

#### User Management (Admin only)

```bash
# List users
GET /api/users

# Create user
POST /api/users
{"username": "newuser", "password": "securepass", "is_admin": false}

# Update user
PUT /api/users/{id}

# Delete user
DELETE /api/users/{id}
```

#### 2FA Management

```bash
# Setup 2FA (returns QR code as base64)
POST /api/2fa/setup

# Enable 2FA
POST /api/2fa/enable
{"code": "123456"}

# Disable 2FA
POST /api/2fa/disable
{"password": "yourpassword"}

# Verify 2FA code during login
POST /api/2fa/verify
{"code": "123456"}
```

## Security Features

### Authentication & Authorization
- Bcrypt password hashing
- Secure session management with HTTP-only cookies
- Role-based access control (admin/user)
- API key authentication for automation

### Two-Factor Authentication
- TOTP-based (Time-based One-Time Password)
- QR code generation for easy setup
- Manual code entry option
- Secure secret storage (never exposed in API responses)

### Best Practices
- Change default passwords immediately
- Enable 2FA for all admin accounts
- Use strong, unique passwords
- Rotate API keys regularly
- Keep the application behind HTTPS (reverse proxy through Caddy)

## Deployment in Production

### 1. Reverse Proxy Through Caddy

Add to your Caddyfile:

```
caddy.yourdomain.com {
    reverse_proxy localhost:8084
}
```

### 2. Environment Variables

Mount Cloudflare credentials securely:

```yaml
volumes:
  - /etc/caddy/cloudflare.env:/etc/caddy/cloudflare.env:ro
  - ./data:/root/data
```

### 3. Persistent Data

The `./data` directory contains:
- SQLite database (`caddy-admin.db`)
- User credentials
- API keys
- Session data

**Backup regularly:**
```bash
cp /opt/stacks/caddy/data/caddy-admin.db /backups/caddy-admin-$(date +%Y%m%d).db
```

### 4. Updates

```bash
cd /opt/stacks/caddy
git pull
docker compose down
docker compose build --no-cache
docker compose up -d
```

## Troubleshooting

### Service not accessible after sync

**Check:**
1. DNS record created in Cloudflare
2. Caddy route configured: `curl http://localhost:2019/config/apps/http/servers/srv0/routes`
3. Service is running on specified port: `ss -tlnp | grep PORT`
4. Caddy Admin API accessible: `curl http://localhost:2019/config/`

### Favicon not displaying

- Clear browser cache
- Verify `/favicon.svg` is accessible
- Check browser console for errors

### 2FA issues

**Lost 2FA device:**
- Admin can disable 2FA for user via database:
```bash
sqlite3 /opt/stacks/caddy/data/caddy-admin.db \
  "UPDATE users SET two_fa_enabled=0, two_fa_secret='' WHERE username='user';"
```

**Invalid code:**
- Check device time is synced (TOTP requires accurate time)
- Verify you're using the correct account in authenticator app

### DNS sync fails

**Check:**
- Cloudflare API token has DNS edit permissions
- Zone ID is correct
- Domain is active in Cloudflare
- API token not expired

### Can't log in

**Reset password:**
```bash
./user.sh add existing_username new_password
```

## Development

### Project Structure

```
/opt/stacks/caddy/
├── main.go              # Main application
├── usermgmt.go          # CLI user management tool
├── user.sh              # User management wrapper script
├── go.mod               # Go dependencies
├── go.sum               # Dependency checksums
├── Dockerfile           # Multi-stage build
├── compose.yaml         # Docker Compose config
├── .env                 # Environment variables (not in git)
├── .env.example         # Example environment config
├── html/
│   ├── index.html       # Main dashboard UI
│   └── favicon.svg      # Application icon
├── data/
│   └── caddy-admin.db   # SQLite database
└── README.md            # This file
```

### Local Development

```bash
# Install dependencies
go mod download

# Run locally
go run main.go

# Build
go build -o caddy-admin main.go

# Build user management tool
go build -o usermgmt usermgmt.go
```

### Database Schema

```sql
-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT 0,
    two_fa_secret TEXT DEFAULT '',
    two_fa_enabled BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- API Keys table
CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    key TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## Technology Stack

- **Backend:** Go 1.25
- **Database:** SQLite 3
- **Frontend:** Vanilla JavaScript, HTML5, CSS3
- **Authentication:** Session-based + API keys
- **2FA:** TOTP (github.com/pquerna/otp)
- **Password Hashing:** bcrypt
- **Container:** Docker with Alpine Linux
- **Reverse Proxy:** Caddy v2
- **DNS:** Cloudflare API

## Contributing

This is a personal project, but suggestions and improvements are welcome:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is provided as-is for personal use. Modify and adapt as needed for your infrastructure.

## Support

For issues or questions:
- Check the Troubleshooting section
- Review application logs: `docker logs caddy-admin-ui`
- Check Caddy logs for proxy issues
- Verify Cloudflare DNS records in dashboard

## Acknowledgments

- Built with [Caddy](https://caddyserver.com/) - fantastic reverse proxy
- DNS management via [Cloudflare API](https://api.cloudflare.com/)
- 2FA implementation using [pquerna/otp](https://github.com/pquerna/otp)

---

**Version:** 2.0.0
**Last Updated:** October 2025
**Author:** Self-hosted infrastructure enthusiast
