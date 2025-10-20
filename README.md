# Enhanced Caddy Admin UI

A modern web-based administration interface for Caddy with integrated service management and DNS functionality.

## Features

- **Service Management**: Add, edit, delete services with automatic DNS records
- **Modern UI**: Responsive design with real-time updates
- **Caddy Integration**: Direct integration with Caddy Admin API
- **DNS Management**: Automatic CNAME record creation via Cloudflare
- **Docker Ready**: Easy deployment with Docker Compose

## Quick Start

1. Clone the repository
2. Copy `.env.example` to `.env` and configure
3. Update domain settings in `main.go`
4. Run with `docker-compose up -d`

## Configuration

Set these environment variables in `.env`:

```
SESSION_SECRET_KEY=your-32-character-secret
ADMIN_PASSWORD=your-secure-password
USER_PASSWORD=your-secure-password
CADDY_ADMIN_URL=http://localhost:2019
```

## Usage

1. Access the UI at your configured domain
2. Login with your credentials
3. Add/manage services through the web interface
4. DNS records and Caddy configuration are updated automatically

## Security

- Always use strong passwords
- Keep API tokens secure
- Use HTTPS in production
- Regularly update dependencies

## License

MIT License
