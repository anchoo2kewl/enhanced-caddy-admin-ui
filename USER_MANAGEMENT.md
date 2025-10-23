# User Management Guide

## Overview

The Caddy Admin UI now includes comprehensive user management with SQLite-based storage, role-based access control, and both web UI and command-line interfaces.

## Features

- **SQLite Database Storage**: Persistent user data stored in `./data/caddy-admin.db`
- **Role-Based Access**: Admin and regular user roles
- **Password Management**: Secure bcrypt password hashing with change functionality
- **Web UI**: Full user management interface for administrators
- **CLI Tool**: Command-line tool for user management
- **Default Admin**: Automatically created on first run

## Default Credentials

On first startup, a default admin user is automatically created:

- **Username**: `admin`
- **Password**: `admin123!`

**⚠️ IMPORTANT**: Change this password immediately after first login!

## Web UI Management

### For All Users

#### Change Password
1. Click "🔐 Change Password" button
2. Enter current password
3. Enter new password (minimum 8 characters)
4. Confirm new password
5. Click "Change Password"

### For Administrators

Admin users have access to the "👥 Manage Users" button, which provides:

#### View All Users
- List of all users with username, admin status, and creation date
- Visual indicators for admin vs regular users

#### Add New User
1. Click "👥 Manage Users"
2. Click "➕ Add New User"
3. Enter username
4. Enter password (minimum 8 characters)
5. Optionally check "Administrator" to grant admin rights
6. Click "Create User"

#### Promote/Demote Admin
- Click "⬆️ Make Admin" to promote a regular user
- Click "⬇️ Revoke Admin" to demote an admin user
- The last admin cannot be demoted (protection)

#### Delete User
1. Click "🗑️ Delete" next to the user
2. Confirm the deletion
- The last admin user cannot be deleted (protection)

## Command-Line Management

### Using the CLI Tool

#### Inside Docker Container

```bash
# Use the wrapper script
./user.sh [command] [options]

# Or access container directly
docker exec -it caddy-admin-ui ./usermgmt [command] [options]
```

#### Direct Usage (Local Development)

```bash
# Build the CLI tool
go build -o usermgmt usermgmt.go

# Run commands
./usermgmt [command] [options]
```

### CLI Commands

#### List All Users

```bash
./user.sh list
```

Output:
```
ID  USERNAME   ADMIN  CREATED             UPDATED
---  --------  -----  -------             -------
1    admin     Yes    2025-10-23 14:30    2025-10-23 14:30
2    john      No     2025-10-23 15:00    2025-10-23 15:00
```

#### Add New User

**Interactive (prompts for password):**
```bash
./user.sh add -username john
```

**With password specified:**
```bash
./user.sh add -username john -password secretpass123
```

**Add as administrator:**
```bash
./user.sh add -username jane -admin
```

#### Delete User

```bash
./user.sh delete -username john
```

Protection: Cannot delete the last admin user.

#### Reset Password

**Interactive (prompts for new password):**
```bash
./user.sh reset-password -username john
```

**With password specified:**
```bash
./user.sh reset-password -username john -password newpass123
```

#### Get Help

```bash
./user.sh help
```

## API Endpoints

### User Management (Admin Only)

#### GET /api/users
List all users

**Response:**
```json
[
  {
    "id": 1,
    "username": "admin",
    "is_admin": true,
    "created_at": "2025-10-23T14:30:00Z",
    "updated_at": "2025-10-23T14:30:00Z"
  }
]
```

#### POST /api/users
Create a new user

**Request:**
```json
{
  "username": "john",
  "password": "secret123",
  "is_admin": false
}
```

#### GET /api/users/{id}
Get user by ID

#### PUT /api/users/{id}
Update user (toggle admin status)

**Request:**
```json
{
  "is_admin": true
}
```

#### DELETE /api/users/{id}
Delete a user

### Password Management (Any Authenticated User)

#### POST /api/change-password
Change current user's password

**Request:**
```json
{
  "current_password": "oldpass",
  "new_password": "newpass123"
}
```

### Current User Info

#### GET /api/me
Get current authenticated user's information

**Response:**
```json
{
  "id": 1,
  "username": "admin",
  "is_admin": true,
  "created_at": "2025-10-23T14:30:00Z",
  "updated_at": "2025-10-23T14:30:00Z"
}
```

## Database Schema

### Users Table

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,  -- bcrypt hashed
    is_admin BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Database Location

- **Docker**: `/root/data/caddy-admin.db` (mounted to `./data/` on host)
- **Local**: `./data/caddy-admin.db`

## Security Features

1. **Password Hashing**: All passwords stored using bcrypt
2. **Minimum Password Length**: 8 characters enforced
3. **Last Admin Protection**: Cannot delete or demote the last administrator
4. **Session-Based Auth**: Uses secure HTTP-only cookies
5. **Role-Based Access**: Admin-only endpoints properly protected
6. **Password Never Exposed**: Passwords never returned in API responses

## Common Tasks

### Initial Setup

```bash
# Deploy the application
./deploy.sh

# Login with default credentials
# Username: admin
# Password: admin123!

# Change the default password immediately
# Use the web UI: Click "Change Password"
```

### Add Team Members

**Via Web UI:**
1. Login as admin
2. Click "👥 Manage Users"
3. Click "➕ Add New User"
4. Enter details and create

**Via CLI:**
```bash
./user.sh add -username alice -admin
./user.sh add -username bob
```

### Promote User to Admin

**Via Web UI:**
1. Click "👥 Manage Users"
2. Find the user
3. Click "⬆️ Make Admin"

**Via CLI:**
Not directly supported. Delete and recreate with `-admin` flag, or use the web UI.

### Reset Forgotten Password

**Must use CLI (requires server access):**
```bash
./user.sh reset-password -username alice
```

### Backup User Database

```bash
# The database is in ./data/caddy-admin.db
cp ./data/caddy-admin.db ./data/caddy-admin.db.backup

# Or backup entire data directory
tar -czf data-backup.tar.gz ./data/
```

### Restore from Backup

```bash
# Stop the application
docker-compose down

# Restore database
cp ./data/caddy-admin.db.backup ./data/caddy-admin.db

# Restart
docker-compose up -d
```

## Troubleshooting

### Can't Login After Changing Password

**Solution**: Reset password via CLI
```bash
./user.sh reset-password -username admin
```

### Database Locked Error

**Cause**: Multiple processes accessing the database

**Solution**:
```bash
# Check if multiple containers are running
docker ps | grep caddy-admin

# Stop all instances
docker-compose down

# Start single instance
docker-compose up -d
```

### Lost Admin Access

**Solution**: Create new admin via CLI
```bash
./user.sh add -username newadmin -admin
```

### Database File Not Found

**Cause**: Database directory not created or mounted

**Solution**:
```bash
# Create data directory
mkdir -p ./data

# Restart application (will create database)
docker-compose restart
```

### Permission Denied on CLI Tool

**Solution**:
```bash
chmod +x ./user.sh
```

## Best Practices

1. **Change Default Password**: Immediately change the default admin password
2. **Limit Admin Users**: Only grant admin rights to trusted users
3. **Regular Backups**: Backup the database regularly
4. **Strong Passwords**: Enforce minimum 12-character passwords
5. **Audit Users**: Regularly review user list and remove inactive users
6. **Secure Database**: Ensure `./data/` directory has proper permissions
7. **Monitor Access**: Check logs for failed login attempts

## Migration from Hardcoded Users

If upgrading from the previous version with hardcoded users:

1. **Backup**: Save your old configuration
2. **Deploy**: Run the new version
3. **Login**: Use default admin credentials (`admin` / `admin123!`)
4. **Recreate Users**: Add your previous users via web UI or CLI
5. **Grant Admin**: Promote users as needed
6. **Change Password**: Update to your preferred password
7. **Test**: Verify all users can login

## Example Workflows

### Onboarding New Team Member

```bash
# 1. Create user account
./user.sh add -username newuser

# 2. Send credentials to user
# Username: newuser
# Password: [provided during creation]
# URL: https://caddy.biswas.me

# 3. User logs in and changes password
# via "Change Password" button
```

### Offboarding Team Member

```bash
# Via CLI
./user.sh delete -username olduser

# Or via web UI
# 1. Click "Manage Users"
# 2. Find user
# 3. Click "Delete"
```

### Emergency Admin Access

```bash
# Create temporary admin account
./user.sh add -username emergency -password temp123! -admin

# After issue resolved
./user.sh delete -username emergency
```

## Support

For issues:
- Check application logs: `./manage.sh logs-tail`
- Verify database exists: `ls -la ./data/`
- Test database access: `./user.sh list`
- Review this documentation

## API Examples

### Using curl

```bash
# Login and get session cookie
curl -c cookies.txt -X POST http://localhost:8084/login \
  -d "username=admin&password=admin123!"

# List users (admin only)
curl -b cookies.txt http://localhost:8084/api/users

# Create user (admin only)
curl -b cookies.txt -X POST http://localhost:8084/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test1234","is_admin":false}'

# Change own password
curl -b cookies.txt -X POST http://localhost:8084/api/change-password \
  -H "Content-Type: application/json" \
  -d '{"current_password":"admin123!","new_password":"newpass123"}'
```
