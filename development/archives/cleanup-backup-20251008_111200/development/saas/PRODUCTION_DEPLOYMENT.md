# Catalytic Computing SaaS - Production Deployment Guide

**Version:** 1.0
**Last Updated:** 2025-10-05
**Estimated Time:** 2-4 hours

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Pre-Deployment Checklist](#pre-deployment-checklist)
3. [Environment Setup](#environment-setup)
4. [Database Migration](#database-migration)
5. [Service Configuration](#service-configuration)
6. [Deployment](#deployment)
7. [Post-Deployment Verification](#post-deployment-verification)
8. [Monitoring & Maintenance](#monitoring--maintenance)
9. [Rollback Procedures](#rollback-procedures)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **OS:** Ubuntu 22.04 LTS or similar Linux distribution
- **CPU:** 2+ cores (4+ recommended)
- **RAM:** 4GB minimum (8GB+ recommended)
- **Storage:** 20GB+ SSD
- **Network:** Static IP or domain name with DNS configured

### Required Software

- Python 3.11 or higher
- PostgreSQL 14 or higher
- Redis 6 or higher
- Nginx (for reverse proxy)
- Certbot (for SSL certificates)
- Git

### Required Accounts & Keys

- Domain name (e.g., catalyticcomputing.com)
- SSL certificate (Let's Encrypt recommended)
- Stripe account (for payments)
- SendGrid account OR AWS SES (for email)
- GitHub repository access
- Cloud provider account (AWS, GCP, DigitalOcean, etc.)

---

## Pre-Deployment Checklist

Before deploying, ensure you have:

- [ ] Production server provisioned and accessible via SSH
- [ ] Domain DNS configured to point to server IP
- [ ] PostgreSQL database created
- [ ] Redis server installed and running
- [ ] Firewall configured (ports 80, 443, 22 open)
- [ ] Production secrets generated (see section below)
- [ ] Stripe API keys (live mode)
- [ ] Email provider API key (SendGrid/SES)
- [ ] Backup strategy defined
- [ ] Monitoring system selected (Sentry, CloudWatch, etc.)

### Generate Production Secrets

```bash
# Session secret
python -c "import secrets; print(f'SESSION_SECRET_KEY={secrets.token_hex(32)}')"

# CSRF secret
python -c "import secrets; print(f'CSRF_SECRET_KEY={secrets.token_hex(32)}')"

# Redis password
python -c "import secrets; print(f'REDIS_PASSWORD={secrets.token_urlsafe(32)}')"

# Database password
python -c "import secrets; print(f'DB_PASSWORD={secrets.token_urlsafe(24)}')"
```

### Generate JWT Keys

```bash
cd /path/to/catalytic-saas/security
python generate_keys.py production

# Keys will be generated at:
# - keys/jwt_production_private.pem
# - keys/jwt_production_public.pem
# - keys/api_encryption_production.key
# - keys/db_encryption_production.key

# IMPORTANT: Backup these keys securely!
```

---

## Environment Setup

### 1. Clone Repository

```bash
# SSH to production server
ssh user@your-server.com

# Clone repository
git clone https://github.com/your-org/catalytic-saas.git
cd catalytic-saas

# Checkout production branch (or stable tag)
git checkout main  # or v1.0.0
```

### 2. Configure Environment

```bash
# Copy production template
cp .env.production.template .env.production

# Edit with your production values
nano .env.production
```

**Critical values to configure:**

```bash
# Database
DATABASE_URL=postgresql://username:password@localhost:5432/catalytic_saas_prod

# JWT Keys (absolute paths)
JWT_PRIVATE_KEY_PATH=/home/user/catalytic-saas/security/keys/jwt_production_private.pem
JWT_PUBLIC_KEY_PATH=/home/user/catalytic-saas/security/keys/jwt_production_public.pem

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-secure-redis-password

# URLs
FRONTEND_URL=https://app.catalyticcomputing.com
BACKEND_URL=https://api.catalyticcomputing.com

# Stripe (LIVE keys)
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# SendGrid
SENDGRID_API_KEY=SG.your-api-key
EMAIL_FROM=noreply@catalyticcomputing.com

# Security
CORS_ALLOWED_ORIGINS=https://app.catalyticcomputing.com
SESSION_SECRET_KEY=<generated-secret>
CSRF_SECRET_KEY=<generated-secret>

# App Settings
APP_ENV=production
DEBUG=false
LOG_LEVEL=WARNING
```

### 3. Install Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -c "import fastapi; import sqlalchemy; import redis; print('Dependencies OK')"
```

---

## Database Migration

### 1. Create PostgreSQL Database

```bash
# Login to PostgreSQL
sudo -u postgres psql

# Create database and user
CREATE DATABASE catalytic_saas_prod;
CREATE USER catalytic_user WITH ENCRYPTED PASSWORD 'your-secure-password';
GRANT ALL PRIVILEGES ON DATABASE catalytic_saas_prod TO catalytic_user;

# Exit PostgreSQL
\q
```

### 2. Test Connection

```bash
# Test connection
psql postgresql://catalytic_user:your-secure-password@localhost:5432/catalytic_saas_prod -c "SELECT version();"
```

### 3. Migrate from SQLite (if applicable)

If migrating from development SQLite database:

```bash
# Dry run first
python scripts/migrate_to_postgresql.py \
    --source "sqlite:///path/to/dev/catalytic_saas.db" \
    --target "postgresql://catalytic_user:password@localhost:5432/catalytic_saas_prod" \
    --dry-run

# Create backup
python scripts/migrate_to_postgresql.py \
    --source "sqlite:///path/to/dev/catalytic_saas.db" \
    --target "postgresql://catalytic_user:password@localhost:5432/catalytic_saas_prod" \
    --backup

# Review migration log before proceeding
```

### 4. Initialize Fresh Database

If starting fresh (no migration):

```bash
cd api
python -c "from database.models import Base, engine; from database.session import init_db; init_db(); print('Database initialized')"
```

### 5. Verify Tables

```bash
psql $DATABASE_URL -c "\dt"

# Should show tables:
# - tenants
# - users
# - subscriptions
# - api_keys
# - usage_logs
# - audit_logs
# - webhooks
# - webhook_deliveries
```

---

## Service Configuration

### 1. Configure Redis

```bash
# Edit Redis config
sudo nano /etc/redis/redis.conf

# Set password
requirepass your-secure-redis-password

# Bind to localhost (if on same server)
bind 127.0.0.1

# Restart Redis
sudo systemctl restart redis

# Test connection
redis-cli -a your-secure-redis-password PING
```

### 2. Configure Systemd Service

```bash
# Copy systemd service file
sudo cp /tmp/catalytic-saas.service /etc/systemd/system/

# Or create manually
sudo nano /etc/systemd/system/catalytic-saas.service
```

**Service file contents:**

```ini
[Unit]
Description=Catalytic Computing SaaS API Server
After=network.target postgresql.service redis.service

[Service]
Type=exec
User=your-user
WorkingDirectory=/home/user/catalytic-saas/api
Environment="PATH=/home/user/catalytic-saas/venv/bin:/usr/local/bin:/usr/bin:/bin"
EnvironmentFile=/home/user/catalytic-saas/.env.production
ExecStart=/home/user/catalytic-saas/venv/bin/uvicorn saas_server:app --host 0.0.0.0 --port 8000 --workers 4
ExecReload=/bin/kill -s HUP $MAINPID
Restart=on-failure
RestartSec=10

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/home/user/catalytic-saas

[Install]
WantedBy=multi-user.target
```

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable catalytic-saas

# Don't start yet - will do after nginx setup
```

### 3. Configure Nginx

```bash
# Create nginx config
sudo nano /etc/nginx/sites-available/catalytic-saas
```

**Nginx configuration:**

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name api.catalyticcomputing.com;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS Server
server {
    listen 443 ssl http2;
    server_name api.catalyticcomputing.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/api.catalyticcomputing.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.catalyticcomputing.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req zone=api_limit burst=20 nodelay;

    # Logging
    access_log /var/log/nginx/catalytic-saas-access.log;
    error_log /var/log/nginx/catalytic-saas-error.log;

    # Proxy to FastAPI
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Health check (no rate limiting)
    location /health {
        proxy_pass http://127.0.0.1:8000;
        access_log off;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/catalytic-saas /etc/nginx/sites-enabled/

# Test nginx config
sudo nginx -t

# Don't reload yet - need SSL first
```

### 4. Configure SSL (Let's Encrypt)

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d api.catalyticcomputing.com

# Test auto-renewal
sudo certbot renew --dry-run

# Certificates will auto-renew via cron
```

---

## Deployment

### Automated Deployment (Recommended)

```bash
# Run deployment script
chmod +x scripts/deploy_production.sh
./scripts/deploy_production.sh

# Follow prompts and verify each step
```

### Manual Deployment

If you prefer manual control:

```bash
# 1. Run tests
pytest -v --tb=short

# 2. Start service
sudo systemctl start catalytic-saas

# 3. Check status
sudo systemctl status catalytic-saas

# 4. Reload nginx
sudo systemctl reload nginx

# 5. Check logs
sudo journalctl -u catalytic-saas -f
```

---

## Post-Deployment Verification

### 1. Health Check

```bash
# API health
curl https://api.catalyticcomputing.com/health

# Expected response:
# {"status":"healthy","timestamp":"2025-10-05T12:00:00Z"}
```

### 2. Test Email

```bash
# Run email test
python setup_email.py

# Enter your email address to receive test email
```

### 3. Test Authentication

```bash
# Create test tenant/user via API
curl -X POST https://api.catalyticcomputing.com/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePassword123!",
    "company_name": "Test Company"
  }'

# Login
curl -X POST https://api.catalyticcomputing.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePassword123!"
  }'
```

### 4. Test Stripe Webhook

```bash
# Use Stripe CLI
stripe listen --forward-to https://api.catalyticcomputing.com/webhooks/stripe

# Trigger test event
stripe trigger payment_intent.succeeded
```

### 5. Monitor Logs

```bash
# Application logs
sudo journalctl -u catalytic-saas -f

# Nginx access logs
sudo tail -f /var/log/nginx/catalytic-saas-access.log

# Nginx error logs
sudo tail -f /var/log/nginx/catalytic-saas-error.log

# PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-14-main.log
```

---

## Monitoring & Maintenance

### 1. Setup Sentry (Error Tracking)

```bash
# Add to .env.production
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project-id
SENTRY_ENVIRONMENT=production
SENTRY_TRACES_SAMPLE_RATE=0.1

# Restart service
sudo systemctl restart catalytic-saas
```

### 2. Configure Automated Backups

```bash
# Create backup script
sudo nano /usr/local/bin/backup-catalytic-db.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/var/backups/catalytic-saas"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/catalytic_saas_$TIMESTAMP.sql"

mkdir -p $BACKUP_DIR

# Backup database
pg_dump $DATABASE_URL | gzip > "$BACKUP_FILE.gz"

# Remove backups older than 30 days
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE.gz"
```

```bash
# Make executable
sudo chmod +x /usr/local/bin/backup-catalytic-db.sh

# Add to cron (daily at 2 AM)
sudo crontab -e
```

Add:
```
0 2 * * * /usr/local/bin/backup-catalytic-db.sh >> /var/log/catalytic-backups.log 2>&1
```

### 3. Setup Log Rotation

```bash
sudo nano /etc/logrotate.d/catalytic-saas
```

```
/var/log/catalytic-saas/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        systemctl reload catalytic-saas > /dev/null 2>&1 || true
    endscript
}
```

### 4. Monitoring Dashboard

Setup external monitoring:
- **Uptime:** UptimeRobot, Pingdom
- **Performance:** New Relic, Datadog
- **Errors:** Sentry
- **Logs:** CloudWatch, Loggly

---

## Rollback Procedures

### Quick Rollback

```bash
# Stop service
sudo systemctl stop catalytic-saas

# Restore from backup
BACKUP_FILE="/var/backups/catalytic-saas/catalytic_saas_YYYYMMDD_HHMMSS.sql.gz"
gunzip < $BACKUP_FILE | psql $DATABASE_URL

# Checkout previous version
cd /home/user/catalytic-saas
git checkout <previous-tag>

# Restart service
sudo systemctl start catalytic-saas
```

### Database Rollback Only

```bash
# Restore database from backup
psql $DATABASE_URL < /path/to/backup.sql

# Restart service
sudo systemctl restart catalytic-saas
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u catalytic-saas -n 100

# Common issues:
# 1. Database connection - verify DATABASE_URL
# 2. Redis connection - verify REDIS_HOST and REDIS_PASSWORD
# 3. Port in use - check with: sudo lsof -i :8000
# 4. File permissions - check /home/user/catalytic-saas ownership
```

### Database Connection Issues

```bash
# Test connection
psql $DATABASE_URL -c "SELECT 1;"

# Check PostgreSQL is running
sudo systemctl status postgresql

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-14-main.log
```

### Redis Connection Issues

```bash
# Test connection
redis-cli -a $REDIS_PASSWORD PING

# Check Redis is running
sudo systemctl status redis

# Check Redis logs
sudo tail -f /var/log/redis/redis-server.log
```

### SSL Certificate Issues

```bash
# Test certificate
sudo certbot certificates

# Renew certificate
sudo certbot renew --force-renewal
```

### Performance Issues

```bash
# Check system resources
htop

# Check database connections
psql $DATABASE_URL -c "SELECT COUNT(*) FROM pg_stat_activity;"

# Check slow queries
psql $DATABASE_URL -c "SELECT query, calls, total_time FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;"
```

---

## Support

For issues and questions:
- **Documentation:** [https://docs.catalyticcomputing.com](https://docs.catalyticcomputing.com)
- **GitHub Issues:** [https://github.com/your-org/catalytic-saas/issues](https://github.com/your-org/catalytic-saas/issues)
- **Email:** support@catalyticcomputing.com

---

**End of Production Deployment Guide**
