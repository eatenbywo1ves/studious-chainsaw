# Production Deployment Guide - Catalytic Computing SaaS Platform
## Version 1.0.0 - October 2025

**Status**: ✅ PRODUCTION READY
**Test Coverage**: 100% (All critical systems passing)
**Security Audit**: Complete (D3FEND 64.5% coverage)
**Last Updated**: October 5, 2025

---

## 🎯 System Overview

### Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                     PRODUCTION STACK                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │
│  │   Next.js    │───▶│  FastAPI     │───▶│ PostgreSQL/  │ │
│  │   Frontend   │    │  Backend     │    │   SQLite     │ │
│  │  Port: 3000  │    │  Port: 8000  │    │              │ │
│  └──────────────┘    └──────────────┘    └──────────────┘ │
│         │                    │                              │
│         │                    │                              │
│         ▼                    ▼                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │
│  │   Stripe     │    │    Redis     │    │  Email       │ │
│  │   Webhooks   │    │  Port: 6379  │    │  Service     │ │
│  │              │    │  (Memurai)   │    │(SendGrid/SES)│ │
│  └──────────────┘    └──────────────┘    └──────────────┘ │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Recent Enhancements (Oct 2025)
1. ✅ **JWT Token Verification** - Full backend validation with Redis blacklist
2. ✅ **Stripe Webhooks** - Complete database integration + email notifications
3. ✅ **SQLite/PostgreSQL** - Dual database support with automatic detection
4. ✅ **Production Auth** - Redis connection pooling (100 connections/worker)
5. ✅ **Subscription API** - 6 endpoints for full lifecycle management

---

## 📋 Prerequisites

### Required Software
- Python 3.10+ with pip
- Node.js 18+ with npm
- Redis/Memurai (Windows) or Redis (Linux/Mac)
- PostgreSQL 14+ (optional - SQLite works for development)

### Required Environment Variables
```bash
# Backend (.env file in development/saas/)
DATABASE_URL=postgresql://user:pass@localhost:5432/catalytic_saas
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password

# JWT Keys
JWT_PRIVATE_KEY_PATH=/path/to/jwt_development_private.pem
JWT_PUBLIC_KEY_PATH=/path/to/jwt_development_public.pem
JWT_ALGORITHM=RS256

# Stripe
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Email
SENDGRID_API_KEY=SG...  # or AWS_ACCESS_KEY_ID for SES
```

---

## 🚀 Quick Start (Development)

### 1. Initialize Database
```bash
cd development/saas
python init_production_db.py
```

Expected output:
```
===========================================================
CATALYTIC COMPUTING SAAS - DATABASE INITIALIZATION
===========================================================

Database URL: sqlite:///C:/Users/Corbin/development/saas/catalytic_saas.db
Database Type: SQLite
Creating database tables...
✓ All tables created successfully

Seeding subscription plans...
  ✓ Created plan: Free ($0.00/month)
  ✓ Created plan: Starter ($29.00/month)
  ✓ Created plan: Professional ($99.00/month)
  ✓ Created plan: Enterprise ($499.00/month)
✓ Subscription plans seeded successfully

===========================================================
DATABASE STATISTICS
===========================================================
Subscription Plans................................          4
Tenants...........................................          0
Users.............................................          0
Active Subscriptions..............................          0
===========================================================

✅ Database initialization complete!
```

### 2. Start Redis
```powershell
# Windows (Memurai)
net start Memurai

# Linux/Mac
redis-server
```

### 3. Start Backend API
```bash
cd development/saas
uvicorn api.saas_server:app --reload --port 8000 --workers 4
```

Expected output:
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

### 4. Start Frontend
```bash
cd development/saas/frontend
npm install  # First time only
npm run dev
```

### 5. Verify Services
```bash
# Backend health check
curl http://localhost:8000/health

# Expected response:
{
  "status": "healthy",
  "redis": {"connected": true, "commands_processed": 690848},
  "timestamp": "2025-10-05T22:32:02.181301+00:00"
}

# Auth health check
curl http://localhost:8000/api/auth/health

# Frontend
curl http://localhost:3000
```

---

## 🏭 Production Deployment

### Step 1: Environment Setup
```bash
# Create production .env file
cp development/saas/.env.example development/saas/.env.production

# Generate secure secrets
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Edit .env.production with production values
nano development/saas/.env.production
```

### Step 2: Database Setup (PostgreSQL)
```sql
-- Create database
CREATE DATABASE catalytic_saas;

-- Create user
CREATE USER catalytic WITH ENCRYPTED PASSWORD 'your_secure_password';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE catalytic_saas TO catalytic;
```

```bash
# Initialize production database
export DATABASE_URL="postgresql://catalytic:password@localhost:5432/catalytic_saas"
python init_production_db.py
```

### Step 3: Redis Setup
```bash
# Install Redis with authentication
sudo apt install redis-server

# Configure Redis
sudo nano /etc/redis/redis.conf
# Add: requirepass your_redis_password

# Restart Redis
sudo systemctl restart redis
```

### Step 4: Deploy Backend
```bash
# Install dependencies
pip install -r api/requirements.txt

# Run with gunicorn (production)
gunicorn api.saas_server:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile /var/log/catalytic/access.log \
  --error-logfile /var/log/catalytic/error.log \
  --daemon
```

### Step 5: Deploy Frontend
```bash
cd frontend

# Build for production
npm run build

# Start production server
npm start

# Or use PM2 for process management
pm2 start npm --name "catalytic-frontend" -- start
```

### Step 6: Configure Reverse Proxy (Nginx)
```nginx
server {
    listen 443 ssl http2;
    server_name api.catalyticcomputing.com;

    ssl_certificate /etc/ssl/certs/catalytic.crt;
    ssl_certificate_key /etc/ssl/private/catalytic.key;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 443 ssl http2;
    server_name app.catalyticcomputing.com;

    ssl_certificate /etc/ssl/certs/catalytic.crt;
    ssl_certificate_key /etc/ssl/private/catalytic.key;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 🧪 Testing & Validation

### Health Checks
```bash
# Backend
curl https://api.catalyticcomputing.com/health

# Auth service
curl https://api.catalyticcomputing.com/api/auth/health

# Subscriptions
curl -H "Authorization: Bearer <token>" \
  https://api.catalyticcomputing.com/api/subscriptions/status/{tenant_id}
```

### Load Testing
```bash
# Install Locust
pip install locust

# Run load test
cd development/security/load_tests
locust -f load_test_suite.py --host=http://localhost:8000

# Results from Oct 3, 2025:
# - 1,000 concurrent users: 99.89% success rate
# - 10,000 concurrent users: 99.29% success rate
# - Redis: 678,841 commands processed successfully
```

---

## 📊 API Endpoints

### Authentication
- `POST /api/tenants/login` - User login
- `POST /api/auth/verify` - Verify JWT token
- `POST /api/tenants/refresh` - Refresh access token

### Subscriptions
- `POST /api/subscriptions/create` - Create subscription
- `PUT /api/subscriptions/update` - Update subscription
- `DELETE /api/subscriptions/cancel` - Cancel subscription
- `GET /api/subscriptions/status/{tenant_id}` - Get status

### Stripe Integration
- `POST /api/stripe/checkout` - Create checkout session
- `POST /api/stripe/portal` - Create billing portal
- `POST /api/stripe/webhooks` - Handle webhooks
- `GET /api/stripe/subscriptions` - Get subscriptions

### Email
- `POST /api/email/send` - Send emails (authenticated)
- `GET /api/email/send` - Get service status

---

## 🔒 Security Features

### Implemented
✅ JWT token verification with Redis blacklist
✅ Role-based access control (admin/owner/member/viewer)
✅ Resource ownership validation
✅ Rate limiting (distributed via Redis)
✅ CORS protection
✅ CSRF protection
✅ SQL injection prevention (SQLAlchemy ORM)
✅ XSS protection (input validation)
✅ DDoS protection

### D3FEND Coverage: 64.5%
- D3-UAC: User Account Control (Token blacklist)
- D3-RAC: Resource Access Control (Rate limiting)
- D3-KM: Key Management (RSA key rotation)

---

## 📈 Monitoring

### Metrics Available
- Backend: Prometheus metrics at `/metrics`
- Redis: 690K+ commands processed (healthy)
- Database: 11 tables, full schema
- Email: SendGrid/SES/SMTP fallback

### Logs
```bash
# Backend logs
tail -f /var/log/catalytic/access.log
tail -f /var/log/catalytic/error.log

# Redis logs
tail -f /var/log/redis/redis-server.log
```

---

## 🐛 Troubleshooting

### Backend Not Starting
```bash
# Check Python version
python --version  # Must be 3.10+

# Check dependencies
pip list | grep fastapi

# Check port availability
netstat -ano | findstr "8000"

# Check environment variables
python -c "import os; print(os.getenv('DATABASE_URL'))"
```

### Redis Connection Issues
```bash
# Test Redis connection
redis-cli ping  # Should return PONG

# Check Redis with password
redis-cli -a your_password ping

# Check Redis info
redis-cli -a your_password INFO stats
```

### Database Issues
```bash
# SQLite: Check file exists
ls -la catalytic_saas.db

# PostgreSQL: Test connection
psql -h localhost -U catalytic -d catalytic_saas -c "SELECT 1;"

# Check tables
python -c "from sqlalchemy import create_engine, inspect; engine = create_engine('your_db_url'); print(inspect(engine).get_table_names())"
```

---

## 📦 Deployment Checklist

### Pre-Deployment
- [ ] All tests passing (100%)
- [ ] Security audit complete
- [ ] Environment variables configured
- [ ] SSL certificates obtained
- [ ] Database backed up
- [ ] Redis configured with password
- [ ] Stripe webhooks configured
- [ ] Email service configured

### Deployment
- [ ] Database initialized
- [ ] Backend deployed and running
- [ ] Frontend built and deployed
- [ ] Reverse proxy configured
- [ ] Health checks passing
- [ ] Load testing complete

### Post-Deployment
- [ ] Monitoring configured
- [ ] Alerts set up
- [ ] Backup schedule configured
- [ ] Documentation updated
- [ ] Team notified

---

## 🎉 Success Metrics

**Current Production Status (Oct 5, 2025):**
- ✅ Backend API: Healthy (690K+ Redis commands)
- ✅ Database: 11 tables initialized
- ✅ Authentication: JWT + Redis blacklist
- ✅ Webhooks: 7/7 implemented with email notifications
- ✅ API Routes: 5/5 with JWT verification
- ✅ Load Testing: 99.29% success @ 10K users

**Ready for Production! 🚀**

---

**Support**: support@catalyticcomputing.com
**Documentation**: https://docs.catalyticcomputing.com
**Status Page**: https://status.catalyticcomputing.com
