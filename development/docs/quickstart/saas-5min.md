# SaaS Platform - 5 Minute Quick Start

**Goal:** Get the multi-tenant SaaS platform running locally in 5 minutes.

**Prerequisites:** Docker, Docker Compose, 8GB RAM

---

## ⚡ Quick Start (Copy & Paste)

```bash
# 1. Navigate to development directory
cd development

# 2. Set up environment (copy template)
cp .env.example .env

# 3. Start PostgreSQL and Redis
docker compose --profile saas up postgres redis -d

# 4. Wait 10 seconds for databases to initialize
sleep 10

# 5. Run database migrations
docker compose --profile saas run --rm saas-api python -m saas.database.migrate

# 6. Start the SaaS platform
docker compose --profile saas up -d

# 7. Verify it's running
curl http://localhost:8000/health
```

**Expected output:** `{"status": "healthy", "database": "connected", "redis": "connected"}`

---

## 🎯 What You Just Built

| Service | URL | Purpose |
|---------|-----|---------|
| **API** | http://localhost:8000 | FastAPI backend |
| **Frontend** | http://localhost:3000 | Web interface |
| **Docs** | http://localhost:8000/docs | Interactive API documentation |
| **PostgreSQL** | localhost:5432 | Multi-tenant database |
| **Redis** | localhost:6379 | Session cache + token blacklist |

---

## ✅ Test It Works

### 1. Create a test user
```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!",
    "organization": "TestOrg"
  }'
```

### 2. Login
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!"
  }'
```

**Expected:** You'll receive a JWT token in the response.

### 3. Check health endpoint
```bash
curl http://localhost:8000/health/redis
```

**Expected:** `{"status": "healthy", "pool_available": true}`

---

## 🚀 Next Steps

**Now that it's running:**

1. **Explore the API:** Visit http://localhost:8000/docs for interactive documentation
2. **Understand the architecture:** Read [SaaS Architecture](../architecture/saas-architecture.md)
3. **Configure for production:** See [Production Deployment Guide](../saas/PRODUCTION_DEPLOYMENT.md)
4. **Monitor performance:** See [Monitoring Guide](../monitoring/README.md)

---

## 🛑 Stop Services

```bash
docker compose --profile saas down
```

To remove data (fresh start):
```bash
docker compose --profile saas down -v
```

---

## 🔧 Common Issues

| Problem | Solution |
|---------|----------|
| Port 8000 already in use | Change `PORT=8000` to `PORT=8001` in `.env` |
| PostgreSQL connection failed | Wait 30 seconds, databases take time to initialize |
| Redis connection failed | Check Redis is running: `docker compose ps` |
| Migration errors | Ensure PostgreSQL is ready: `docker compose logs postgres` |

---

## 📚 Key Features

- ✅ **Multi-tenant:** Row-level security (RLS) with PostgreSQL
- ✅ **Authentication:** JWT with RS256 signing
- ✅ **Session Management:** Redis connection pooling (100% success @ 1K users)
- ✅ **Payments:** Stripe integration with webhooks
- ✅ **Email:** SendGrid integration
- ✅ **Monitoring:** Prometheus metrics + health endpoints

---

## 🎓 Learn More

- **Full Guide:** [SaaS Deployment Guide](../guides/saas-deployment-guide.md)
- **Architecture:** [SaaS Architecture](../architecture/saas-architecture.md)
- **Redis Optimization:** [Redis Pool Guide](../guides/REDIS_POOL_OPTIMIZATION_GUIDE.md)
- **Security:** [JWT Consolidation Analysis](../specifications/JWT_CONSOLIDATION_ANALYSIS.md)

---

**Time to complete:** ⏱️ 3-5 minutes
**Difficulty:** 🟢 Beginner
**Last updated:** 2025-10-08

[← Back to Index](../INDEX.md) | [Architecture →](../architecture/saas-architecture.md)
