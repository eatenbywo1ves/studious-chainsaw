# Test Infrastructure Quick Reference

## Service Connection Details

| Service | Host | Port | Credentials | Connection String |
|---------|------|------|-------------|-------------------|
| **PostgreSQL** | localhost | 5433 | postgres/postgres | `postgresql://postgres:postgres@localhost:5433/test_saas` |
| **Redis** | localhost | 6380 | test_redis_password | `redis://:test_redis_password@localhost:6380` |
| **Prometheus** | localhost | 9091 | none | `http://localhost:9091` |
| **Grafana** | localhost | 3001 | admin/admin | `http://localhost:3001` |

## Common Commands

### Start Infrastructure
```bash
cd /c/Users/Corbin/development/tests
bash setup-test-infrastructure.sh
```

### Stop Infrastructure
```bash
cd /c/Users/Corbin/development/tests
bash teardown-test-infrastructure.sh
```

### Check Health
```bash
cd /c/Users/Corbin/development/tests
bash health-check.sh
```

### View Service Status
```bash
cd /c/Users/Corbin/development/tests/integration
docker compose -f docker-compose.test.yml ps
```

### View Logs
```bash
# All services
docker compose -f docker-compose.test.yml logs -f

# Specific service
docker logs -f saas-postgres-test
docker logs -f saas-redis-test
```

### Restart Service
```bash
cd /c/Users/Corbin/development/tests/integration
docker compose -f docker-compose.test.yml restart <service-name>
```

## Test Execution

### Load Environment
```bash
cd /c/Users/Corbin/development/tests/integration
source .env.test
```

### Run Integration Tests (87 tests)
```bash
cd /c/Users/Corbin/development/tests/integration
pytest -v --cov=../../saas --cov-report=html
```

## Database Operations

### Access PostgreSQL CLI
```bash
docker exec -it saas-postgres-test psql -U postgres -d test_saas
```

### Access Redis CLI
```bash
docker exec -it saas-redis-test redis-cli -a test_redis_password
```

### Common SQL Commands
```sql
-- List tables
\dt

-- Show table structure
\d table_name

-- Check database size
SELECT pg_size_pretty(pg_database_size('test_saas'));
```

### Common Redis Commands
```bash
# Ping
PING

# Get all keys
KEYS *

# Get memory info
INFO memory

# Flush all data (BE CAREFUL!)
FLUSHALL
```

## Container Management

### List Running Containers
```bash
docker ps --filter "name=saas-*-test"
```

### Stop All Test Containers
```bash
docker stop $(docker ps -q --filter "name=saas-*-test")
```

### Remove All Test Containers
```bash
docker rm $(docker ps -aq --filter "name=saas-*-test")
```

### List Test Volumes
```bash
docker volume ls --filter "name=integration_"
```

### Remove All Test Volumes
```bash
docker volume rm $(docker volume ls -q --filter "name=integration_")
```

## Monitoring

### Prometheus Targets
```bash
curl http://localhost:9091/api/v1/targets
```

### Prometheus Metrics
```bash
curl http://localhost:9091/metrics
```

### Grafana API Health
```bash
curl http://localhost:3001/api/health
```

## Troubleshooting

### Port Already in Use
```bash
# Check what's using a port (Windows)
netstat -ano | grep :5433

# Kill process (use PID from above)
taskkill /PID <pid> /F
```

### Container Won't Start
```bash
# Check logs
docker logs saas-postgres-test

# Inspect container
docker inspect saas-postgres-test

# Remove and recreate
docker compose -f docker-compose.test.yml up -d --force-recreate postgres-test
```

### Database Connection Refused
```bash
# Check if container is running
docker ps | grep postgres

# Check health
docker inspect --format='{{.State.Health.Status}}' saas-postgres-test

# Restart container
docker restart saas-postgres-test
```

### Redis Connection Issues
```bash
# Check if container is running
docker ps | grep redis

# Test connection
docker exec saas-redis-test redis-cli -a test_redis_password ping

# Check memory
docker exec saas-redis-test redis-cli -a test_redis_password INFO memory
```

## File Locations

```
C:\Users\Corbin\development\tests\
├── setup-test-infrastructure.sh      # Start all services
├── teardown-test-infrastructure.sh   # Stop all services
├── health-check.sh                   # Verify all services
└── integration/
    ├── docker-compose.test.yml       # Service definitions
    └── .env.test                      # Environment variables
```

## Environment Variables (for pytest)

```bash
export TEST_DATABASE_URL="postgresql://postgres:postgres@localhost:5433/test_saas"
export TEST_REDIS_URL="redis://:test_redis_password@localhost:6380"
export TEST_API_URL="http://localhost:8001"
export PROMETHEUS_URL="http://localhost:9091"
export GRAFANA_URL="http://localhost:3001"
```

## Service Health Checks

| Service | Health Check Command | Expected Response |
|---------|---------------------|-------------------|
| PostgreSQL | `docker exec saas-postgres-test pg_isready -U postgres` | `accepting connections` |
| Redis | `docker exec saas-redis-test redis-cli -a test_redis_password ping` | `PONG` |
| Prometheus | `curl http://localhost:9091/-/healthy` | `Prometheus Server is Healthy.` |
| Grafana | `curl http://localhost:3001/api/health` | `{"database":"ok",...}` |

## Notes

- **Port Conflicts:** Test services use different ports (5433, 6380, 9091, 3001) to avoid conflicts with production services
- **Data Persistence:** Test data is stored in Docker volumes and persists between runs unless explicitly removed with `--volumes` flag
- **Isolation:** Test network is isolated from production services
- **Cleanup:** Always run teardown script after testing to free up resources

---

**Quick Start:**
```bash
cd /c/Users/Corbin/development/tests
bash setup-test-infrastructure.sh    # Start
bash health-check.sh                 # Verify
bash teardown-test-infrastructure.sh # Stop
```
