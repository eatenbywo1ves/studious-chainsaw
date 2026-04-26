# Health Endpoint Fix - Quick Reference

## Problem
- Health endpoint shows `"database": "unhealthy"`
- Missing `"vault"` key in response
- Database actually works fine

## Root Cause
SQLAlchemy 2.0+ requires `text()` wrapper: `db.execute(text("SELECT 1"))`

## Fix Status
✅ Code fixed in: `C:\Users\Corbin\development\saas\api\saas_server.py` (lines 831-836)
⏳ Docker build pending (network issues)
⏳ Deployment pending

## Quick Deploy

### Windows PowerShell
```powershell
cd C:\Users\Corbin\development\saas
.\deploy-health-fix.ps1
```

### Linux/WSL/Git Bash
```bash
cd /c/Users/Corbin/development/saas
chmod +x deploy-health-fix.sh
./deploy-health-fix.sh
```

### Manual Steps
```bash
# 1. Build
cd /c/Users/Corbin/development
docker build -f saas/Dockerfile -t catalytic-saas:staging .

# 2. Deploy (kind)
kind load docker-image catalytic-saas:staging --name catalytic-cluster
kubectl set image deployment/saas-api saas-api=catalytic-saas:staging -n catalytic-staging
kubectl rollout status deployment/saas-api -n catalytic-staging

# 3. Verify
kubectl exec -n catalytic-staging deployment/saas-api -- curl http://localhost:8000/health
```

## Expected Result
```json
{
  "status": "healthy",
  "database": "healthy",  ← Should be "healthy" now
  "vault": "unavailable",  ← Now included
  "gpu_available": false,
  "timestamp": "2025-11-07T23:45:00.123456"
}
```

## Test Database Directly
```bash
kubectl exec -n catalytic-staging deployment/saas-api -- python3 -c "
from sqlalchemy import text
from database.connection import get_db
db = next(get_db())
print(db.execute(text('SELECT 1')).fetchone())
"
# Expected: (1,)
```

## Files Modified
- `C:\Users\Corbin\development\saas\api\saas_server.py` - Fixed health endpoint

## Files Created
- `C:\Users\Corbin\HEALTH_ENDPOINT_FIX_SUMMARY.md` - Full report
- `C:\Users\Corbin\development\saas\deploy-health-fix.sh` - Bash deployment script
- `C:\Users\Corbin\development\saas\deploy-health-fix.ps1` - PowerShell deployment script
- `C:\Users\Corbin\HEALTH_FIX_QUICK_REFERENCE.md` - This file

## Key Changes in Code
```python
# Added import
from sqlalchemy import text

# Changed this:
db.execute("SELECT 1")

# To this:
db.execute(text("SELECT 1"))
```

## Current Environment
- Pod: `saas-api-9659c55f8-s59v7`
- Namespace: `catalytic-staging`
- Image: `catalytic-saas:staging` (7 days old - needs rebuild)
- SQLAlchemy: 2.0.17
