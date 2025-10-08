# Redis Connection Pool Optimization - Manual Testing Guide

**Date:** 2025-10-05
**Status:** Ready for Testing
**Environment:** Windows PowerShell

---

## Quick Start (Copy & Paste Commands)

### Step 1: Start the Server

Open PowerShell and run:

```powershell
cd C:\Users\Corbin\development\security\load_tests
.\start-server.ps1
```

**Expected Output:**
```
================================================================================
OPTIMIZED REDIS CONNECTION POOL INITIALIZED
================================================================================
Environment: production
Target Users: 10,000
Workers: 4
Max Connections: 160
Connections per Worker: 40
================================================================================
Optimizations Enabled:
  [OK] Health check interval: 30 seconds
  [OK] Exponential backoff retry (3 attempts)
  [OK] Socket keepalive enabled
  [OK] Connection pool monitoring
================================================================================
[SUCCESS] Redis pool healthy: localhost:6379
```

Leave this window open (server running).

---

### Step 2: Test Server Health

Open a **NEW** PowerShell window and run:

```powershell
cd C:\Users\Corbin\development\security\load_tests
.\test-server.ps1
```

**Expected Output:**
```
================================================================================
POOL HEALTH CHECK
================================================================================
Status:              HEALTHY
Environment:         production
Max Connections:     160
In Use:              0
Available:           160
Utilization:         0.0%

Recommendations:
  - Pool operating optimally.
```

---

### Step 3: Manual Quick Test (Optional)

Test a login request:

```powershell
$body = @{
    email = "test@example.com"
    password = "testpass"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://localhost:8001/auth/login" -Method Post -Body $body -ContentType "application/json"

Write-Host "Access Token: $($response.access_token)" -ForegroundColor Green
```

---

## Alternative: Command-Line Testing (No Scripts)

If the PowerShell scripts don't work, use these direct commands:

### Start Server (CMD or PowerShell)

```cmd
cd C:\Users\Corbin\development\security\load_tests

set DEPLOYMENT_ENV=production
set REDIS_PASSWORD=RLr5E73KjlPcAghcLXjBEdWJzqFVeV3EQ1GyQzqoOxo=

python mock_auth_server_redis_optimized.py
```

### Test Health (New Window)

```powershell
Invoke-RestMethod -Uri http://localhost:8000/health/redis | ConvertTo-Json
```

---

## Troubleshooting

### Error: "Port already in use"

The server script automatically tries ports 8001, 8002. If both are taken:

```powershell
# Find what's using the port
Get-NetTCPConnection -LocalPort 8001

# Kill the process (replace PID)
Stop-Process -Id <PID> -Force
```

### Error: "Redis not responding"

```powershell
# Start Memurai
net start Memurai

# Test Redis
& "C:\Program Files\Memurai\memurai-cli.exe" -a "RLr5E73KjlPcAghcLXjBEdWJzqFVeV3EQ1GyQzqoOxo=" PING
# Should return: PONG
```

### Error: "Module not found"

```powershell
# Install required packages
pip install fastapi uvicorn pyjwt pydantic email-validator redis
```

---

## What to Look For

### ✅ Successful Startup Indicators

1. **Pool initialization message** with 160 connections
2. **"Redis pool healthy" message**
3. **Server listening on port** (8000, 8001, or 8002)
4. **Uvicorn startup logs** showing workers starting

### ✅ Healthy Pool Metrics

- **Utilization: 0-10%** (idle state)
- **In Use: 0-5 connections** (minimal activity)
- **Available: 155-160** (most connections free)
- **Recommendations: "Pool operating optimally"**

---

## Files Created

| File | Purpose |
|------|---------|
| `start-server.ps1` | Start server with environment setup |
| `test-server.ps1` | Check pool health and metrics |
| `REDIS_TESTING_MANUAL.md` | This guide |

---

## Next Steps After Successful Startup

Once the server is running and health checks pass:

1. ✅ **Server is running** - Confirmed via `test-server.ps1`
2. ✅ **Pool is healthy** - 160 connections allocated
3. ✅ **Redis connected** - No connection errors

**You're ready to proceed with:**
- Load testing (if you have Locust installed)
- Integration into production code
- Comparing performance to baseline

---

## Contact Info

- **Documentation:** `C:\Users\Corbin\development\REDIS_POOL_OPTIMIZATION_GUIDE.md`
- **Quick Start:** `C:\Users\Corbin\development\security\load_tests\QUICK_START.md`
- **Session Summary:** `C:\Users\Corbin\development\REDIS_OPTIMIZATION_COMPLETE.md`

---

**All files created and ready!** Run `.\start-server.ps1` to begin. 🚀
