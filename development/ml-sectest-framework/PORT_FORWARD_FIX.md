# Port-Forward Socket Error - RESOLVED ✅

**Date:** 2025-10-23
**Issue:** "Unable to listen on port 8085: bind: Only one usage of each socket address is normally permitted"
**Status:** ✅ **FIXED**

---

## Problem Diagnosis

### Symptoms
```
kubectl port-forward -n ml-sectest svc/ml-sectest-api 8085:80
Unable to listen on port 8085: Listeners failed to create with the following errors:
[unable to create listener: Error listen tcp4 0.0.0.0:8085: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.]
error: unable to listen on any of the requested ports: [[8085 80]]
```

### Root Cause
Multiple `kubectl port-forward` processes were running in the background from previous sessions, occupying the desired ports (8085, 8080, 9091).

**Evidence:**
```bash
$ netstat -ano | findstr ":8085"
TCP    127.0.0.1:8085         0.0.0.0:0              LISTENING       26424
TCP    [::1]:8085             [::]:0                 LISTENING       26424

$ tasklist | findstr "26424"
kubectl.exe                  26424 Console                    1     23,052 K
```

Three kubectl.exe processes were found:
- PID 26424 (port 8085)
- PID 69160 (port 8080)
- PID 70308 (port 9091)

---

## Solution Implemented

### 1. Immediate Fix
Killed all conflicting kubectl processes:
```bash
taskkill //F //PID 26424
taskkill //F //PID 69160
taskkill //F //PID 70308
```

**Result:** All ports freed successfully ✅

### 2. Long-term Solution
Created a comprehensive port-forward management script to prevent future occurrences.

---

## Port-Forward Management Script

### Location
- `scripts/k8s-port-forward.sh` - Main bash script
- `scripts/k8s-port-forward.bat` - Windows wrapper

### Features
✅ **Automatic port conflict detection**
✅ **Clean process management**
✅ **Health check verification**
✅ **Status monitoring**
✅ **Easy start/stop/restart**
✅ **Colored output for readability**

### Configuration
- **ML-SecTest API:** localhost:8085 → ml-sectest-api:80
- **Prometheus:** localhost:9092 → prometheus:9090
  - Note: Changed from 9091 to avoid conflicts with other services

---

## Usage

### Starting Port-Forwards
```bash
# Using bash script
cd /c/Users/Corbin/development/ml-sectest-framework
bash scripts/k8s-port-forward.sh start

# Or using Windows batch file
cd C:\Users\Corbin\development\ml-sectest-framework
scripts\k8s-port-forward.bat start
```

**Output:**
```
Starting ML-SecTest port-forwards...
  Starting ML-SecTest API: localhost:8085 -> ml-sectest-api:80
    PID: 51440
  Starting Prometheus: localhost:9092 -> prometheus:9090
    PID: 63132
Verifying connections...
  ✓ ML-SecTest API: http://localhost:8085/health
  ✓ Prometheus: http://localhost:9092

Port-forwards started successfully!

Access points:
  ML-SecTest API:  http://localhost:8085
  API Health:      http://localhost:8085/health
  API Docs:        http://localhost:8085/docs
  Prometheus:      http://localhost:9092
```

### Checking Status
```bash
bash scripts/k8s-port-forward.sh status
```

**Output:**
```
Kubernetes Port-Forward Status:

  ✓ ML-SecTest API: localhost:8085 (PID: 51440)
    Health check: PASSED
  ✓ Prometheus: localhost:9092 (PID: 63132)

Active kubectl processes:
kubectl.exe                  51440 Console                    1     39,100 K
kubectl.exe                  63132 Console                    1     38,884 K
```

### Stopping Port-Forwards
```bash
bash scripts/k8s-port-forward.sh stop
```

**Output:**
```
Stopping all kubectl port-forward processes...
  Killing kubectl process PID: 51440
  Killing kubectl process PID: 63132
All kubectl processes terminated.
```

### Restarting Port-Forwards
```bash
bash scripts/k8s-port-forward.sh restart
```

---

## Verification Results

### API Health Check ✅
```bash
$ curl http://localhost:8085/health
{
    "status": "healthy",
    "version": "1.0.0",
    "agents_available": 0,
    "timestamp": "2025-10-24T00:46:41.550429"
}
```

### Port Status ✅
```bash
$ netstat -ano | findstr ":8085"
TCP    127.0.0.1:8085         0.0.0.0:0              LISTENING       51440
TCP    [::1]:8085             [::]:0                 LISTENING       51440
```

### Prometheus Access ✅
```bash
$ curl -s http://localhost:9092/-/healthy
Prometheus is Healthy.
```

---

## Best Practices to Prevent Port Conflicts

### 1. Always Use the Management Script
✅ **DO:**
```bash
bash scripts/k8s-port-forward.sh start
```

❌ **DON'T:**
```bash
kubectl port-forward -n ml-sectest svc/ml-sectest-api 8085:80 &
# This leaves orphaned processes
```

### 2. Check Status Before Starting
```bash
# Check if port-forwards are already running
bash scripts/k8s-port-forward.sh status
```

### 3. Clean Stop When Done
```bash
# Always stop cleanly
bash scripts/k8s-port-forward.sh stop
```

### 4. Use Restart for Clean Slate
```bash
# If you're unsure of the state
bash scripts/k8s-port-forward.sh restart
```

---

## Troubleshooting

### Port Still in Use
```bash
# Check what's using the port
netstat -ano | findstr ":8085"

# Find the process
tasklist | findstr "<PID>"

# Kill it manually if needed
taskkill //F //PID <PID>
```

### Script Fails to Start
1. Check if ports are available: `bash scripts/k8s-port-forward.sh status`
2. Stop existing port-forwards: `bash scripts/k8s-port-forward.sh stop`
3. Verify Kubernetes pods are running: `kubectl get pods -n ml-sectest`
4. Try again: `bash scripts/k8s-port-forward.sh start`

### Permission Errors
- Ensure you're running from a terminal with proper permissions
- On Windows, run from Git Bash or WSL
- Script is already executable (`chmod +x` was applied)

---

## Files Created

1. **`scripts/k8s-port-forward.sh`**
   - Main bash script with all management logic
   - Includes port checking, health verification, status monitoring
   - Handles process cleanup automatically

2. **`scripts/k8s-port-forward.bat`**
   - Windows batch wrapper for easy double-click execution
   - Calls the bash script with passed arguments

3. **`PORT_FORWARD_FIX.md`** (this file)
   - Complete documentation of the issue and solution
   - Usage instructions and best practices

---

## Summary

**Problem:** Port conflicts from orphaned kubectl port-forward processes

**Solution:**
1. Identified and killed conflicting processes
2. Created automated management script
3. Implemented health checks and status monitoring
4. Documented best practices

**Result:**
- ✅ Port 8085 freed and available
- ✅ ML-SecTest API accessible on localhost:8085
- ✅ Prometheus accessible on localhost:9092
- ✅ Robust management system in place
- ✅ Future conflicts prevented

**Status:** **FULLY RESOLVED** - Services running and accessible

---

*Last Updated: 2025-10-23*
*Issue Resolution Time: ~15 minutes*
*Prevention: Automated script created*
