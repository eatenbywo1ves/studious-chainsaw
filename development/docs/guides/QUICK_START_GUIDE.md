# Redis Production Deployment - Quick Start Guide

**Last Updated**: October 2, 2025
**Status**: ✅ Ready to Use

---

## 🚀 Quick Actions

### Run a Manual Backup Right Now
```powershell
$env:REDIS_PASSWORD = "<REDACTED>"
cd development/security/deployment
powershell -ExecutionPolicy Bypass -File backup-redis.ps1
```

### Check Redis Health Right Now
```powershell
$env:REDIS_PASSWORD = "<REDACTED>"
cd development/security/deployment
powershell -ExecutionPolicy Bypass -File check-redis-health.ps1 -Verbose
```

### Run Security Tests
```bash
cd development/security
export REDIS_PASSWORD="<REDACTED>"
python tests/test_redis_fixes_simple.py
```

---

## ⚡ 5-Minute Setup (Scheduled Tasks)

### Step 1: Open PowerShell as Administrator
```
Right-click PowerShell → Run as Administrator
```

### Step 2: Navigate to Deployment Folder
```powershell
cd C:\Users\Corbin\development\security\deployment
```

### Step 3: Run Setup Script
```powershell
.\setup-scheduled-tasks.ps1
```

**That's it!** Your scheduled tasks are now running:
- ✅ Daily backups at 2 AM
- ✅ Health checks every 15 minutes

---

## 📋 Manual Task Scheduler Setup (Alternative)

If the automated script doesn't work, set up manually:

### Task 1: Daily Backup

1. Open Task Scheduler (`Win+R` → `taskschd.msc`)
2. Click **Action** → **Create Task**
3. Fill in:
   - **Name**: `Redis-Daily-Backup`
   - **Description**: `Daily Redis backup at 2 AM`
   - **Security**: Run whether user is logged on or not
   - **Run with highest privileges**: ✅ Checked

4. **Triggers** tab:
   - New trigger
   - **Begin**: On a schedule
   - **Daily**, at **2:00 AM**
   - **Enabled**: ✅ Checked

5. **Actions** tab:
   - New action
   - **Program**: `powershell.exe`
   - **Arguments**:
     ```
     -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "$env:REDIS_PASSWORD = '<REDACTED>'; & 'C:\Users\Corbin\development\security\deployment\backup-redis.ps1'"
     ```

6. Click **OK**

### Task 2: Health Monitoring

1. Same steps as above, but use:
   - **Name**: `Redis-Health-Check`
   - **Description**: `Redis health check every 15 minutes`
   - **Trigger**: Daily, repeat every **15 minutes** for **indefinitely**
   - **Arguments**:
     ```
     -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "$env:REDIS_PASSWORD = '<REDACTED>'; & 'C:\Users\Corbin\development\security\deployment\check-redis-health.ps1' | Out-File -Append -FilePath 'C:\Users\Corbin\development\security\deployment\logs\redis-health-$(Get-Date -Format yyyy-MM-dd).log'"
     ```

---

## 🔐 Essential Commands

### Redis Service Management
```powershell
# Check status
Get-Service Memurai

# Start Redis
net start Memurai

# Stop Redis
net stop Memurai

# Restart Redis
net stop Memurai; net start Memurai
```

### Connect to Redis CLI
```bash
# With password (use environment variable)
"C:\Program Files\Memurai\memurai-cli.exe" -a "${REDIS_PASSWORD}"

# Test connection
"C:\Program Files\Memurai\memurai-cli.exe" -a "${REDIS_PASSWORD}" PING
# Should return: PONG

# Get server info
"C:\Program Files\Memurai\memurai-cli.exe" -a "${REDIS_PASSWORD}" INFO
```

### View Logs
```powershell
# Redis server log
Get-Content "C:\Program Files\Memurai\memurai-production.log" -Tail 50

# Health check logs
Get-Content "development\security\deployment\logs\redis-health-$(Get-Date -Format yyyy-MM-dd).log"
```

---

## 📁 Important File Locations

| Purpose | Location |
|---------|----------|
| **Redis Config** | `C:\Program Files\Memurai\memurai-production.conf` |
| **Redis Logs** | `C:\Program Files\Memurai\memurai-production.log` |
| **Redis Data (RDB)** | `C:\Program Files\Memurai\dump.rdb` |
| **Redis Data (AOF)** | `C:\Program Files\Memurai\appendonlydir\` |
| **Backups** | `C:\Backups\Redis\` |
| **Health Logs** | `development\security\deployment\logs\` |
| **App Config** | `development\security\.env.development` |
| **Credentials** | `development\security\deployment\REDIS_CREDENTIALS.md` |

---

## 🎯 Common Tasks

### Restore from Backup

1. **Stop Redis**:
   ```powershell
   net stop Memurai
   ```

2. **Replace RDB file**:
   ```powershell
   Copy-Item "C:\Backups\Redis\redis_backup_YYYYMMDD_HHMMSS.rdb" "C:\Program Files\Memurai\dump.rdb" -Force
   ```

3. **Replace AOF files** (if you have them):
   ```powershell
   Remove-Item "C:\Program Files\Memurai\appendonlydir\*" -Force
   Copy-Item "C:\Backups\Redis\redis_aof_backup_YYYYMMDD_HHMMSS\*" "C:\Program Files\Memurai\appendonlydir\" -Recurse -Force
   ```

4. **Start Redis**:
   ```powershell
   net start Memurai
   ```

5. **Verify**:
   ```bash
   "C:\Program Files\Memurai\memurai-cli.exe" -a "${REDIS_PASSWORD}" PING
   ```

### Change Redis Password

1. **Generate new password**:
   ```bash
   openssl rand -base64 32
   ```

2. **Update config**:
   ```powershell
   # Edit: C:\Program Files\Memurai\memurai-production.conf
   # Change line: requirepass YOUR_NEW_PASSWORD
   ```

3. **Restart Redis**:
   ```powershell
   net stop Memurai
   net start Memurai
   ```

4. **Update application config**:
   ```bash
   # Edit: development/security/.env.development
   # Update REDIS_PASSWORD and REDIS_URL
   ```

5. **Update scheduled tasks**:
   ```powershell
   cd development/security/deployment
   .\setup-scheduled-tasks.ps1
   ```

6. **Test**:
   ```bash
   cd development/security
   export REDIS_PASSWORD="YOUR_NEW_PASSWORD"
   python tests/test_redis_fixes_simple.py
   ```

---

## 🚨 Troubleshooting

### Problem: "Authentication required" errors

**Solution**: Set the Redis password environment variable
```bash
export REDIS_PASSWORD="<REDACTED>"
```

### Problem: Redis won't start

**Check logs**:
```powershell
Get-Content "C:\Program Files\Memurai\memurai-production.log" -Tail 100
```

**Common causes**:
- Port 6379 already in use
- Config file syntax error
- Insufficient permissions on data directory

### Problem: Backup script fails

**Run with verbose output**:
```powershell
$env:REDIS_PASSWORD = "<REDACTED>"
powershell -ExecutionPolicy Bypass -File backup-redis.ps1 -Verbose
```

**Common causes**:
- Redis not running
- Wrong password
- No write permission to backup directory

### Problem: Health check shows errors

**Run manually to see details**:
```powershell
$env:REDIS_PASSWORD = "<REDACTED>"
powershell -ExecutionPolicy Bypass -File check-redis-health.ps1 -Verbose
```

---

## 📊 Performance Monitoring

### Check Memory Usage
```bash
"C:\Program Files\Memurai\memurai-cli.exe" -a "${REDIS_PASSWORD}" INFO memory
```

Look for:
- `used_memory_human`: Current memory usage
- `maxmemory_human`: Memory limit (2GB)
- `mem_fragmentation_ratio`: Should be 1.0-1.5

### Check Slow Queries
```bash
"C:\Program Files\Memurai\memurai-cli.exe" -a "${REDIS_PASSWORD}" SLOWLOG GET 10
```

### Monitor Client Connections
```bash
"C:\Program Files\Memurai\memurai-cli.exe" -a "${REDIS_PASSWORD}" CLIENT LIST
```

---

## 🎓 Advanced Topics

### Enable Redis Sentinel (High Availability)

For production deployments with multiple servers, set up Redis Sentinel:

1. **Install Memurai on 3+ servers**
2. **Configure master-replica replication**
3. **Set up Sentinel nodes for automatic failover**

See: `development/security/deployment/REDIS_PRODUCTION_DEPLOYMENT.md` (Section: Sentinel Setup)

### Enable TLS Encryption

For remote connections, enable TLS:

1. Generate TLS certificates
2. Update config:
   ```conf
   port 0
   tls-port 6379
   tls-cert-file memurai.crt
   tls-key-file memurai.key
   tls-ca-cert-file ca.crt
   ```

3. Update application connection string:
   ```
   rediss://:password@localhost:6379  # Note: rediss (with SSL)
   ```

---

## ✅ Daily Checklist

### Morning (Optional - Automated)
- [x] Health check runs automatically every 15 min
- [x] Review health logs if needed:
  ```powershell
  Get-Content "development\security\deployment\logs\redis-health-$(Get-Date -Format yyyy-MM-dd).log"
  ```

### Weekly
- [ ] Review backup success (check `C:\Backups\Redis\`)
- [ ] Check disk space for backups
- [ ] Review slow query log
- [ ] Check memory usage trends

### Monthly
- [ ] Test backup restoration
- [ ] Review and clean old backups (>30 days)
- [ ] Update Redis/Memurai if new version available
- [ ] Review security logs

### Quarterly
- [ ] Rotate Redis password
- [ ] Audit access logs
- [ ] Performance tuning review

---

## 📚 Documentation Links

### Local Documentation
- **Full Deployment Guide**: `REDIS_PRODUCTION_DEPLOYMENT_COMPLETE.md`
- **Credentials & Rotation**: `development/security/deployment/REDIS_CREDENTIALS.md`
- **Security Fixes**: `CRITICAL_SECURITY_FIXES_COMPLETE.md`
- **D3FEND Compliance**: `D3FEND_COMPLIANCE_ACHIEVED.md`
- **Production Readiness**: `PRODUCTION_READY_REPORT.md`

### External Resources
- **Memurai Docs**: https://docs.memurai.com
- **Redis Commands**: https://redis.io/commands
- **Redis Best Practices**: https://redis.io/topics/admin

---

## 🎯 Next Steps Checklist

### Immediate
- [x] Redis deployed with production config
- [x] Backups configured and tested
- [x] Health monitoring configured
- [x] Security tests passing (6/6)
- [ ] Schedule tasks in Task Scheduler (run `setup-scheduled-tasks.ps1`)

### This Week
- [ ] Monitor backup execution (check logs daily)
- [ ] Monitor health check results
- [ ] Review Redis performance metrics
- [ ] Store password in password manager

### Before Production
- [ ] Generate NEW password for staging
- [ ] Generate NEW password for production
- [ ] Set up Redis Sentinel (HA)
- [ ] Configure TLS encryption
- [ ] Set up Prometheus monitoring (optional)

---

## 💡 Pro Tips

1. **Use PowerShell Profile for Password**: Add to your PowerShell profile:
   ```powershell
   # In: $PROFILE
   $env:REDIS_PASSWORD = "<REDACTED>"
   # Note: Get actual password from secure password manager
   ```

2. **Create Aliases for Common Commands**:
   ```powershell
   function Redis-Health {
       & "development\security\deployment\check-redis-health.ps1" -Verbose
   }
   function Redis-Backup {
       & "development\security\deployment\backup-redis.ps1"
   }
   ```

3. **Monitor Backup Size**: Set up alerts if backup size grows unexpectedly

4. **Test Restoration Monthly**: Practice makes perfect for emergencies

---

**Need Help?** Check the full documentation in `REDIS_PRODUCTION_DEPLOYMENT_COMPLETE.md`

**Report Issues**: Create issue in project repository with Redis logs attached
