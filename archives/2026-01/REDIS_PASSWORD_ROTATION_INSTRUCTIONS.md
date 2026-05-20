# 🔐 Redis Password Rotation - Quick Instructions

**Generated:** 2025-10-24 18:30:00
**Incident:** GitGuardian-001
**New Password Generated:** `<REDACTED>`

---

## ⚡ Quick Start (Automated)

### Windows (PowerShell):
```powershell
cd C:\Users\Corbin\development\saas\scripts
.\rotate-redis-password.ps1
```

### Linux/Mac/WSL:
```bash
cd ~/development/saas/scripts
./rotate-redis-password.sh
```

**What the script does:**
1. ✅ Generates cryptographically secure new password
2. ✅ Checks/starts Redis Docker container
3. ✅ Backs up current .env.production
4. ✅ Updates Redis configuration with new password
5. ✅ Verifies new password works (PING test)
6. ✅ Updates .env.production file
7. ✅ Updates docker-compose.redis.yml

**Time:** ~30 seconds

---

## 📋 Manual Steps (If Script Fails)

### 1. Start Redis Container
```bash
cd ~/development/saas
docker-compose -f docker-compose.yml -f docker-compose.redis.yml up -d redis

# Verify running
docker ps --filter "name=catalytic-redis"
```

### 2. Update Redis Password
```bash
# Connect to container and set password
docker exec -it catalytic-redis redis-cli

# In redis-cli:
CONFIG SET requirepass "<REDACTED>"
AUTH <REDACTED>
PING
# Expected: PONG
exit
```

### 3. Update .env.production
```bash
cd ~/development/saas

# Create backup
cp .env.production .env.production.backup.$(date +%Y%m%d)

# Edit file
nano .env.production
```

**Change line 4 to:**
```
REDIS_PASSWORD=<REDACTED>
```

Save and exit (Ctrl+X, Y, Enter)

### 4. Update docker-compose.redis.yml

Add password requirement to Redis configuration:

```bash
nano docker-compose.redis.yml
```

**Find the `command:` section (line 11-18) and add after line 18:**
```yaml
      --requirepass ${REDIS_PASSWORD}
```

**Should look like:**
```yaml
command: >
  redis-server
  --appendonly yes
  --appendfsync everysec
  --maxmemory 512mb
  --maxmemory-policy allkeys-lru
  --save 60 1000
  --protected-mode no
  --requirepass ${REDIS_PASSWORD}
```

### 5. Restart Services
```bash
cd ~/development/saas

# Restart Redis
docker-compose -f docker-compose.yml -f docker-compose.redis.yml restart redis

# Wait for health check
sleep 10

# Verify Redis is healthy
docker exec catalytic-redis redis-cli -a "<REDACTED>" PING
# Expected: PONG

# Restart SaaS application
docker-compose restart
```

---

## ✅ Verification Checklist

After rotation, verify:

- [ ] Redis container is running: `docker ps --filter "name=catalytic-redis"`
- [ ] Redis responds with auth: `docker exec catalytic-redis redis-cli -a "<NEW_PASSWORD>" PING`
- [ ] Old password fails: `docker exec catalytic-redis redis-cli -a "<OLD_PASSWORD_REDACTED>" PING` (should fail)
- [ ] .env.production updated: `grep REDIS_PASSWORD ~/development/saas/.env.production`
- [ ] docker-compose.redis.yml has --requirepass
- [ ] Application starts without errors: `docker-compose logs app`
- [ ] Application can connect to Redis: Check app logs for Redis connection errors

---

## 🔍 Troubleshooting

### "redis-cli: command not found"
**Solution:** Use Docker exec:
```bash
docker exec catalytic-redis redis-cli -a "PASSWORD" PING
```

### "Container not running"
**Solution:** Start Redis:
```bash
cd ~/development/saas
docker-compose -f docker-compose.yml -f docker-compose.redis.yml up -d redis
```

### "Authentication failed"
**Cause:** Password mismatch between Redis and .env.production

**Solution:** Check passwords match:
```bash
# Check .env.production
grep REDIS_PASSWORD ~/development/saas/.env.production

# Test password
docker exec catalytic-redis redis-cli -a "PASSWORD_FROM_ENV" PING
```

### "Application can't connect to Redis"
**Solution:** Restart application services:
```bash
cd ~/development/saas
docker-compose restart
```

---

## 🚨 If You Encounter Issues

1. **Check logs:**
   ```bash
   docker logs catalytic-redis
   docker-compose logs app
   ```

2. **Verify Redis configuration:**
   ```bash
   docker exec catalytic-redis redis-cli CONFIG GET requirepass
   ```

3. **Test connection from application:**
   ```bash
   docker exec catalytic-redis redis-cli -h localhost -p 6379 -a "NEW_PASSWORD" PING
   ```

4. **Rollback if needed:**
   ```bash
   # Restore backup
   cp ~/development/saas/.env.production.backup.YYYYMMDD ~/development/saas/.env.production

   # Get old password from backup
   OLD_PASSWORD=$(grep REDIS_PASSWORD ~/development/saas/.env.production | cut -d'=' -f2)

   # Set old password in Redis
   docker exec catalytic-redis redis-cli CONFIG SET requirepass "$OLD_PASSWORD"

   # Restart services
   cd ~/development/saas
   docker-compose restart
   ```

---

## 📝 Next Steps After Successful Rotation

### Immediate:
- [ ] Verify application functionality
- [ ] Check application logs for Redis errors
- [ ] Test critical features that use Redis

### Within 24 Hours:
- [ ] Update Kubernetes secrets (if applicable)
- [ ] Update any external services using this Redis instance
- [ ] Document rotation in change log
- [ ] Delete temporary password files

### Security Follow-Up:
- [ ] Review `SECURITY_INCIDENT_REMEDIATION.md`
- [ ] Decide on git history rewriting
- [ ] Install pre-commit hooks (detect-secrets)
- [ ] Plan migration to centralized secrets management

---

## 📞 Support

**If password rotation fails:**
1. Check troubleshooting section above
2. Review Docker logs: `docker logs catalytic-redis`
3. See comprehensive guide: `SECURITY_INCIDENT_REMEDIATION.md`
4. Contact DevOps/Redis admin

**Related Documents:**
- `SECURITY_INCIDENT_REMEDIATION.md` - Comprehensive incident response
- `GITGUARDIAN_INCIDENT_SUMMARY.md` - Executive summary
- `saas/scripts/rotate-redis-password.ps1` - Windows automation
- `saas/scripts/rotate-redis-password.sh` - Linux/Mac automation

---

## 🔐 Security Reminders

**DO:**
- ✅ Use automated scripts when possible
- ✅ Back up current configuration
- ✅ Verify new password works before finalizing
- ✅ Update all dependent services
- ✅ Test application functionality

**DON'T:**
- ❌ Commit .env.production to git
- ❌ Share passwords in Slack/email
- ❌ Leave temporary password files
- ❌ Skip verification steps
- ❌ Forget to restart services

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)

**Incident:** GitGuardian-001
**Status:** Automated scripts ready for execution
**Action Required:** Run rotation script or follow manual steps above
