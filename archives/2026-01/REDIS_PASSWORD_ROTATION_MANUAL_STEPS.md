# Redis Password Rotation - Manual Execution Steps

**CRITICAL:** Execute these steps NOW to rotate the compromised Redis password.

**New Password:** `<REDACTED>`

---

## Step-by-Step Instructions

### Step 1: Check Docker and Redis Status

Open **PowerShell** or **Command Prompt** and run:

```powershell
# Check if Docker is running
docker --version

# Check if Redis container exists
docker ps -a --filter "name=catalytic-redis"
```

**Expected:** Docker version displayed and Redis container listed (may be stopped or running)

---

### Step 2: Start Redis Container (if not running)

```powershell
cd C:\Users\Corbin\development\saas

# Start Redis
docker-compose -f docker-compose.yml -f docker-compose.redis.yml up -d redis

# Wait for container to start
timeout /t 5

# Verify it's running
docker ps --filter "name=catalytic-redis"
```

**Expected:** Container status shows "Up"

---

### Step 3: Set New Password in Redis

```powershell
# Set new password
docker exec catalytic-redis redis-cli CONFIG SET requirepass "<REDACTED>"

# Test authentication with new password
docker exec catalytic-redis redis-cli -a "<REDACTED>" PING
```

**Expected:**
- First command: `OK`
- Second command: `PONG`

If you see `PONG`, password is successfully set!

---

### Step 4: Backup and Update .env.production

```powershell
cd C:\Users\Corbin\development\saas

# Create backup
copy .env.production .env.production.backup.%date:~-4,4%%date:~-10,2%%date:~-7,2%

# Open file in notepad
notepad .env.production
```

**In Notepad:**
1. Find line 4: `REDIS_PASSWORD=<OLD_PASSWORD_REDACTED>`
2. Replace with: `REDIS_PASSWORD=<NEW_PASSWORD_REDACTED>`
3. Save and close (Ctrl+S, then close)

**Verify change:**
```powershell
type .env.production | findstr REDIS_PASSWORD
```

**Expected:** `REDIS_PASSWORD=<NEW_PASSWORD_REDACTED>`

---

### Step 5: Update docker-compose.redis.yml

```powershell
# Open file in notepad
notepad docker-compose.redis.yml
```

**In Notepad:**
1. Scroll to the `command:` section (around line 11-18)
2. After the line `--protected-mode no` add a new line:
   ```
         --requirepass ${REDIS_PASSWORD}
   ```
3. The section should look like:
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
4. Save and close

---

### Step 6: Restart Redis with New Configuration

```powershell
cd C:\Users\Corbin\development\saas

# Stop Redis
docker-compose -f docker-compose.yml -f docker-compose.redis.yml stop redis

# Start Redis with new config
docker-compose -f docker-compose.yml -f docker-compose.redis.yml up -d redis

# Wait for startup
timeout /t 10

# Verify Redis is running with password
docker exec catalytic-redis redis-cli -a "<REDACTED>" PING
```

**Expected:** `PONG`

---

### Step 7: Test Old Password Fails (Security Verification)

```powershell
# This should FAIL (proving old password is invalid)
docker exec catalytic-redis redis-cli -a "<OLD_PASSWORD_REDACTED>" PING
```

**Expected:** Error message like `NOAUTH Authentication required` or `ERR invalid password`

This confirms the old password no longer works!

---

### Step 8: Restart Application Services

```powershell
cd C:\Users\Corbin\development\saas

# Restart all services to pick up new Redis password
docker-compose restart

# Check logs for errors
docker-compose logs --tail=50 app
```

**Look for:** No Redis connection errors in logs

---

## Verification Checklist

After completing all steps, verify:

- [ ] `docker ps` shows `catalytic-redis` running
- [ ] New password works: `docker exec catalytic-redis redis-cli -a "<REDACTED>" PING` returns `PONG`
- [ ] Old password fails: `docker exec catalytic-redis redis-cli -a "<OLD_PASSWORD_REDACTED>" PING` returns error
- [ ] `.env.production` contains new password
- [ ] `docker-compose.redis.yml` has `--requirepass ${REDIS_PASSWORD}`
- [ ] Application logs show no Redis errors: `docker-compose logs app | findstr /i redis`

---

## Troubleshooting

### "Docker command not found"
**Fix:** Ensure Docker Desktop is installed and running

### "Container catalytic-redis not found"
**Fix:** Redis has never been started. Run:
```powershell
cd C:\Users\Corbin\development\saas
docker-compose -f docker-compose.yml -f docker-compose.redis.yml up -d redis
```

### "NOAUTH Authentication required"
**Cause:** Password was set but not provided

**Fix:** Always use `-a "PASSWORD"` flag:
```powershell
docker exec catalytic-redis redis-cli -a "<REDACTED>" PING
```

### Application can't connect to Redis
**Fix:** Restart application:
```powershell
cd C:\Users\Corbin\development\saas
docker-compose restart
```

---

## Quick Command Reference

**Test Redis connection:**
```powershell
docker exec catalytic-redis redis-cli -a "<REDACTED>" PING
```

**View Redis logs:**
```powershell
docker logs catalytic-redis --tail=50
```

**View application logs:**
```powershell
cd C:\Users\Corbin\development\saas
docker-compose logs app --tail=50
```

**Restart everything:**
```powershell
cd C:\Users\Corbin\development\saas
docker-compose -f docker-compose.yml -f docker-compose.redis.yml restart
```

---

## After Successful Rotation

1. **Mark as complete in todo list**
2. **Delete temporary password files** (if any were created)
3. **Do NOT commit `.env.production` to git!**
4. **Review** `SECURITY_INCIDENT_REMEDIATION.md` for next steps
5. **Decide** on git history rewriting approach

---

🤖 Generated with Claude Code

**Status:** Ready to execute
**Estimated Time:** 10-15 minutes
**Start:** Open PowerShell and begin with Step 1
