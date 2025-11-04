# Redis Production Credentials

**⚠️ SECURITY WARNING**: This file contains sensitive credentials. Keep it secure!

**Date Created**: October 2, 2025
**Environment**: Development/Local
**Redis Version**: Memurai 4.1.6 (Redis 7.2.10)

---

## 🔐 Redis Password

### Development Environment
```
Password: <REDACTED>
Host: localhost
Port: 6379
Database: 0
```

**Connection String**:
```
redis://:<REDACTED>@localhost:6379/0
```

**Environment Variable**:
```bash
export REDIS_PASSWORD="<REDACTED>"
```

---

## 📍 Where This Password Is Used

1. **Redis Configuration**
   - File: `C:\Program Files\Memurai\memurai-production.conf`
   - Line: `requirepass <REDACTED>`

2. **Application Environment**
   - File: `development/security/.env.development`
   - Variables: `REDIS_URL`, `REDIS_PASSWORD`

3. **Backup Script**
   - File: `development/security/deployment/backup-redis.ps1`
   - Via: `$env:REDIS_PASSWORD`

4. **Health Check Script**
   - File: `development/security/deployment/check-redis-health.ps1`
   - Via: `$env:REDIS_PASSWORD`

5. **Test Suite**
   - File: `development/security/tests/test_redis_fixes_simple.py`
   - Via: `os.getenv("REDIS_PASSWORD")`

---

## 🔄 Password Rotation Plan

### When to Rotate
- [ ] Every 90 days (quarterly)
- [ ] When employee with access leaves
- [ ] After security incident
- [ ] Before production deployment

### How to Rotate

1. **Generate New Password**:
   ```bash
   openssl rand -base64 32
   ```

2. **Update Redis Config**:
   ```conf
   # Edit C:\Program Files\Memurai\memurai-production.conf
   requirepass YOUR_NEW_PASSWORD_HERE
   ```

3. **Restart Redis**:
   ```powershell
   net stop Memurai
   net start Memurai
   ```

4. **Update Application Config**:
   ```bash
   # Edit development/security/.env.development
   REDIS_PASSWORD=YOUR_NEW_PASSWORD_HERE
   REDIS_URL=redis://:YOUR_NEW_PASSWORD_HERE@localhost:6379/0
   ```

5. **Update Scheduled Tasks**:
   - Re-run `setup-scheduled-tasks.ps1` with new password

6. **Test Connection**:
   ```bash
   cd development/security
   export REDIS_PASSWORD="YOUR_NEW_PASSWORD_HERE"
   python tests/test_redis_fixes_simple.py
   ```

---

## 🎯 Security Best Practices

### DO ✅
- ✅ Store this file in encrypted storage (BitLocker, VeraCrypt)
- ✅ Use password managers (1Password, LastPass, Bitwarden)
- ✅ Set file permissions to read-only for your user
- ✅ Generate NEW passwords for staging/production
- ✅ Enable 2FA on systems with password access
- ✅ Audit access logs regularly

### DON'T ❌
- ❌ Commit this file to Git
- ❌ Share password via email/Slack
- ❌ Reuse this password in other environments
- ❌ Store password in plain text notes
- ❌ Share password with unauthorized users
- ❌ Use weak/predictable passwords

---

## 🌍 Environment-Specific Passwords

### Development (Current)
```
Password: <REDACTED>
Status: ✅ Active
Last Rotated: October 2, 2025
Next Rotation: January 2, 2026
```

### Staging (To Be Configured)
```
Password: [GENERATE NEW - DO NOT REUSE DEVELOPMENT]
Status: ⏳ Pending
Command: openssl rand -base64 32
```

### Production (To Be Configured)
```
Password: [GENERATE NEW - DO NOT REUSE DEVELOPMENT OR STAGING]
Status: ⏳ Pending
Command: openssl rand -base64 32
Additional: Consider using Azure Key Vault or AWS Secrets Manager
```

---

## 🔐 Secure Storage Recommendations

### Option 1: Password Manager (Recommended)
- **1Password**: Create secure note with Redis credentials
- **Bitwarden**: Store as secure note or custom item
- **LastPass**: Save as secure note

### Option 2: Encrypted File
```powershell
# Encrypt this file (Windows)
$secureString = ConvertTo-SecureString "FilePassword123!" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("User", $secureString)

# Export encrypted
$content = Get-Content REDIS_CREDENTIALS.md
$encrypted = ConvertTo-SecureString $content -AsPlainText -Force | ConvertFrom-SecureString
$encrypted | Out-File REDIS_CREDENTIALS.encrypted
```

### Option 3: Azure Key Vault (Production)
```bash
# Store in Azure Key Vault
az keyvault secret set --vault-name "MyKeyVault" --name "RedisPassword" --value "<REDACTED>"

# Retrieve when needed
az keyvault secret show --vault-name "MyKeyVault" --name "RedisPassword" --query value -o tsv
```

---

## 📋 Access Log

| Date | User | Action | Reason |
|------|------|--------|--------|
| 2025-10-02 | Claude | Created | Initial Redis deployment |
| | | | |
| | | | |

---

## 🚨 Emergency Procedures

### If Password is Compromised

1. **Immediate Actions** (Within 1 hour):
   ```powershell
   # Generate new password
   $newPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | % {[char]$_})

   # Update Redis config
   # Edit C:\Program Files\Memurai\memurai-production.conf
   # requirepass $newPassword

   # Restart Redis
   net stop Memurai
   net start Memurai
   ```

2. **Update All Services** (Within 4 hours):
   - Update application `.env` files
   - Update scheduled tasks
   - Update monitoring tools
   - Notify development team

3. **Audit & Report** (Within 24 hours):
   - Check Redis logs for unauthorized access
   - Review application logs
   - Document incident
   - Update security procedures

---

## 📞 Support Contacts

### Internal
- **DevOps Team**: devops@company.com
- **Security Team**: security@company.com
- **On-Call**: +1-XXX-XXX-XXXX

### External
- **Memurai Support**: https://support.memurai.com
- **Redis Documentation**: https://redis.io/documentation

---

**Last Updated**: October 2, 2025
**Next Review**: January 2, 2026
**Owner**: DevOps Team

---

*Keep this document secure and update access log when shared*