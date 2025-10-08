# Pre-Deployment Checklist
## Catalytic Computing SaaS Platform

**Target Launch Date:** _________________
**Environment:** Production
**Version:** 1.0.0

---

## Phase 1: Infrastructure Preparation (Day 1-2)

### Server Provisioning
- [ ] Cloud provider selected: _________________ (AWS / GCP / DigitalOcean / Other)
- [ ] Server instance created
  - [ ] Minimum specs: 4GB RAM, 2 vCPU, 20GB SSD
  - [ ] Operating system: Ubuntu 22.04 LTS
  - [ ] SSH access configured
  - [ ] Firewall rules set (ports 22, 80, 443)
- [ ] Static IP address assigned: _________________
- [ ] Server accessible via SSH

### Domain & DNS
- [ ] Domain name registered: _________________
- [ ] DNS A record configured (@ → server IP)
- [ ] DNS A record configured (api → server IP)
- [ ] DNS A record configured (www → server IP)
- [ ] DNS propagation verified (dig/nslookup)
- [ ] TTL reduced to 300 for launch day

### Database Setup
- [ ] PostgreSQL service chosen:
  - [ ] Self-hosted (on same server)
  - [ ] Managed service: _________________
- [ ] PostgreSQL 14+ installed/provisioned
- [ ] Database created: `catalytic_saas_prod`
- [ ] Database user created with strong password
- [ ] Database connection tested
- [ ] Connection string saved securely

### Redis Setup
- [ ] Redis service chosen:
  - [ ] Self-hosted (on same server)
  - [ ] Managed service: _________________
- [ ] Redis 6+ installed/provisioned
- [ ] Redis password configured
- [ ] Redis connection tested
- [ ] Connection string saved securely

---

## Phase 2: Third-Party Services (Day 2-3)

### Stripe Configuration
- [ ] Stripe account activated (business verification complete)
- [ ] Bank account added for payouts
- [ ] Tax information submitted
- [ ] Live mode activated
- [ ] Live API keys obtained:
  - [ ] Publishable key (pk_live_...): ✓
  - [ ] Secret key (sk_live_...): ✓
- [ ] Products created in live mode:
  - [ ] Starter ($29/mo)
  - [ ] Professional ($99/mo)
  - [ ] Enterprise ($299/mo)
- [ ] Product IDs recorded: _________________
- [ ] Webhook endpoint configured
- [ ] Webhook signing secret saved
- [ ] Test payment completed successfully

### Email Service Configuration
- [ ] Email provider selected: _________________ (SendGrid / AWS SES / SMTP)

**If SendGrid:**
- [ ] SendGrid account activated
- [ ] API key generated (full access)
- [ ] Sender email verified: _________________
- [ ] Domain authentication configured (SPF, DKIM, DMARC)
- [ ] Test email sent and received

**If AWS SES:**
- [ ] AWS account configured
- [ ] IAM user created with SES permissions
- [ ] Production access requested and approved
- [ ] Sender email/domain verified
- [ ] Test email sent and received

**If SMTP:**
- [ ] SMTP host configured: _________________
- [ ] SMTP credentials obtained
- [ ] Test email sent and received

### SSL Certificate
- [ ] SSL certificate method chosen:
  - [ ] Let's Encrypt (free, recommended)
  - [ ] Commercial certificate
  - [ ] Cloud provider certificate
- [ ] Certificate obtained and installed
- [ ] HTTPS working (https://api.yourdomain.com)
- [ ] HTTP → HTTPS redirect configured
- [ ] SSL Labs grade: _________________ (target: A+)

### Monitoring & Error Tracking
- [ ] Sentry account created
- [ ] Sentry project created for production
- [ ] Sentry DSN obtained: ✓
- [ ] Uptime monitoring configured:
  - [ ] Service: _________________ (UptimeRobot / Pingdom / Other)
  - [ ] Check interval: 5 minutes
  - [ ] Alert email configured
- [ ] Status page created (optional): _________________

---

## Phase 3: Application Configuration (Day 3)

### Security Keys Generation
- [ ] Production JWT keys generated:
  ```bash
  cd /path/to/catalytic-saas/security
  python generate_keys.py production
  ```
- [ ] JWT private key backed up securely
- [ ] JWT public key backed up securely
- [ ] API encryption key generated and backed up
- [ ] Database encryption key generated and backed up

### Secrets Generation
- [ ] Session secret generated:
  ```bash
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
- [ ] CSRF secret generated (different from session secret)
- [ ] Redis password generated/configured
- [ ] Database password generated/configured

### Environment File Creation
- [ ] `.env.production` created from template:
  ```bash
  cp .env.production.template .env.production
  ```
- [ ] All placeholder values replaced with real credentials
- [ ] Critical values verified:
  - [ ] DATABASE_URL (PostgreSQL connection string)
  - [ ] REDIS_HOST and REDIS_PASSWORD
  - [ ] JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH
  - [ ] STRIPE_SECRET_KEY (sk_live_...)
  - [ ] SENDGRID_API_KEY or AWS credentials
  - [ ] CORS_ALLOWED_ORIGINS (your actual domain)
  - [ ] SESSION_SECRET_KEY
  - [ ] CSRF_SECRET_KEY
  - [ ] SENTRY_DSN
- [ ] APP_ENV set to `production`
- [ ] DEBUG set to `false`
- [ ] LOG_LEVEL set to `WARNING`

### File Permissions
- [ ] `.env.production` permissions set to 600 (read/write owner only)
  ```bash
  chmod 600 .env.production
  ```
- [ ] JWT keys permissions set to 600
- [ ] Encryption keys permissions set to 600

---

## Phase 4: Code Deployment (Day 4)

### Repository Setup
- [ ] Production branch created (if using separate branch)
- [ ] Code pushed to repository
- [ ] Release tag created (v1.0.0)

### Server Preparation
- [ ] Python 3.11+ installed
- [ ] pip upgraded to latest
- [ ] Virtual environment created
- [ ] Dependencies installed:
  ```bash
  pip install -r requirements.txt
  ```
- [ ] Dependency installation successful (no errors)

### Database Migration
- [ ] Database tables created:
  ```bash
  python -c "from database.models import Base, engine; from database.session import init_db; init_db()"
  ```
- [ ] Tables verified:
  ```bash
  psql $DATABASE_URL -c "\dt"
  ```
- [ ] If migrating from SQLite, migration completed:
  ```bash
  python scripts/migrate_to_postgresql.py --backup
  ```

### Service Configuration
- [ ] Systemd service file created:
  ```bash
  sudo cp /tmp/catalytic-saas.service /etc/systemd/system/
  ```
- [ ] Service enabled:
  ```bash
  sudo systemctl enable catalytic-saas
  ```
- [ ] Nginx configuration created and tested:
  ```bash
  sudo nginx -t
  ```
- [ ] Nginx site enabled

---

## Phase 5: Testing (Day 4-5)

### Unit & Integration Tests
- [ ] All tests passing:
  ```bash
  pytest -v
  ```
- [ ] Test coverage ≥ 80%:
  ```bash
  pytest --cov --cov-report=html
  ```
- [ ] Security tests passing:
  ```bash
  pytest -v -m security
  ```

### Manual Testing
- [ ] Health endpoint responds:
  ```bash
  curl https://api.yourdomain.com/health
  ```
- [ ] User registration works
- [ ] User login works
- [ ] JWT token generation and validation works
- [ ] API key generation works
- [ ] Subscription checkout flow works
- [ ] Stripe webhook processing works
- [ ] Email delivery works
- [ ] Password reset works
- [ ] Rate limiting works
- [ ] CORS configuration works

### Security Testing
- [ ] HTTPS enforced (HTTP redirects to HTTPS)
- [ ] HSTS header present
- [ ] SSL certificate valid
- [ ] CORS wildcard not used (verify: no "*" in allowed origins)
- [ ] API requires authentication
- [ ] Webhook signatures verified
- [ ] SQL injection prevention tested
- [ ] XSS prevention tested

### Performance Testing
- [ ] Load test completed:
  ```bash
  # Example with Apache Bench
  ab -n 1000 -c 10 https://api.yourdomain.com/health
  ```
- [ ] Response times acceptable (<200ms P95)
- [ ] No memory leaks observed
- [ ] Database connection pooling working

---

## Phase 6: Pre-Launch (Day 5)

### Backup Configuration
- [ ] Automated backup script installed:
  ```bash
  sudo cp backup-catalytic-db.sh /usr/local/bin/
  sudo chmod +x /usr/local/bin/backup-catalytic-db.sh
  ```
- [ ] Backup cron job configured (daily 2 AM)
- [ ] First manual backup created and verified
- [ ] Backup restoration tested
- [ ] Off-site backup configured (S3, Google Cloud Storage, etc.)

### Monitoring Setup
- [ ] Application logging verified
- [ ] Log rotation configured
- [ ] Sentry receiving errors (test error triggered)
- [ ] Uptime monitoring active
- [ ] Alert emails working
- [ ] Performance metrics baseline recorded

### Documentation
- [ ] Deployment summary reviewed
- [ ] Runbooks accessible to team
- [ ] Support email configured
- [ ] Incident response plan documented
- [ ] Team onboarded on monitoring tools

### Communication
- [ ] Launch announcement prepared
- [ ] Social media posts scheduled
- [ ] Early access users notified
- [ ] Support channels ready
- [ ] Status page published

---

## Phase 7: Launch (Day 6)

### Final Checks (T-2 hours)
- [ ] All services running:
  ```bash
  sudo systemctl status catalytic-saas
  sudo systemctl status postgresql
  sudo systemctl status redis
  sudo systemctl status nginx
  ```
- [ ] Health check passing
- [ ] No errors in logs (last hour)
- [ ] Uptime monitoring green
- [ ] SSL certificate valid for 90+ days
- [ ] DNS propagation complete

### Go Live
- [ ] DNS TTL restored to normal (3600)
- [ ] Final smoke test completed
- [ ] Launch announcement sent
- [ ] Team on standby for support

### Post-Launch Monitoring (First 24 Hours)
- [ ] Error rate monitored (target: <0.1%)
- [ ] Response times monitored (target: P95 <200ms)
- [ ] Uptime monitored (target: 100%)
- [ ] First payment processed successfully
- [ ] First emails delivered successfully
- [ ] No critical errors in Sentry
- [ ] User signups working
- [ ] Support tickets addressed

---

## Phase 8: Post-Launch (Week 1)

### Optimization
- [ ] Slow queries identified and optimized
- [ ] Cache hit rates reviewed
- [ ] Resource usage optimized
- [ ] Unused indexes removed
- [ ] Connection pool tuned

### Security Audit
- [ ] Security headers verified
- [ ] Access logs reviewed for suspicious activity
- [ ] Failed login attempts monitored
- [ ] API key usage reviewed
- [ ] Webhook signature failures investigated

### Business Metrics
- [ ] First paying customers
- [ ] MRR tracking started
- [ ] Churn rate baseline established
- [ ] Support ticket volume measured
- [ ] User feedback collected

---

## Rollback Plan

If critical issues occur:

### Immediate Rollback
1. [ ] Stop service: `sudo systemctl stop catalytic-saas`
2. [ ] Restore database from backup
3. [ ] Revert code to previous version
4. [ ] Restart service: `sudo systemctl start catalytic-saas`
5. [ ] Notify users of temporary maintenance

### Post-Rollback
- [ ] Identify root cause
- [ ] Fix issue in development
- [ ] Test fix thoroughly
- [ ] Plan re-deployment

---

## Sign-Off

**Deployment Lead:** _________________________ Date: _________

**Technical Review:** _________________________ Date: _________

**Security Review:** _________________________ Date: _________

**Business Approval:** _________________________ Date: _________

---

## Notes

_Use this space for deployment-specific notes, issues encountered, or lessons learned:_

```





```

---

## Quick Reference

**Emergency Contacts:**
- DevOps Engineer: _________________________
- Backend Engineer: _________________________
- On-Call Escalation: _________________________

**Critical URLs:**
- Production API: https://api.yourdomain.com
- Health Check: https://api.yourdomain.com/health
- Stripe Dashboard: https://dashboard.stripe.com
- Sentry Dashboard: https://sentry.io
- Uptime Monitor: https://uptimerobot.com

**Emergency Commands:**
```bash
# Check service status
sudo systemctl status catalytic-saas

# View recent logs
sudo journalctl -u catalytic-saas -n 100

# Restart service
sudo systemctl restart catalytic-saas

# Database backup
pg_dump $DATABASE_URL > emergency-backup.sql

# Rollback to previous version
git checkout v0.9.0 && sudo systemctl restart catalytic-saas
```

---

**Document Version:** 1.0
**Last Updated:** 2025-10-05
**Next Review:** Upon completion of deployment
