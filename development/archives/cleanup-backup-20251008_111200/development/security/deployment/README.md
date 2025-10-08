# Security Implementation Deployment Guide

## Quick Start

1. **Generate Security Keys**
   ```bash
   cd security/deployment
   ./01-setup-keys.sh development
   ```

2. **Build and Scan Containers**
   ```bash
   ./02-build-containers.sh development
   ```

3. **Deploy Kubernetes Security (if using K8s)**
   ```bash
   ./03-deploy-k8s-security.sh staging
   ```

4. **Integrate Application Security**
   ```bash
   python 04-integrate-application.py development
   ```

5. **Deploy Application**
   ```bash
   cd ../../saas
   docker-compose up -d
   ```

## Environment Variables

Create `.env` file in saas/ directory:

```bash
# Copy from template
cp security/.env.development.template saas/.env

# Edit with your configuration
vi saas/.env
```

## Testing Security

1. **Test JWT Authentication**
   ```bash
   curl -X POST http://localhost:8000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"secure123"}'
   ```

2. **Test Rate Limiting**
   ```bash
   for i in {1..100}; do
     curl http://localhost:8000/api/test
   done
   ```

3. **Run Security Scan**
   ```bash
   cd security/container
   ./security-scanner.sh
   ```

## Monitoring

- **Security Dashboard**: http://localhost:3000/dashboards/security
- **Prometheus Alerts**: http://localhost:9090/alerts
- **Log Aggregation**: Check security/monitoring/

## Troubleshooting

### JWT Key Errors
- Verify keys exist in security/keys/
- Check file permissions (600 for private key)
- Verify environment variables point to correct paths

### Rate Limiting Issues
- Check Redis connection
- Verify RATE_LIMIT_ENABLED=true in .env
- Review rate limit configuration

### Container Security Scan Failures
- Fix reported vulnerabilities
- Update base images
- Review Trivy scan reports

## Production Checklist

- [ ] Generate production RSA keys
- [ ] Configure production .env
- [ ] Run full security scan (0 HIGH/CRITICAL)
- [ ] Deploy network policies
- [ ] Enable monitoring and alerting
- [ ] Test disaster recovery
- [ ] Schedule regular security audits

---
Generated: 2025-10-01
Environment: development
