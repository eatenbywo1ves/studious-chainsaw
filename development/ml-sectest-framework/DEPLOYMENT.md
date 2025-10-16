# ML-SecTest Framework Deployment

**Version:** 1.0.0
**Last Updated:** 2025-10-14
**Current Status:** 🟢 OPERATIONAL

---

## Quick Links

| Document | Purpose |
|----------|---------|
| [LIVE_SYSTEM_STATUS.md](LIVE_SYSTEM_STATUS.md) | Current deployment status and metrics |
| [QUICKSTART.md](QUICKSTART.md) | Fast setup guide for developers |
| [README.md](README.md) | Project overview and documentation |
| [Deployment History →](docs/deployment-history/) | Historical deployment reports |

---

## Current Deployment Status

**System Health:** 🟢 ALL SYSTEMS OPERATIONAL

### Live Services

- **REST API Server:** ✅ Running on port 8081
- **Prometheus Metrics:** ✅ Running on port 9090
- **Test Suite:** ✅ 97.1% passing (105 tests)
- **CI/CD Pipeline:** ✅ Configured and operational

### Quick Access

```bash
# API Documentation (Interactive)
http://127.0.0.1:8081/docs

# Health Check
curl http://127.0.0.1:8081/health

# Prometheus Metrics
http://localhost:9090/metrics
```

See [LIVE_SYSTEM_STATUS.md](LIVE_SYSTEM_STATUS.md) for detailed real-time information.

---

## Deployment Guides

### For New Deployments

1. **Quick Start** - [QUICKSTART.md](QUICKSTART.md)
   - Fast setup for local development
   - Docker-based deployment
   - Testing and validation

2. **Production Deployment** - See deployment history
   - System requirements
   - Infrastructure setup
   - Security configuration
   - Monitoring integration

### For Existing Deployments

- **Current Status:** [LIVE_SYSTEM_STATUS.md](LIVE_SYSTEM_STATUS.md)
- **Health Monitoring:** `GET http://127.0.0.1:8081/health`
- **Metrics Dashboard:** `http://localhost:9090/metrics`

---

## Deployment History

All historical deployment documentation has been archived for reference:

**Location:** [docs/deployment-history/](docs/deployment-history/)

**Available Documents:**
- `DEPLOYMENT_PLAN.md` - Original deployment planning
- `DEPLOYMENT_ROADMAP.md` - Feature roadmap and milestones
- `DEPLOYMENT_STATUS.md` - Progressive deployment status
- `DEPLOYMENT_EXECUTION_REPORT.md` - Execution details and results
- `DEPLOYMENT_VALIDATION_COMPLETE.md` - Validation and testing results
- `FINAL_DEPLOYMENT_REPORT.md` - Comprehensive final report

These documents provide a complete historical record of the framework's deployment journey from planning through production.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                  ML-SECTEST ARCHITECTURE                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────┐       ┌────────────────┐               │
│  │  REST API      │──────▶│  Security      │               │
│  │  (Port 8081)   │       │  Orchestrator  │               │
│  └────────┬───────┘       └────────┬───────┘               │
│           │                         │                        │
│           │                         ▼                        │
│           │              ┌─────────────────────┐            │
│           │              │   9 Security        │            │
│           │              │   Agents            │            │
│           │              └─────────────────────┘            │
│           │                                                  │
│           ▼                                                  │
│  ┌────────────────┐                                         │
│  │  Prometheus    │                                         │
│  │  Metrics       │                                         │
│  │  (Port 9090)   │                                         │
│  └────────────────┘                                         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

For detailed architecture information, see [ARCHITECTURE.md](ARCHITECTURE.md)

---

## Available Security Agents

The framework includes 9 operational security testing agents:

1. **Prompt Injection Agent** - Tests for prompt manipulation vulnerabilities
2. **Model Inversion Agent** - Attempts to extract training data
3. **Data Poisoning Agent** - Tests data integrity protections
4. **Jailbreak Agent** - Tests safety guardrail bypasses
5. **Privacy Violation Agent** - Checks PII leakage
6. **Auth Bypass Agent** - Tests authentication weaknesses
7. **Denial of Service Agent** - Tests resource exhaustion protection
8. **Model Extraction Agent** - Attempts model theft
9. **Adversarial Examples Agent** - Tests robustness to adversarial inputs

See API documentation for usage: http://127.0.0.1:8081/docs

---

## Monitoring & Metrics

### Prometheus Metrics

The framework exports 11 metric types for monitoring:

**Counters:**
- `ml_sectest_scan_requests_total` - Total scan requests
- `ml_sectest_agent_executions_total` - Total agent executions
- `ml_sectest_vulnerabilities_found_total` - Total vulnerabilities
- `ml_sectest_api_requests_total` - Total API requests

**Histograms:**
- `ml_sectest_scan_duration_seconds` - Scan duration distribution
- `ml_sectest_agent_duration_seconds` - Agent duration distribution
- `ml_sectest_api_request_duration_seconds` - API latency distribution

**Gauges:**
- `ml_sectest_active_scans` - Currently running scans
- `ml_sectest_agents_available` - Number of available agents
- `ml_sectest_vulnerabilities_by_severity` - Vulnerabilities by severity

**Info:**
- `ml_sectest_framework_info` - Framework metadata (version, etc.)

### Grafana Integration

Metrics are compatible with Grafana dashboards. Query examples:

```promql
# Request rate
rate(ml_sectest_scan_requests_total[5m])

# P95 scan duration
histogram_quantile(0.95, ml_sectest_scan_duration_seconds_bucket)

# Vulnerabilities by severity
ml_sectest_vulnerabilities_by_severity
```

---

## Testing & Validation

### Running Tests

```bash
# Activate virtual environment
cd C:\Users\Corbin\development\ml-sectest-framework
venv\Scripts\activate

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Run specific test categories
pytest tests/test_api.py -v
pytest tests/test_agents/ -v
```

### Current Test Results

- **Total Tests:** 105
- **Passing:** 102 (97.1%)
- **Failed:** 3 (non-blocking)
- **Duration:** 3.18 seconds
- **Status:** EXCELLENT

---

## CI/CD Pipeline

GitHub Actions workflow configured with:

- **Automated Testing:** All tests run on push/PR
- **Security Scanning:**
  - Bandit (SAST)
  - Safety (dependency vulnerabilities)
  - Trivy (container scanning)
  - Checkov (infrastructure as code)
- **Code Quality:** Linting with Ruff
- **Type Checking:** MyPy static analysis
- **Coverage Reports:** Automated coverage tracking

Configuration: [.github/workflows/ci-cd.yml](.github/workflows/ci-cd.yml)

---

## Troubleshooting

### Common Issues

**API Server Won't Start:**
```bash
# Check if port 8081 is available
netstat -ano | findstr ":8081"

# Check Python dependencies
venv\Scripts\pip list | grep -i fastapi

# View logs
tail -f logs/api.log
```

**Metrics Not Showing:**
```bash
# Verify Prometheus server
curl http://localhost:9090/metrics | grep ml_sectest

# Check metrics endpoint
curl http://127.0.0.1:8081/metrics
```

**Tests Failing:**
```bash
# Clear pytest cache
rm -rf .pytest_cache __pycache__

# Reinstall dependencies
pip install -r requirements.txt

# Run with verbose output
pytest tests/ -vv
```

---

## Support & Documentation

### Additional Resources

- **Main Documentation:** [README.md](README.md)
- **Architecture Guide:** [ARCHITECTURE.md](ARCHITECTURE.md)
- **Quick Start Guide:** [QUICKSTART.md](QUICKSTART.md)
- **Agent Documentation:** [docs/](docs/)
- **Changelog:** [CHANGELOG.md](CHANGELOG.md)
- **GitHub Workflows:** [.github/workflows/](.github/workflows/)

### Getting Help

1. Check [LIVE_SYSTEM_STATUS.md](LIVE_SYSTEM_STATUS.md) for current status
2. Review [docs/deployment-history/](docs/deployment-history/) for deployment details
3. Consult API documentation at http://127.0.0.1:8081/docs
4. Check GitHub Issues for known problems

---

## Maintenance

### Regular Tasks

**Daily:**
- Monitor [LIVE_SYSTEM_STATUS.md](LIVE_SYSTEM_STATUS.md)
- Check health endpoint: `curl http://127.0.0.1:8081/health`
- Review Prometheus metrics

**Weekly:**
- Run full test suite: `pytest tests/ -v`
- Review security scan results
- Update dependencies if needed

**Monthly:**
- Review and archive old scan reports
- Update deployment documentation
- Performance optimization review

---

## Next Steps

### Recommended Actions

1. ✅ **Deployment Complete** - System is operational
2. 📊 **Monitor Metrics** - Track performance via Prometheus
3. 🔒 **Security Review** - Regular vulnerability scanning
4. 📈 **Scale Planning** - Prepare for increased load
5. 🚀 **Feature Development** - See [CHANGELOG.md](CHANGELOG.md) for roadmap

---

**Document Version:** 1.0.0
**Last Updated:** 2025-10-14
**Maintained By:** ML-SecTest Team
**Status:** 🟢 CURRENT
