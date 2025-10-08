# Smoke Tests - Production Verification

## Overview

Smoke tests are a critical set of rapid tests run immediately after deployment to verify that the production system is functional. These tests check:

1. **Health Checks**: All services are running and healthy
2. **Critical Workflows**: Must-work user flows are functional

## Purpose

- **Fast Feedback**: Get immediate confirmation that deployment succeeded
- **Critical Coverage**: Focus on must-work functionality only
- **Production Safety**: Detect major issues before users do
- **Deployment Gate**: Block bad deployments from going live

## Test Suites

### 1. Production Health Tests (`test_production_health.py`)

Verifies infrastructure and service health:

- API server is running and responding
- Database connection is active
- Redis cache is accessible (if configured)
- Prometheus metrics endpoint is working
- Response times meet SLA requirements
- Authentication endpoint is accessible
- Rate limiting is enforced
- CORS headers are configured
- Security headers are present
- Error handling returns proper responses
- SSL certificate is valid (for HTTPS)

**Expected Duration**: < 2 minutes

### 2. Critical Workflow Tests (`test_critical_workflows.py`)

Verifies core user functionality:

- User registration flow
- User login flow
- Authenticated API access
- Subscription management
- Lattice creation
- Lattice pathfinding
- Webhook registration
- Usage tracking
- Error recovery
- Bulk operations performance

**Expected Duration**: < 5 minutes

## Running Smoke Tests

### Prerequisites

```bash
# Install dependencies
pip install pytest requests

# Set production URL (required)
export PRODUCTION_URL=https://api.your-domain.com  # Linux/macOS
set PRODUCTION_URL=https://api.your-domain.com     # Windows
```

### Option 1: Automated Runner (Recommended)

**Linux/macOS:**
```bash
chmod +x smoke_test_runner.sh
./smoke_test_runner.sh
```

**Windows:**
```batch
smoke_test_runner.bat
```

The automated runner will:
- Check URL accessibility
- Verify Python environment
- Run all smoke tests
- Generate results report
- Save test artifacts

### Option 2: Manual Execution

**Run all smoke tests:**
```bash
pytest tests/smoke/ -v
```

**Run specific test suite:**
```bash
# Health checks only
pytest tests/smoke/test_production_health.py -v

# Critical workflows only
pytest tests/smoke/test_critical_workflows.py -v
```

**Run with detailed output:**
```bash
pytest tests/smoke/ -v --tb=short --color=yes
```

**Run and save results:**
```bash
pytest tests/smoke/ --junitxml=results/smoke_tests.xml
```

## Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PRODUCTION_URL` | Production API base URL | `http://localhost:8000` | Yes |
| `API_TIMEOUT` | Request timeout in seconds | `30` | No |
| `TEST_EMAIL` | Email for test user (auto-generated) | `smoketest-{uuid}@example.com` | No |
| `TEST_PASSWORD` | Password for test user | `SmokeTest123!@#` | No |

## Test Results

### Results Location

Automated runner saves results to `tests/smoke/results/`:
- `health_{timestamp}.xml` - Health check results (JUnit format)
- `workflows_{timestamp}.xml` - Workflow test results (JUnit format)
- `summary_{timestamp}.txt` - Test run summary

### Interpreting Results

**Success Indicators:**
- All tests pass (green checkmarks)
- Response times within SLA
- No critical errors
- All services healthy

**Failure Indicators:**
- Test failures (red X marks)
- Timeouts or connection errors
- HTTP 500 errors
- Services unreachable

**Warning Indicators:**
- Optional features unavailable (yellow warnings)
- Performance degradation
- Missing optional headers

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Smoke Tests
on:
  deployment_status:
    types: [success]

jobs:
  smoke-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: pip install pytest requests

      - name: Run smoke tests
        env:
          PRODUCTION_URL: ${{ secrets.PRODUCTION_URL }}
        run: |
          chmod +x tests/smoke/smoke_test_runner.sh
          ./tests/smoke/smoke_test_runner.sh

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: smoke-test-results
          path: tests/smoke/results/
```

### GitLab CI Example

```yaml
smoke_tests:
  stage: verify
  image: python:3.9
  script:
    - pip install pytest requests
    - export PRODUCTION_URL=$PRODUCTION_URL
    - chmod +x tests/smoke/smoke_test_runner.sh
    - ./tests/smoke/smoke_test_runner.sh
  artifacts:
    when: always
    reports:
      junit: tests/smoke/results/*.xml
    paths:
      - tests/smoke/results/
  only:
    - main
    - production
```

### Jenkins Example

```groovy
stage('Smoke Tests') {
    steps {
        script {
            sh '''
                pip install pytest requests
                export PRODUCTION_URL=${PRODUCTION_URL}
                chmod +x tests/smoke/smoke_test_runner.sh
                ./tests/smoke/smoke_test_runner.sh
            '''
        }
    }
    post {
        always {
            junit 'tests/smoke/results/*.xml'
            archiveArtifacts artifacts: 'tests/smoke/results/*', allowEmptyArchive: true
        }
    }
}
```

## Deployment Workflow

### Recommended Deployment Process

1. **Pre-Deployment**
   - Review production readiness checklist
   - Verify all pre-deployment tests pass
   - Schedule maintenance window (if needed)

2. **Deployment**
   - Deploy new version to production
   - Wait for deployment to complete
   - Verify pods/services are running

3. **Smoke Tests** ← **YOU ARE HERE**
   - Run automated smoke test runner
   - Verify all critical tests pass
   - Check test results and metrics

4. **Post-Deployment**
   - If tests pass: Monitor for 1-2 hours
   - If tests fail: Execute rollback plan
   - Notify stakeholders of deployment status

### Rollback Decision Matrix

| Scenario | Action | Reason |
|----------|--------|--------|
| All smoke tests pass | ✅ Proceed | Deployment successful |
| Health checks fail | 🔴 Rollback immediately | Critical infrastructure issue |
| < 50% workflows pass | 🔴 Rollback immediately | Major functionality broken |
| 50-80% workflows pass | 🟡 Investigate | Partial functionality issue |
| > 80% workflows pass | 🟢 Monitor closely | Minor issues acceptable |

## Troubleshooting

### Common Issues

**Issue: Connection Refused**
```
Error: requests.exceptions.ConnectionError: Connection refused
```
**Solution**:
- Verify PRODUCTION_URL is correct
- Check if service is actually deployed
- Verify network connectivity
- Check firewall/security group rules

**Issue: Authentication Failures**
```
Error: 401 Unauthorized
```
**Solution**:
- Verify JWT secret is configured
- Check token generation logic
- Ensure database is seeded with test data

**Issue: Timeout Errors**
```
Error: requests.exceptions.Timeout
```
**Solution**:
- Increase API_TIMEOUT value
- Check if services are under heavy load
- Verify database connections aren't exhausted

**Issue: SSL Certificate Errors**
```
Error: requests.exceptions.SSLError
```
**Solution**:
- Verify SSL certificate is valid
- Check certificate expiration
- Update certificate if expired

### Debug Mode

Run tests with maximum verbosity:

```bash
pytest tests/smoke/ -vv --tb=long --capture=no
```

## Best Practices

1. **Run After Every Deployment**: Make smoke tests mandatory
2. **Keep Tests Fast**: < 5 minutes total runtime
3. **Test Critical Paths Only**: Don't test every edge case
4. **Use Test Data**: Don't use production user data
5. **Clean Up**: Remove test data after runs (or use auto-cleanup)
6. **Monitor Trends**: Track test execution time and failures
7. **Alert on Failures**: Integrate with PagerDuty/Slack
8. **Version Lock**: Keep tests in sync with application version

## Maintenance

### Adding New Smoke Tests

1. Identify critical user workflow
2. Add test method to appropriate test class
3. Follow naming convention: `test_{workflow}_flow`
4. Keep test execution under 30 seconds
5. Use descriptive assertions and error messages
6. Update this README with new test description

### Removing Deprecated Tests

1. Verify workflow is no longer critical
2. Comment out test (don't delete immediately)
3. Monitor for one release cycle
4. Delete commented test if no issues

## Metrics and Reporting

### Key Metrics to Track

- **Test Pass Rate**: Percentage of tests passing
- **Execution Time**: Total time for all smoke tests
- **Test Reliability**: Flaky test percentage
- **Time to Detection**: How quickly issues are found
- **False Positive Rate**: Tests failing incorrectly

### Sample Dashboard Queries (Prometheus)

```promql
# Smoke test pass rate
sum(rate(smoke_test_passed_total[5m])) / sum(rate(smoke_test_total[5m]))

# Smoke test duration
histogram_quantile(0.95, rate(smoke_test_duration_seconds_bucket[5m]))

# Smoke test failures
increase(smoke_test_failed_total[1h])
```

## Contact

For issues with smoke tests:
- **DevOps Team**: devops@example.com
- **Slack Channel**: #production-deployments
- **On-Call**: Follow escalation process

---

**Last Updated**: 2025-10-06
**Maintained By**: DevOps Team
**Review Frequency**: Quarterly
