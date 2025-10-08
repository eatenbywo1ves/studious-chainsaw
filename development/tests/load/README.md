# Load Testing Framework - Catalytic Computing SaaS Platform

Comprehensive load testing suite built with Locust to validate performance, scalability, and stability of the Catalytic Computing SaaS platform.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Test Scenarios](#test-scenarios)
4. [Performance Targets](#performance-targets)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Docker Environment](#docker-environment)
8. [Results and Reports](#results-and-reports)
9. [Troubleshooting](#troubleshooting)
10. [Best Practices](#best-practices)

---

## Overview

This load testing framework provides comprehensive performance validation through five distinct test scenarios:

| Scenario | Users | Duration | Purpose |
|----------|-------|----------|---------|
| **Baseline** | 100 | 10 min | Normal operations |
| **Stress** | 500 | 5 min | High load capacity |
| **Spike** | 1000 | 5 min | Traffic surge handling |
| **Soak** | 50 | 4 hours | Stability & memory leaks |
| **Mixed** | 200 | 15 min | Realistic production traffic |

### Performance Targets

- **API Latency p95:** <500ms
- **API Latency p99:** <1000ms
- **Throughput:** >1000 req/s
- **Error Rate:** <1%

---

## Quick Start

### Prerequisites

- Python 3.8+
- Locust 2.15+
- Running SaaS API server (http://localhost:8000)
- PostgreSQL database
- Redis cache

### Installation

```bash
# Install dependencies
cd tests/load
pip install -r requirements.txt
```

### Run Your First Load Test

```bash
# Option 1: Using Python runner (recommended)
python run_load_tests.py --scenario baseline

# Option 2: Using shell script (Linux/Mac)
./run_load_tests.sh baseline

# Option 3: Using batch script (Windows)
run_load_tests.bat baseline

# Option 4: Direct Locust command
locust -f locustfile.py --host http://localhost:8000 \
       --tags baseline --users 100 --spawn-rate 10 --run-time 10m --headless
```

---

## Test Scenarios

### 1. Baseline Test

**Purpose:** Validate normal production operations

```bash
python run_load_tests.py --scenario baseline
```

**Configuration:**
- Users: 100 concurrent
- Spawn Rate: 10 users/second
- Duration: 10 minutes
- Operations: Registration, Login, Lattice CRUD, Health checks

**Expected Results:**
- All requests complete successfully
- p95 latency < 500ms
- Error rate < 0.1%
- No resource exhaustion

**Use Case:** Daily performance validation, regression testing

---

### 2. Stress Test

**Purpose:** Test system under high concurrent load

```bash
python run_load_tests.py --scenario stress
```

**Configuration:**
- Users: 500 concurrent
- Spawn Rate: 50 users/second
- Duration: 5 minutes
- Operations: Rapid CRUD operations, concurrent access

**Expected Results:**
- System remains stable
- p95 latency < 500ms
- Error rate < 1%
- No cascading failures

**Use Case:** Capacity planning, peak load validation

---

### 3. Spike Test

**Purpose:** Validate response to sudden traffic surges

```bash
python run_load_tests.py --scenario spike
```

**Configuration:**
- Users: 0 → 1000 in 60 seconds
- Spawn Rate: 1000 users/second (instant spike)
- Duration: 5 minutes total
- Operations: Burst API requests

**Expected Results:**
- System handles spike gracefully
- Rate limiting activates appropriately
- Quick recovery after spike
- No permanent degradation

**Use Case:** DDoS resilience, auto-scaling validation

---

### 4. Soak Test

**Purpose:** Detect memory leaks and long-term stability issues

```bash
python run_load_tests.py --scenario soak
```

**Configuration:**
- Users: 50 concurrent
- Spawn Rate: 5 users/second
- Duration: 4 hours
- Operations: Sustained continuous load

**Expected Results:**
- No memory leaks
- Stable performance over time
- No resource exhaustion
- Consistent response times

**Use Case:** Production readiness, stability validation

**Note:** This test takes 4 hours. Run during off-hours or use `--run-time 30m` for shorter validation.

---

### 5. Mixed Workload Test

**Purpose:** Simulate realistic production traffic patterns

```bash
python run_load_tests.py --scenario mixed
```

**Configuration:**
- Users: 200 concurrent
- Spawn Rate: 20 users/second
- Duration: 15 minutes

**Traffic Distribution:**
- 15% Authentication (login/register/refresh)
- 60% Read operations (list/get)
- 20% Write operations (create)
- 5% Delete operations

**Expected Results:**
- Realistic performance baseline
- Balanced resource utilization
- Stable under mixed operations

**Use Case:** Production simulation, capacity planning

---

## Installation

### Standard Installation

```bash
# Clone repository
cd C:/Users/Corbin/development/tests/load

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Verify installation
locust --version
```

### Docker Installation

```bash
# Install Docker and Docker Compose
# https://docs.docker.com/get-docker/

# Build and start environment
docker-compose -f docker-compose.load-test.yml up -d

# Verify containers are running
docker-compose -f docker-compose.load-test.yml ps
```

---

## Usage

### Interactive Web UI

Best for exploratory testing and real-time monitoring.

```bash
# Start Locust with Web UI
locust -f locustfile.py --host http://localhost:8000

# Open browser to http://localhost:8089
# Configure users, spawn rate, duration
# Start test and monitor in real-time
```

### Headless Mode (Automated)

Best for CI/CD pipelines and automated testing.

```bash
# Run specific scenario
locust -f locustfile.py --host http://localhost:8000 \
       --tags baseline --users 100 --spawn-rate 10 \
       --run-time 10m --headless \
       --html results/baseline_report.html \
       --csv results/baseline_stats

# Run all scenarios
python run_load_tests.py --scenario all
```

### Python Test Runner

Recommended approach for comprehensive testing.

```bash
# Run all scenarios (excludes 4-hour soak test)
python run_load_tests.py

# Run specific scenario
python run_load_tests.py --scenario baseline

# Include soak test (4 hours)
python run_load_tests.py --include-soak

# Custom host
python run_load_tests.py --host http://production.example.com

# Docker environment
python run_load_tests.py --docker
```

### Command Line Scripts

**Windows:**
```cmd
REM Run baseline test
run_load_tests.bat baseline

REM Run stress test
run_load_tests.bat stress http://localhost:8000
```

**Linux/Mac:**
```bash
# Run baseline test
./run_load_tests.sh baseline

# Run stress test
./run_load_tests.sh stress http://localhost:8000
```

---

## Docker Environment

### Full Stack Load Testing

The Docker Compose environment includes:
- Locust Master (Web UI)
- 2x Locust Workers (distributed load generation)
- SaaS API Server (test target)
- PostgreSQL Database
- Redis Cache
- Prometheus (metrics collection)
- Grafana (visualization)

### Start Environment

```bash
# Start all services
docker-compose -f docker-compose.load-test.yml up -d

# View logs
docker-compose -f docker-compose.load-test.yml logs -f

# Access services
# - Locust UI: http://localhost:8089
# - API Server: http://localhost:8000
# - Prometheus: http://localhost:9090
# - Grafana: http://localhost:3000 (admin/admin)
```

### Run Tests in Docker

```bash
# Run test in Docker environment
python run_load_tests.py --docker --scenario baseline

# Or use docker-compose directly
docker-compose -f docker-compose.load-test.yml run --rm locust-master \
  -f /mnt/locust/locustfile.py \
  --host http://saas-api:8000 \
  --tags baseline \
  --users 100 \
  --spawn-rate 10 \
  --run-time 10m \
  --headless
```

### Stop Environment

```bash
# Stop all services
docker-compose -f docker-compose.load-test.yml down

# Stop and remove volumes (clean slate)
docker-compose -f docker-compose.load-test.yml down -v
```

---

## Results and Reports

### Output Files

All results are saved to the `results/` directory:

```
results/
├── baseline_20251006_123000.html       # HTML report
├── baseline_20251006_123000_stats.csv  # Request statistics
├── baseline_20251006_123000_failures.csv  # Failure details
├── load_test_metrics_20251006_123000.json  # Custom metrics
└── summary_20251006_123000.json        # Overall summary
```

### HTML Report

Open `results/baseline_TIMESTAMP.html` in a browser to view:
- Request statistics (success/failure rates)
- Response time percentiles (p50, p95, p99)
- Requests per second over time
- Charts and visualizations

### CSV Statistics

Import into spreadsheet or analysis tool:
- Request counts by endpoint
- Response times (min, max, avg, percentiles)
- Failures and error rates
- Throughput metrics

### Metrics JSON

Custom metrics tracked by the framework:
```json
{
  "registrations": {
    "total": 100,
    "successful": 99,
    "failed": 1
  },
  "logins": {
    "total": 500,
    "successful": 498,
    "failed": 2
  },
  "lattice_operations": {
    "created": 250,
    "listed": 1000,
    "retrieved": 500,
    "deleted": 100
  }
}
```

### Analyzing Results

```bash
# View summary
cat results/summary_TIMESTAMP.json | jq

# Calculate success rate
# success_rate = (total_requests - failures) / total_requests * 100

# Check if targets met
# p95 < 500ms
# p99 < 1000ms
# error_rate < 1%
# throughput > 1000 req/s
```

---

## Troubleshooting

### High Failure Rate (>5%)

**Symptoms:**
- Many 500 Internal Server Error responses
- Request timeouts

**Diagnosis:**
1. Check API server logs
2. Monitor CPU/memory usage
3. Check database connections

**Solutions:**
- Reduce spawn rate (slower ramp-up)
- Increase API server workers
- Scale database connection pool
- Optimize slow queries

### Response Times Increase with Load

**Symptoms:**
- p95 starts low, increases to >1000ms
- CPU usage >90%

**Diagnosis:**
- CPU saturation bottleneck

**Solutions:**
- Scale API server horizontally
- Optimize CPU-intensive operations
- Enable caching
- Use async processing

### Connection Errors

**Symptoms:**
- "Connection refused" errors
- "Too many open files" errors

**Diagnosis:**
- System resource limits

**Solutions:**
```bash
# Increase file descriptors (Linux)
ulimit -n 65536

# Increase connection pool
# In API server config:
# pool_size=100, max_overflow=200
```

### Memory Leaks (Soak Test)

**Symptoms:**
- Memory grows continuously
- Eventually crashes (OOM)

**Diagnosis:**
- Memory leak in application

**Solutions:**
1. Profile with memory_profiler
2. Check for unclosed connections
3. Implement connection pooling
4. Review caching strategy

---

## Best Practices

### Before Running Tests

1. **Clean Environment**
   ```bash
   # Clear database
   # Restart API server
   # Flush Redis cache
   redis-cli FLUSHALL
   ```

2. **Baseline Metrics**
   ```bash
   # Record current performance
   # Note system resources (CPU, memory, disk)
   # Document test conditions
   ```

3. **Monitoring Setup**
   - Start Prometheus/Grafana
   - Monitor system resources
   - Watch API server logs

### During Tests

1. **Monitor in Real-Time**
   - Watch Locust Web UI (http://localhost:8089)
   - Monitor system resources
   - Check error logs

2. **Gradual Ramp-Up**
   - Don't spike instantly (except spike test)
   - Use appropriate spawn rates
   - Allow system to stabilize

3. **Document Observations**
   - Note any anomalies
   - Record error patterns
   - Track resource utilization

### After Tests

1. **Analyze Results**
   - Compare against targets
   - Identify bottlenecks
   - Review error patterns

2. **Generate Reports**
   - Document findings
   - Create action items
   - Plan optimizations

3. **Clean Up**
   ```bash
   # Archive results
   mkdir -p archive/$(date +%Y%m%d)
   mv results/*.html archive/$(date +%Y%m%d)/

   # Stop services
   docker-compose -f docker-compose.load-test.yml down
   ```

### Ramp-Up Recommendations

| Users | Spawn Rate | Ramp-Up Time |
|-------|------------|--------------|
| 100 | 10/s | 10 seconds |
| 500 | 50/s | 10 seconds |
| 1000 | 100/s | 10 seconds |
| 5000 | 100/s | 50 seconds |
| 10000 | 200/s | 50 seconds |

### Test Frequency

- **Baseline:** Daily (automated)
- **Stress:** Weekly
- **Spike:** Weekly
- **Soak:** Monthly or before major releases
- **Mixed:** Weekly

---

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Load Testing

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  load-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: |
          cd tests/load
          pip install -r requirements.txt

      - name: Start services
        run: |
          cd tests/load
          docker-compose -f docker-compose.load-test.yml up -d
          sleep 30  # Wait for services

      - name: Run baseline test
        run: |
          cd tests/load
          python run_load_tests.py --scenario baseline

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: load-test-results
          path: tests/load/results/

      - name: Cleanup
        run: |
          cd tests/load
          docker-compose -f docker-compose.load-test.yml down
```

---

## Performance Baselines

See [PERFORMANCE_BASELINES.md](PERFORMANCE_BASELINES.md) for detailed performance targets and historical results.

---

## Support

For issues or questions:
1. Check [Troubleshooting](#troubleshooting) section
2. Review API server logs
3. Check system resources
4. Consult [Locust Documentation](https://docs.locust.io/)

---

## Version History

- **v1.0.0** (2025-10-06): Initial release
  - 5 comprehensive test scenarios
  - Docker support
  - Automated test runner
  - Performance baselines

---

**Last Updated:** 2025-10-06
**Status:** Production Ready
**Next Steps:** Execute load tests and establish performance baselines
