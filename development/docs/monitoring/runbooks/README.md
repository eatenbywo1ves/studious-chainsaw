# Operational Runbooks

**Quick response guides for production incidents**

These runbooks provide step-by-step procedures for diagnosing and resolving common production issues. Each runbook follows a standard format: symptoms, diagnosis, remediation, and prevention.

---

## Available Runbooks

### Performance Issues

#### [High API Latency](./high_api_latency.md)
**Symptoms**: API response times > 500ms, user complaints about slow performance
**When to use**: P95 latency exceeds SLA thresholds

#### [GPU Memory Exhaustion](./gpu_memory_exhaustion.md)
**Symptoms**: CUDA out-of-memory errors, GPU utilization drops to 0%
**When to use**: GPU workloads failing or performance degrading

### Resource Issues

#### [Database Connection Pool](./database_connection_pool.md)
**Symptoms**: Connection timeout errors, database connection errors in logs
**When to use**: Applications unable to acquire database connections

#### [Redis Memory Pressure](./redis_memory_pressure.md)
**Symptoms**: Redis evicting keys, memory usage > 80%, cache misses increasing
**When to use**: Redis memory alerts firing or degraded cache performance

### Service Availability

#### [High Error Rate](./high_error_rate.md)
**Symptoms**: 5xx errors > 1%, error rate alerts firing
**When to use**: Elevated error rates across services

#### [Service Unavailable](./service_unavailable.md)
**Symptoms**: Service health checks failing, 503 responses, pods not ready
**When to use**: Complete service outage or degraded availability

---

## Runbook Structure

Each runbook follows this format:

1. **Overview** - Description and impact
2. **Symptoms** - How to identify the issue
3. **Quick Diagnosis** - Fast checks to confirm root cause
4. **Immediate Actions** - Steps to restore service
5. **Detailed Investigation** - Deep dive for persistent issues
6. **Prevention** - Long-term fixes to prevent recurrence
7. **Related Runbooks** - Links to related procedures

---

## Using Runbooks

### During an Incident

1. **Identify symptoms** from alerts or monitoring dashboards
2. **Select appropriate runbook** from the list above
3. **Follow Quick Diagnosis** to confirm the issue
4. **Execute Immediate Actions** to restore service
5. **Document findings** in incident log
6. **Schedule follow-up** for prevention measures

### After Resolution

1. Review **Prevention** section
2. Update runbook if new information learned
3. Consider adding automation for common fixes
4. Share learnings with team

---

## Getting Help

If runbooks don't resolve the issue:

1. Check [Monitoring Dashboard](../dashboard_guide.md) for related metrics
2. Review [Metrics Catalog](../metrics_catalog.md) for additional signals
3. Escalate using incident management procedures
4. Document the incident for future runbook updates

---

## Contributing

To add or update a runbook:

1. Use the standard runbook template
2. Include real examples from incidents
3. Add diagnostic commands that actually work
4. Test procedures in staging first
5. Link related runbooks for context

---

**Last Updated**: 2025-10-22
**Maintained by**: Operations Team

[← Back to Monitoring Docs](../README.md) | [Monitoring Dashboard Guide →](../dashboard_guide.md)
