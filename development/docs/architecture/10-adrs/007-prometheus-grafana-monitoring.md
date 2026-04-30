# ADR-007: Prometheus + Grafana Monitoring

**Status**: Accepted | **Date**: 2024-10-01 | **Deciders**: DevOps, SRE

## Decision
Use **Prometheus** for metrics collection and **Grafana** for visualization.

## Rationale
- Industry standard observability stack
- Pull-based architecture (scalable)
- Native Kubernetes integration
- Rich ecosystem (exporters, dashboards)

## Key Metrics
- `http_request_duration_seconds` - API latency
- `db_connections_active` - Database health
- `redis_keyspace_hits_total` - Cache performance
- `catalytic_memory_efficiency_ratio` - GPU efficiency

## Alternatives Rejected
- **Datadog**: Cost at scale, vendor lock-in
- **ELK Stack**: Better for logs, not metrics
- **CloudWatch**: AWS-specific

---
**Last Updated**: 2024-10-15
