# ADR-011: Kubernetes for Production Orchestration

**Status**: Accepted | **Date**: 2024-10-10 | **Deciders**: DevOps, SRE

## Decision
Use **Kubernetes** for production container orchestration.

## Key Features
- **HPA**: Auto-scale 4-20 replicas based on CPU
- **Resource Quotas**: Prod (100 CPU, 200Gi), Staging (40 CPU, 64Gi)
- **Network Policies**: Pod-to-pod isolation
- **Health Checks**: Liveness/readiness probes

## Resource Allocation
```yaml
resources:
  requests:
    cpu: "2"
    memory: "4Gi"
  limits:
    cpu: "4"
    memory: "8Gi"
```

## Scaling Policy
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
spec:
  minReplicas: 4
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## Alternatives Rejected
- **Docker Swarm**: Less mature, smaller ecosystem
- **ECS**: AWS lock-in
- **Nomad**: Smaller community

---
**Last Updated**: 2024-10-15
