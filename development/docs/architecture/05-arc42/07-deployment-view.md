# 7. Deployment View

## 7.1 Infrastructure Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Cloud Infrastructure                               │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                        Load Balancer (Nginx)                        │    │
│  │                    Public IP: xxx.xxx.xxx.xxx                       │    │
│  │                    SSL Termination, Rate Limiting                   │    │
│  └─────────────────────────────┬──────────────────────────────────────┘    │
│                                │                                            │
│  ┌─────────────────────────────▼──────────────────────────────────────┐    │
│  │                     Kubernetes Cluster                              │    │
│  │                                                                     │    │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐    │    │
│  │  │   Node Pool 1   │  │   Node Pool 2   │  │   Node Pool 3   │    │    │
│  │  │   (CPU/Mem)     │  │   (CPU/Mem)     │  │     (GPU)       │    │    │
│  │  │                 │  │                 │  │                 │    │    │
│  │  │ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │    │    │
│  │  │ │  SaaS API   │ │  │ │  GhidraGo   │ │  │ │  Catalytic  │ │    │    │
│  │  │ │  (4 pods)   │ │  │ │  (2 pods)   │ │  │ │  (2 pods)   │ │    │    │
│  │  │ └─────────────┘ │  │ └─────────────┘ │  │ └─────────────┘ │    │    │
│  │  │ ┌─────────────┐ │  │                 │  │                 │    │    │
│  │  │ │   Nginx     │ │  │                 │  │                 │    │    │
│  │  │ │  Ingress    │ │  │                 │  │                 │    │    │
│  │  │ └─────────────┘ │  │                 │  │                 │    │    │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘    │    │
│  │                                                                     │    │
│  │  ┌───────────────────────────────────────────────────────────┐    │    │
│  │  │                    StatefulSets                            │    │    │
│  │  │ ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐    │    │    │
│  │  │ │ PostgreSQL  │  │    Redis    │  │   Prometheus    │    │    │    │
│  │  │ │ (Primary)   │  │  (Cluster)  │  │    (Server)     │    │    │    │
│  │  │ └─────────────┘  └─────────────┘  └─────────────────┘    │    │    │
│  │  └───────────────────────────────────────────────────────────┘    │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                         Persistent Storage                          │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐    │    │
│  │  │  PG Data    │  │ Redis AOF   │  │    Binary Storage       │    │    │
│  │  │   100GB     │  │    20GB     │  │       500GB             │    │    │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────┘    │    │
│  └────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 7.2 Node Specifications

### CPU Node Pool (Application Services)

| Specification | Value |
|---------------|-------|
| Instance Type | 4 vCPU, 16GB RAM |
| Count | 3-6 (auto-scaling) |
| OS | Ubuntu 22.04 LTS |
| Container Runtime | containerd |

### GPU Node Pool (Compute Services)

| Specification | Value |
|---------------|-------|
| Instance Type | 8 vCPU, 32GB RAM, NVIDIA T4 |
| Count | 2-4 (manual scaling) |
| OS | Ubuntu 22.04 LTS |
| CUDA | 12.1 |
| Driver | 535.x |

## 7.3 Kubernetes Resources

### SaaS API Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: saas-api
  namespace: catalytic
spec:
  replicas: 4
  selector:
    matchLabels:
      app: saas-api
  template:
    metadata:
      labels:
        app: saas-api
    spec:
      containers:
      - name: saas-api
        image: catalytic/saas-api:latest
        ports:
        - containerPort: 8000
        resources:
          requests:
            cpu: "500m"
            memory: "1Gi"
          limits:
            cpu: "2"
            memory: "4Gi"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: catalytic-secrets
              key: database-url
```

### Catalytic Engine Deployment (GPU)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: catalytic-engine
  namespace: catalytic
spec:
  replicas: 2
  selector:
    matchLabels:
      app: catalytic-engine
  template:
    spec:
      nodeSelector:
        nvidia.com/gpu: "true"
      containers:
      - name: catalytic-engine
        image: catalytic/engine:latest
        ports:
        - containerPort: 8001
        resources:
          requests:
            cpu: "2"
            memory: "8Gi"
            nvidia.com/gpu: 1
          limits:
            cpu: "4"
            memory: "16Gi"
            nvidia.com/gpu: 1
```

### Horizontal Pod Autoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: saas-api-hpa
  namespace: catalytic
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: saas-api
  minReplicas: 4
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## 7.4 Network Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Network Topology                              │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Public Subnet (10.0.0.0/24)               │   │
│  │  ┌─────────────────┐                                         │   │
│  │  │  Load Balancer  │  ◄── Internet Traffic                   │   │
│  │  │   10.0.0.10     │                                         │   │
│  │  └────────┬────────┘                                         │   │
│  └───────────┼─────────────────────────────────────────────────┘   │
│              │                                                      │
│  ┌───────────▼─────────────────────────────────────────────────┐   │
│  │                 Application Subnet (10.0.1.0/24)             │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │   │
│  │  │SaaS Pods │  │ Catalytic│  │ GhidraGo │  │  Ingress │    │   │
│  │  │10.0.1.x  │  │10.0.1.x  │  │10.0.1.x  │  │10.0.1.5  │    │   │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   Data Subnet (10.0.2.0/24)                  │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │   │
│  │  │  PostgreSQL  │  │    Redis     │  │    Vault     │      │   │
│  │  │  10.0.2.10   │  │  10.0.2.20   │  │  10.0.2.30   │      │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                Management Subnet (10.0.3.0/24)               │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │   │
│  │  │  Prometheus  │  │   Grafana    │  │  Logging     │      │   │
│  │  │  10.0.3.10   │  │  10.0.3.20   │  │  10.0.3.30   │      │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘      │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## 7.5 Environment Configuration

| Environment | Purpose | Scale | Resources |
|-------------|---------|-------|-----------|
| Development | Local testing | 1 node | Minikube |
| Staging | Pre-production | 3 nodes | 50% of prod |
| Production | Live traffic | 6+ nodes | Full capacity |

### Production vs Staging

| Resource | Staging | Production |
|----------|---------|------------|
| SaaS API replicas | 2 | 4-20 |
| Catalytic replicas | 1 | 2-4 |
| PostgreSQL | Single | Primary + Replica |
| Redis | Single | Cluster (3 nodes) |
| GPU nodes | 1 | 2-4 |

---
**Last Updated**: 2024-10-15
