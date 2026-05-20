# Deployment Architecture: Kubernetes

## Cluster Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Kubernetes Cluster                                   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Control Plane                                 │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │   │
│  │  │  API Server  │  │  Scheduler   │  │  Controller Manager      │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      catalytic Namespace                             │   │
│  │                                                                      │   │
│  │  Deployments:                                                        │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │   │
│  │  │  saas-api    │  │  catalytic   │  │      ghidrago            │  │   │
│  │  │  (4 pods)    │  │  (2 pods)    │  │      (2 pods)            │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │   │
│  │                                                                      │   │
│  │  StatefulSets:                                                       │   │
│  │  ┌──────────────┐  ┌──────────────┐                                 │   │
│  │  │  postgresql  │  │    redis     │                                 │   │
│  │  │  (1 primary) │  │  (3 nodes)   │                                 │   │
│  │  └──────────────┘  └──────────────┘                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      monitoring Namespace                            │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │   │
│  │  │  prometheus  │  │   grafana    │  │     alertmanager         │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        vault Namespace                               │   │
│  │  ┌──────────────────────────────────────────────────────────────┐  │   │
│  │  │  vault (HA: 3 pods with Raft storage)                         │  │   │
│  │  └──────────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Namespace Configuration

### catalytic Namespace
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: catalytic
  labels:
    name: catalytic
    environment: production
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: catalytic-quota
  namespace: catalytic
spec:
  hard:
    requests.cpu: "100"
    requests.memory: 200Gi
    limits.cpu: "200"
    limits.memory: 400Gi
    pods: "100"
    services: "20"
```

## Deployment Manifests

### SaaS API Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: saas-api
  namespace: catalytic
  labels:
    app: saas-api
    version: v1
spec:
  replicas: 4
  selector:
    matchLabels:
      app: saas-api
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    metadata:
      labels:
        app: saas-api
        version: v1
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8000"
    spec:
      serviceAccountName: saas-api
      containers:
      - name: saas-api
        image: catalytic/saas-api:1.2.3
        ports:
        - containerPort: 8000
          name: http
        resources:
          requests:
            cpu: "500m"
            memory: "1Gi"
          limits:
            cpu: "2"
            memory: "4Gi"
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: catalytic-db
              key: url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: catalytic-redis
              key: url
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 10
          periodSeconds: 30
          timeoutSeconds: 5
        readinessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 3
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
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
    metadata:
      labels:
        app: catalytic-engine
    spec:
      nodeSelector:
        nvidia.com/gpu: "true"
      tolerations:
      - key: "nvidia.com/gpu"
        operator: "Exists"
        effect: "NoSchedule"
      containers:
      - name: catalytic-engine
        image: catalytic/engine:1.2.3
        ports:
        - containerPort: 8001
        resources:
          requests:
            cpu: "4"
            memory: "16Gi"
            nvidia.com/gpu: 1
          limits:
            cpu: "8"
            memory: "32Gi"
            nvidia.com/gpu: 1
        env:
        - name: CUDA_VISIBLE_DEVICES
          value: "0"
        volumeMounts:
        - name: shm
          mountPath: /dev/shm
      volumes:
      - name: shm
        emptyDir:
          medium: Memory
          sizeLimit: 8Gi
```

## Service Configuration

### ClusterIP Services
```yaml
apiVersion: v1
kind: Service
metadata:
  name: saas-api
  namespace: catalytic
spec:
  type: ClusterIP
  selector:
    app: saas-api
  ports:
  - port: 8000
    targetPort: http
    name: http
---
apiVersion: v1
kind: Service
metadata:
  name: catalytic-engine
  namespace: catalytic
spec:
  type: ClusterIP
  selector:
    app: catalytic-engine
  ports:
  - port: 8001
    targetPort: 8001
    name: http
```

### Ingress Configuration
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: catalytic-ingress
  namespace: catalytic
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "100m"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - api.catalytic.dev
    secretName: catalytic-tls
  rules:
  - host: api.catalytic.dev
    http:
      paths:
      - path: /api/v1
        pathType: Prefix
        backend:
          service:
            name: saas-api
            port:
              number: 8000
      - path: /compute
        pathType: Prefix
        backend:
          service:
            name: catalytic-engine
            port:
              number: 8001
```

## Auto-Scaling

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
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
```

## Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: saas-api-policy
  namespace: catalytic
spec:
  podSelector:
    matchLabels:
      app: saas-api
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - port: 8000
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgresql
    ports:
    - port: 5432
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - port: 6379
  - to:
    - namespaceSelector:
        matchLabels:
          name: vault
    ports:
    - port: 8200
```

## Secrets Management

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: catalytic-db
  namespace: catalytic
type: Opaque
data:
  url: <base64-encoded-url>
---
# Using External Secrets Operator for Vault integration
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: catalytic-secrets
  namespace: catalytic
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: catalytic-app-secrets
  data:
  - secretKey: jwt-private-key
    remoteRef:
      key: secret/catalytic/jwt
      property: private_key
```

---
**Last Updated**: 2024-10-15
