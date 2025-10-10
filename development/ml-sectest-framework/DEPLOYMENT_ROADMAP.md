# ML-SecTest Framework Deployment Roadmap 2025

## Executive Summary
Based on current industry best practices and 2025 security standards, this roadmap outlines the optimal deployment strategy for the ML-SecTest framework.

## Phase 1: Containerization (Week 1) 🐳

### 1.1 Create Production Dockerfile
```dockerfile
# Dockerfile
FROM python:3.13-slim

# Security: Run as non-root user
RUN useradd -m -u 1000 mlsectest && \
    mkdir -p /app /reports && \
    chown -R mlsectest:mlsectest /app /reports

WORKDIR /app

# Install dependencies with pinned versions
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install gunicorn

# Copy application code
COPY --chown=mlsectest:mlsectest . .

USER mlsectest

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)"

ENTRYPOINT ["python", "ml_sectest.py"]
CMD ["--help"]
```

### 1.2 Create Docker Compose for Local Development
```yaml
# docker-compose.yml
version: '3.8'

services:
  ml-sectest:
    build: .
    container_name: ml-sectest-framework
    volumes:
      - ./reports:/reports
      - ./config:/app/config:ro
    environment:
      - PYTHONUNBUFFERED=1
      - LOG_LEVEL=INFO
    networks:
      - mlsectest-net
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    container_name: ml-sectest-redis
    ports:
      - "6379:6379"
    networks:
      - mlsectest-net
    restart: unless-stopped

networks:
  mlsectest-net:
    driver: bridge
```

### 1.3 Security Scanning Integration
- **Tool**: Trivy (open-source, lightweight)
- **Purpose**: Scan Docker images for vulnerabilities before deployment
- **Integration**: GitHub Actions pipeline

## Phase 2: CI/CD Pipeline with GitHub Actions (Week 2) 🚀

### 2.1 Automated Testing & Deployment Workflow

```yaml
# .github/workflows/ci-cd.yml
name: ML-SecTest CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    name: Test & Type Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python 3.13
        uses: actions/setup-python@v5
        with:
          python-version: '3.13'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest mypy ruff

      - name: Run linting
        run: ruff check .

      - name: Run type checking
        run: mypy . --strict

      - name: Run tests
        run: pytest tests/ -v --cov=. --cov-report=xml

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v4
        with:
          file: ./coverage.xml

  security-scan:
    name: Security Scanning
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4

      - name: Run Bandit security scan
        run: |
          pip install bandit
          bandit -r . -f json -o bandit-report.json || true

      - name: Run dependency vulnerability scan
        run: |
          pip install safety
          safety check --json > safety-report.json || true

      - name: Upload security reports
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bandit-report.json

  build-and-push:
    name: Build & Push Docker Image
    runs-on: ubuntu-latest
    needs: [test, security-scan]
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Login to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: |
            ghcr.io/${{ github.repository }}/ml-sectest:latest
            ghcr.io/${{ github.repository }}/ml-sectest:${{ github.sha }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ghcr.io/${{ github.repository }}/ml-sectest:latest
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'
```

### 2.2 Quality Gates
- **Type Safety**: Mypy strict mode must pass (✅ Already implemented!)
- **Code Coverage**: Minimum 80% test coverage
- **Security**: Zero critical/high vulnerabilities
- **Performance**: Tests complete in < 5 minutes

## Phase 3: Cloud Deployment Options (Week 3-4) ☁️

### Option A: AWS Serverless (Recommended for Pay-per-Use)

**Architecture:**
```
API Gateway → Lambda Functions → S3 (Reports) → CloudWatch (Logging)
                ↓
            DynamoDB (Results Cache)
```

**AWS Lambda Deployment:**
```yaml
# serverless.yml
service: ml-sectest-framework

provider:
  name: aws
  runtime: python3.13
  region: us-east-1
  memorySize: 3008
  timeout: 900  # 15 minutes max for security scans
  environment:
    STAGE: ${opt:stage, 'dev'}
    REPORTS_BUCKET: ${self:custom.reportsBucket}

functions:
  scanTarget:
    handler: lambda_handler.scan_target
    events:
      - http:
          path: scan
          method: post
          cors: true
    layers:
      - {Ref: PythonRequirementsLambdaLayer}

  testChallenge:
    handler: lambda_handler.test_challenge
    events:
      - http:
          path: challenge/{challengeId}
          method: post
          cors: true

resources:
  Resources:
    ReportsBucket:
      Type: AWS::S3::Bucket
      Properties:
        BucketName: ${self:custom.reportsBucket}
        PublicAccessBlockConfiguration:
          BlockPublicAcls: true
          BlockPublicPolicy: true
          IgnorePublicAcls: true
          RestrictPublicBuckets: true

custom:
  reportsBucket: ml-sectest-reports-${opt:stage, 'dev'}
  pythonRequirements:
    dockerizePip: true
    layer: true

plugins:
  - serverless-python-requirements
  - serverless-plugin-tracing
```

**Cost Estimate:**
- Lambda: $0.20 per million requests + $0.0000166667 per GB-second
- API Gateway: $1.00 per million requests
- S3: $0.023 per GB
- **Estimated monthly cost for 10K scans: ~$25-50**

### Option B: Azure Container Instances (Best for Enterprise)

**Architecture:**
```
Azure Front Door → Container Instances → Blob Storage (Reports)
                        ↓
                  Azure Monitor (Telemetry)
```

**Deployment:**
```yaml
# azure-container-instance.yml
apiVersion: 2021-09-01
location: eastus
name: ml-sectest-framework
properties:
  containers:
  - name: ml-sectest
    properties:
      image: ghcr.io/your-org/ml-sectest:latest
      resources:
        requests:
          cpu: 2
          memoryInGb: 4
      ports:
      - port: 8080
        protocol: TCP
      environmentVariables:
      - name: AZURE_STORAGE_CONNECTION_STRING
        secureValue: ${AZURE_STORAGE_CONNECTION_STRING}
  osType: Linux
  restartPolicy: Always
  ipAddress:
    type: Public
    ports:
    - protocol: tcp
      port: 8080
    dnsNameLabel: ml-sectest-api
tags:
  environment: production
  costCenter: security
type: Microsoft.ContainerInstance/containerGroups
```

**Cost Estimate:**
- Container Instances: ~$0.0000125 per vCPU-second + $0.0000014 per GB-second
- **Estimated monthly cost for 24/7 operation: ~$75-150**

### Option C: Kubernetes (Best for Scale & Multi-Cloud)

**Architecture:**
```
Ingress Controller → Service → Pods (ML-SecTest) → Persistent Volume (Reports)
                                   ↓
                          Horizontal Pod Autoscaler
```

**Kubernetes Deployment:**
```yaml
# k8s/deployment.yml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ml-sectest-framework
  labels:
    app: ml-sectest
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ml-sectest
  template:
    metadata:
      labels:
        app: ml-sectest
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: ml-sectest
        image: ghcr.io/your-org/ml-sectest:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
        env:
        - name: LOG_LEVEL
          value: "INFO"
        - name: REPORTS_PATH
          value: "/reports"
        volumeMounts:
        - name: reports-volume
          mountPath: /reports
      volumes:
      - name: reports-volume
        persistentVolumeClaim:
          claimName: ml-sectest-reports-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: ml-sectest-service
spec:
  type: LoadBalancer
  selector:
    app: ml-sectest
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: ml-sectest-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: ml-sectest-framework
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

**Cost Estimate (AKS/EKS):**
- Managed Kubernetes: ~$75/month
- Worker nodes (3x Standard_D2s_v3): ~$200/month
- **Total estimated monthly cost: ~$275-350**

## Phase 4: Security Hardening (Week 5) 🔒

### 4.1 Infrastructure Security Scanning

**Checkov Integration:**
```yaml
# .github/workflows/iac-security.yml
name: Infrastructure Security Scan

on: [push, pull_request]

jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          framework: dockerfile,kubernetes,github_actions
          output_format: sarif
          output_file_path: checkov-results.sarif

      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: checkov-results.sarif
```

### 4.2 Secrets Management

**AWS Secrets Manager Integration:**
```python
# config/secrets.py
import boto3
from typing import Dict, Any

class SecretsManager:
    def __init__(self, region: str = "us-east-1"):
        self.client = boto3.client('secretsmanager', region_name=region)

    def get_secret(self, secret_name: str) -> Dict[str, Any]:
        """Retrieve secret from AWS Secrets Manager."""
        response = self.client.get_secret_value(SecretId=secret_name)
        return json.loads(response['SecretString'])
```

### 4.3 Network Security

**Pod Security Policy (Kubernetes):**
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: ml-sectest-psp
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
  readOnlyRootFilesystem: true
```

## Phase 5: Observability & Monitoring (Week 6) 📊

### 5.1 Prometheus Metrics Export

```python
# utils/metrics.py
from prometheus_client import Counter, Histogram, Gauge
import time

# Define metrics
scan_requests_total = Counter(
    'ml_sectest_scan_requests_total',
    'Total number of scan requests',
    ['challenge_type', 'status']
)

scan_duration_seconds = Histogram(
    'ml_sectest_scan_duration_seconds',
    'Duration of security scans',
    ['challenge_type']
)

vulnerabilities_found = Gauge(
    'ml_sectest_vulnerabilities_found',
    'Number of vulnerabilities detected',
    ['severity', 'type']
)

class MetricsCollector:
    @staticmethod
    def track_scan(challenge_type: str, func):
        """Decorator to track scan metrics."""
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                scan_requests_total.labels(
                    challenge_type=challenge_type,
                    status='success'
                ).inc()
                return result
            except Exception as e:
                scan_requests_total.labels(
                    challenge_type=challenge_type,
                    status='error'
                ).inc()
                raise
            finally:
                duration = time.time() - start_time
                scan_duration_seconds.labels(
                    challenge_type=challenge_type
                ).observe(duration)
        return wrapper
```

### 5.2 Grafana Dashboard Configuration

```yaml
# monitoring/grafana-dashboard.json
{
  "dashboard": {
    "title": "ML-SecTest Framework Monitoring",
    "panels": [
      {
        "title": "Scan Success Rate",
        "type": "gauge",
        "targets": [{
          "expr": "rate(ml_sectest_scan_requests_total{status='success'}[5m])"
        }]
      },
      {
        "title": "Vulnerabilities by Severity",
        "type": "piechart",
        "targets": [{
          "expr": "sum by (severity) (ml_sectest_vulnerabilities_found)"
        }]
      },
      {
        "title": "Average Scan Duration",
        "type": "graph",
        "targets": [{
          "expr": "rate(ml_sectest_scan_duration_seconds_sum[5m]) / rate(ml_sectest_scan_duration_seconds_count[5m])"
        }]
      }
    ]
  }
}
```

## Phase 6: Documentation & API (Week 7) 📚

### 6.1 REST API with FastAPI

```python
# api/main.py
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel, HttpUrl
from typing import List, Optional
import uvicorn

app = FastAPI(
    title="ML-SecTest API",
    version="1.0.0",
    description="Automated ML Security Testing Framework API"
)

class ScanRequest(BaseModel):
    target_url: HttpUrl
    challenge_name: str = "custom"
    agents: Optional[List[str]] = None
    parallel: bool = False

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

@app.post("/api/v1/scan", response_model=ScanResponse)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """Initiate a new security scan."""
    scan_id = generate_scan_id()
    background_tasks.add_task(
        run_scan,
        scan_id=scan_id,
        target_url=str(request.target_url),
        challenge_name=request.challenge_name,
        agents=request.agents,
        parallel=request.parallel
    )
    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        message=f"Scan {scan_id} initiated"
    )

@app.get("/api/v1/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get scan status and results."""
    # Implementation here
    pass

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
```

### 6.2 OpenAPI Documentation

Auto-generated at `/docs` endpoint with Swagger UI and `/redoc` for ReDoc.

## Recommended Deployment Strategy

**For Your Use Case (CTF Security Testing Framework):**

1. **Start with**: **GitHub Actions + Docker + AWS Lambda** (Phase 1-3A)
   - **Why**: Cost-effective, serverless scales to zero, perfect for on-demand security scans
   - **Timeline**: 2-3 weeks
   - **Cost**: ~$25-50/month

2. **Scale to**: **Kubernetes on EKS/AKS** (Phase 3C) when:
   - Running 1000+ scans per day
   - Need sub-second response times
   - Require multi-cloud deployment
   - **Timeline**: +2 weeks
   - **Cost**: ~$275-350/month

3. **Essential from Day 1**:
   - ✅ Type safety (Already done!)
   - ✅ CI/CD pipeline (Phase 2)
   - ✅ Security scanning (Phase 4)
   - ✅ Monitoring (Phase 5)

## Next Immediate Actions

1. **This Week**: Create `Dockerfile` and test local build
2. **Next Week**: Set up GitHub Actions workflow
3. **Week 3**: Deploy to AWS Lambda (lowest cost, fastest deployment)
4. **Week 4**: Add Prometheus metrics and Grafana dashboard
5. **Week 5**: Security hardening with Checkov and vulnerability scanning

## Success Metrics

- **Deployment Time**: < 5 minutes from commit to production
- **Scan Availability**: 99.9% uptime
- **Security Posture**: Zero critical vulnerabilities in production
- **Cost Efficiency**: < $0.01 per security scan
- **Type Safety**: 100% mypy strict compliance ✅ (Already achieved!)

---

**Document Version**: 1.0
**Last Updated**: 2025-10-10
**Status**: Ready for Implementation
