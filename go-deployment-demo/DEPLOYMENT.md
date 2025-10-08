# Deployment Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Local Deployment](#local-deployment)
4. [Docker Deployment](#docker-deployment)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Cloud Platform Deployment](#cloud-platform-deployment)
7. [Monitoring & Troubleshooting](#monitoring--troubleshooting)

## Prerequisites

### Required Software
- **Go**: Version 1.25.1+ ([Download](https://go.dev/dl/))
- **Docker**: For containerization ([Download](https://www.docker.com/get-started))
- **kubectl**: For Kubernetes deployment ([Install](https://kubernetes.io/docs/tasks/tools/))
- **Git**: For version control

### Verify Installation
```bash
go version          # Should show go1.25.1 or later
docker --version    # Should show Docker version
kubectl version     # Should show kubectl version
```

## Environment Setup

### 1. Clone/Download Project
```bash
cd C:/Users/Corbin/go-deployment-demo
```

### 2. Set Environment Variables
Create a `.env` file (copy from `.env.example`):
```bash
PORT=8080
ENVIRONMENT=development
VERSION=1.0.0
```

## Local Deployment

### Option 1: Run from Source
```bash
# Set environment variables
set PORT=8080
set ENVIRONMENT=development

# Run the application
go run main.go
```

### Option 2: Build and Run Binary
```bash
# Build
go build -o go-deployment-demo.exe

# Run
./go-deployment-demo.exe
```

### Verify Local Deployment
```bash
# Test health endpoint
curl http://localhost:8080/health

# Expected output:
# {"status":"healthy","version":"1.0.0","environment":"development","timestamp":"..."}
```

## Docker Deployment

### Step 1: Build Docker Image
```bash
cd C:/Users/Corbin/go-deployment-demo

docker build -t go-deployment-demo:1.0.0 .
```

**Build Process**:
- Stage 1: Compiles Go code (golang:1.25.1-alpine)
- Stage 2: Creates minimal runtime (scratch base)
- Final image size: ~10.3MB

### Step 2: Run Container Locally
```bash
# Run in detached mode
docker run -d \
  --name go-demo \
  -p 8080:8080 \
  -e ENVIRONMENT=production \
  -e VERSION=1.0.0 \
  go-deployment-demo:1.0.0

# View logs
docker logs go-demo

# Follow logs
docker logs -f go-demo
```

### Step 3: Test Container
```bash
# Health check
curl http://localhost:8080/health

# Readiness check
curl http://localhost:8080/ready

# Metrics
curl http://localhost:8080/metrics

# Home page
curl http://localhost:8080/
```

### Step 4: Container Management
```bash
# Stop container
docker stop go-demo

# Start container
docker start go-demo

# Remove container
docker rm go-demo

# View running containers
docker ps

# View all containers
docker ps -a
```

### Push to Registry (Optional)

#### Docker Hub
```bash
# Tag image
docker tag go-deployment-demo:1.0.0 username/go-deployment-demo:1.0.0

# Login
docker login

# Push
docker push username/go-deployment-demo:1.0.0
```

#### AWS ECR
```bash
# Authenticate
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com

# Tag
docker tag go-deployment-demo:1.0.0 \
  ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/go-deployment-demo:1.0.0

# Push
docker push ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/go-deployment-demo:1.0.0
```

## Kubernetes Deployment

### Step 1: Prepare Kubernetes Cluster
```bash
# Verify cluster connection
kubectl cluster-info

# Check nodes
kubectl get nodes

# Create namespace (optional)
kubectl create namespace go-demo
```

### Step 2: Load Docker Image to Cluster

**For Minikube**:
```bash
minikube image load go-deployment-demo:1.0.0
```

**For kind**:
```bash
kind load docker-image go-deployment-demo:1.0.0
```

**For cloud clusters**: Push to a container registry (see above)

### Step 3: Deploy to Kubernetes
```bash
# Apply all configurations
kubectl apply -f k8s/

# Or apply individually
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/ingress.yaml
kubectl apply -f k8s/serviceaccount.yaml
```

### Step 4: Verify Deployment
```bash
# Check deployment
kubectl get deployments

# Check pods
kubectl get pods

# Check services
kubectl get svc

# Check detailed pod status
kubectl describe pod <pod-name>

# View logs
kubectl logs <pod-name>

# Follow logs
kubectl logs -f <pod-name>
```

### Step 5: Test the Service
```bash
# Port forward to test locally
kubectl port-forward svc/go-deployment-demo 8080:80

# In another terminal
curl http://localhost:8080/health
```

### Step 6: Scale Application
```bash
# Manual scaling
kubectl scale deployment go-deployment-demo --replicas=5

# Check HPA status
kubectl get hpa

# View HPA details
kubectl describe hpa go-deployment-demo-hpa
```

### Step 7: Update Deployment
```bash
# Update image version
kubectl set image deployment/go-deployment-demo \
  go-deployment-demo=go-deployment-demo:1.1.0

# Check rollout status
kubectl rollout status deployment/go-deployment-demo

# View rollout history
kubectl rollout history deployment/go-deployment-demo

# Rollback if needed
kubectl rollout undo deployment/go-deployment-demo
```

## Cloud Platform Deployment

### AWS EKS

#### 1. Push to ECR (see Docker section)

#### 2. Update deployment.yaml
```yaml
image: ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/go-deployment-demo:1.0.0
```

#### 3. Deploy
```bash
kubectl apply -f k8s/
```

### Google Cloud Run

```bash
# Build and push to GCR
gcloud builds submit --tag gcr.io/PROJECT_ID/go-deployment-demo:1.0.0

# Deploy
gcloud run deploy go-deployment-demo \
  --image gcr.io/PROJECT_ID/go-deployment-demo:1.0.0 \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --port 8080 \
  --set-env-vars ENVIRONMENT=production
```

### Azure AKS

#### 1. Push to ACR
```bash
# Login
az acr login --name myregistry

# Tag
docker tag go-deployment-demo:1.0.0 \
  myregistry.azurecr.io/go-deployment-demo:1.0.0

# Push
docker push myregistry.azurecr.io/go-deployment-demo:1.0.0
```

#### 2. Update and Deploy
```bash
# Update image in deployment.yaml
kubectl apply -f k8s/
```

### DigitalOcean/Vultr (VPS)

```bash
# SSH to server
ssh user@your-server-ip

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Pull or build image
docker pull username/go-deployment-demo:1.0.0

# Run container
docker run -d \
  --name go-demo \
  --restart unless-stopped \
  -p 80:8080 \
  go-deployment-demo:1.0.0
```

## Monitoring & Troubleshooting

### Health Checks
```bash
# Liveness probe
curl http://localhost:8080/health

# Readiness probe
curl http://localhost:8080/ready
```

### Kubernetes Troubleshooting

#### Pod Issues
```bash
# Describe pod for events
kubectl describe pod <pod-name>

# View logs
kubectl logs <pod-name>

# View previous logs (if crashed)
kubectl logs <pod-name> --previous

# Execute into pod
kubectl exec -it <pod-name> -- sh
```

#### Service Issues
```bash
# Check endpoints
kubectl get endpoints go-deployment-demo

# Describe service
kubectl describe svc go-deployment-demo

# Check if pods are selected
kubectl get pods -l app=go-deployment-demo
```

#### Resource Issues
```bash
# Check resource usage
kubectl top pods

# Check HPA status
kubectl get hpa

# View events
kubectl get events --sort-by=.metadata.creationTimestamp
```

### Docker Troubleshooting

```bash
# Check container logs
docker logs go-demo

# Inspect container
docker inspect go-demo

# Check resource usage
docker stats go-demo

# Execute into container (if shell available)
docker exec -it go-demo sh
```

### Common Issues

#### Port Already in Use
```bash
# Windows: Find process using port
netstat -ano | findstr :8080

# Kill process
taskkill /PID <process-id> /F

# Or use different port
docker run -p 8081:8080 go-deployment-demo:1.0.0
```

#### Image Pull Errors (Kubernetes)
```bash
# Verify image is available
docker images | grep go-deployment-demo

# For Minikube, load image
minikube image load go-deployment-demo:1.0.0

# Check imagePullPolicy in deployment.yaml
imagePullPolicy: IfNotPresent
```

#### Health Check Failures
```bash
# Check if application started
kubectl logs <pod-name>

# Verify health endpoint
kubectl exec -it <pod-name> -- wget -O- http://localhost:8080/health
```

## Rollback Procedures

### Docker
```bash
# Stop current version
docker stop go-demo

# Start previous version
docker run -d --name go-demo \
  -p 8080:8080 \
  go-deployment-demo:0.9.0
```

### Kubernetes
```bash
# Rollback to previous version
kubectl rollout undo deployment/go-deployment-demo

# Rollback to specific revision
kubectl rollout undo deployment/go-deployment-demo --to-revision=2

# Check rollout status
kubectl rollout status deployment/go-deployment-demo
```

## Production Checklist

- [ ] Environment variables configured
- [ ] Resource limits set appropriately
- [ ] Health checks working
- [ ] Monitoring in place
- [ ] Logging configured
- [ ] Backups planned (if stateful)
- [ ] SSL/TLS certificates configured
- [ ] Security scanning completed
- [ ] Load testing performed
- [ ] Rollback procedure documented
- [ ] On-call rotation established

## Performance Tuning

### Kubernetes Resources
```yaml
resources:
  requests:
    memory: "32Mi"   # Minimum guaranteed
    cpu: "50m"       # 0.05 cores
  limits:
    memory: "128Mi"  # Maximum allowed
    cpu: "200m"      # 0.2 cores
```

### HPA Tuning
```yaml
minReplicas: 3      # Minimum pods
maxReplicas: 10     # Maximum pods
targetCPUUtilization: 70%  # Scale up threshold
```

## Security Recommendations

1. **Use secrets for sensitive data**
   ```bash
   kubectl create secret generic app-secrets \
     --from-literal=api-key=YOUR_API_KEY
   ```

2. **Enable network policies**
3. **Regular security scans**
   ```bash
   docker scan go-deployment-demo:1.0.0
   ```

4. **Keep dependencies updated**
   ```bash
   go get -u ./...
   go mod tidy
   ```

## Support & Resources

- **Go Documentation**: https://go.dev/doc/
- **Kubernetes Docs**: https://kubernetes.io/docs/
- **Docker Docs**: https://docs.docker.com/

## Next Steps

1. Set up CI/CD pipeline
2. Implement observability (Prometheus/Grafana)
3. Add distributed tracing
4. Configure alerting
5. Implement feature flags
6. Set up staging environment
