# Go Deployment Demo

A production-ready Go web application demonstrating best practices for deployment using Docker and Kubernetes.

## 🎯 Features

- **Minimal footprint**: 10.3MB Docker image using multi-stage builds
- **12-Factor App**: Environment-based configuration
- **Production-ready**: Health checks, readiness probes, and metrics
- **Cloud-native**: Kubernetes manifests with autoscaling
- **Security-focused**: Non-root user, minimal dependencies, read-only filesystem
- **Observable**: Built-in health and metrics endpoints

## 📋 Prerequisites

- Go 1.25.1 or later
- Docker
- Kubernetes cluster (optional, for K8s deployment)

## 🚀 Quick Start

### Local Development

```bash
# Clone or navigate to the project
cd go-deployment-demo

# Run tests
go test -v

# Build the application
go build -o go-deployment-demo.exe

# Run locally
set PORT=8080
set ENVIRONMENT=development
./go-deployment-demo.exe
```

### Using Docker

```bash
# Build the Docker image
docker build -t go-deployment-demo:1.0.0 .

# Run the container
docker run -d -p 8080:8080 \
  -e ENVIRONMENT=production \
  --name go-demo \
  go-deployment-demo:1.0.0

# Test the endpoints
curl http://localhost:8080/health
curl http://localhost:8080/ready
curl http://localhost:8080/metrics

# Stop and remove
docker stop go-demo
docker rm go-demo
```

### Kubernetes Deployment

```bash
# Apply all Kubernetes resources
kubectl apply -f k8s/

# Check deployment status
kubectl get deployments
kubectl get pods
kubectl get svc

# Test the service
kubectl port-forward svc/go-deployment-demo 8080:80
curl http://localhost:8080/health

# Clean up
kubectl delete -f k8s/
```

## 📡 API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Home page with available endpoints |
| `GET /health` | Health check (liveness probe) |
| `GET /ready` | Readiness check (readiness probe) |
| `GET /metrics` | Application metrics |

## 🔧 Configuration

The application follows the **12-Factor App** methodology and uses environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `ENVIRONMENT` | `development` | Application environment |
| `VERSION` | `1.0.0` | Application version |

## 🏗️ Architecture

### Multi-Stage Docker Build

1. **Build Stage**: Uses `golang:1.25.1-alpine` for compilation
   - Installs build dependencies
   - Downloads Go modules
   - Compiles static binary with optimizations
   - Runs tests during build

2. **Runtime Stage**: Uses `scratch` for minimal footprint
   - Only contains the binary and essential certificates
   - Runs as non-root user (UID 65534)
   - Read-only filesystem for security
   - Final image: **10.3MB**

### Kubernetes Resources

- **Deployment**: 3 replicas with resource limits
- **Service**: ClusterIP for internal communication
- **ConfigMap**: Environment configuration
- **HPA**: Auto-scaling based on CPU/memory (3-10 replicas)
- **Ingress**: External access with TLS
- **ServiceAccount**: RBAC for least privilege

## 🔒 Security Features

- ✅ Non-root user (UID 65534)
- ✅ Read-only root filesystem
- ✅ No privilege escalation
- ✅ Dropped all capabilities
- ✅ Static binary with no dependencies
- ✅ Minimal attack surface (scratch base image)

## 📊 Monitoring & Observability

### Health Checks

**Liveness Probe** (`/health`):
- Checks if the application is alive
- Returns HTTP 200 with health status JSON

**Readiness Probe** (`/ready`):
- Checks if the application is ready to serve traffic
- Useful for checking dependencies (databases, external services)

### Metrics

The `/metrics` endpoint provides:
- Application uptime
- Version information
- Can be extended for Prometheus integration

## 🚢 Deployment Strategies

### Local Development
```bash
go run main.go
```

### Docker Deployment
```bash
docker build -t go-deployment-demo:1.0.0 .
docker run -p 8080:8080 go-deployment-demo:1.0.0
```

### Kubernetes Deployment
```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/ingress.yaml
```

### Cloud Platforms

**AWS ECS/EKS**:
- Push image to ECR
- Deploy using ECS tasks or EKS

**Google Cloud Run**:
```bash
gcloud run deploy go-deployment-demo \
  --image=go-deployment-demo:1.0.0 \
  --platform=managed
```

**Azure Container Instances**:
```bash
az container create \
  --resource-group myResourceGroup \
  --name go-deployment-demo \
  --image go-deployment-demo:1.0.0
```

## 🧪 Testing

```bash
# Run all tests
go test -v ./...

# Run tests with coverage
go test -v -cover ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## 📦 Building for Production

```bash
# Build optimized binary
CGO_ENABLED=0 GOOS=linux go build \
  -ldflags="-w -s" \
  -o go-deployment-demo .

# Build multi-arch Docker images
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t go-deployment-demo:1.0.0 \
  --push .
```

## 🔄 CI/CD Integration

The application is designed for easy CI/CD integration:

1. **Build**: `go build`
2. **Test**: `go test -v ./...`
3. **Containerize**: `docker build`
4. **Deploy**: `kubectl apply -f k8s/`

Example GitHub Actions workflow:
```yaml
- name: Build
  run: go build -v ./...
- name: Test
  run: go test -v ./...
- name: Docker Build
  run: docker build -t ${{ env.IMAGE }} .
```

## 📝 Best Practices Implemented

✅ **12-Factor App** - Environment-based configuration  
✅ **Stateless** - No local state, easy horizontal scaling  
✅ **Health Checks** - Liveness and readiness probes  
✅ **Resource Limits** - Memory and CPU constraints  
✅ **Security** - Non-root, read-only filesystem  
✅ **Minimal Dependencies** - Single static binary  
✅ **Logging** - Structured logging to stdout  
✅ **Graceful Shutdown** - Proper signal handling  

## 🎓 Why Go for Deployment?

Based on industry best practices:

1. **Single Static Binary** - No runtime dependencies
2. **Fast Compilation** - Quick build times
3. **Small Footprint** - Minimal container sizes (10.3MB)
4. **Built-in Concurrency** - Goroutines for efficient resource usage
5. **Cross-Platform** - Compile for any OS/architecture
6. **Production-Ready** - Used by Docker, Kubernetes, Terraform

## 📚 Additional Resources

- [Official Go Documentation](https://go.dev/doc/)
- [12-Factor App Methodology](https://12factor.net/)
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
- [Docker Multi-Stage Builds](https://docs.docker.com/build/building/multi-stage/)

## 📄 License

MIT License - Feel free to use this as a template for your own Go deployments!
