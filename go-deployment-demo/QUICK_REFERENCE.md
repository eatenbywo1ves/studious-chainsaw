# Quick Reference Guide

## 🚀 Common Commands

### Development
```bash
# Run application
go run main.go

# Run tests
go test -v

# Build binary
go build -o go-deployment-demo.exe

# Run with custom port
set PORT=8081 && go run main.go
```

### Docker
```bash
# Build
docker build -t go-deployment-demo:1.0.0 .

# Run
docker run -d -p 8080:8080 --name go-demo go-deployment-demo:1.0.0

# Logs
docker logs -f go-demo

# Stop
docker stop go-demo && docker rm go-demo

# Shell (won't work - scratch image)
docker exec -it go-demo sh
```

### Kubernetes
```bash
# Deploy
kubectl apply -f k8s/

# Status
kubectl get pods,svc,hpa

# Logs
kubectl logs -l app=go-deployment-demo --tail=50 -f

# Port-forward
kubectl port-forward svc/go-deployment-demo 8080:80

# Scale
kubectl scale deployment go-deployment-demo --replicas=5

# Delete
kubectl delete -f k8s/
```

### Makefile
```bash
make help           # Show all commands
make test           # Run tests
make build          # Build binary
make docker-build   # Build Docker image
make docker-run     # Run Docker container
make k8s-deploy     # Deploy to Kubernetes
make k8s-status     # Check K8s status
make all            # Test + Build + Docker build
```

## 📡 API Endpoints

```bash
# Home
curl http://localhost:8080/

# Health check
curl http://localhost:8080/health

# Readiness check
curl http://localhost:8080/ready

# Metrics
curl http://localhost:8080/metrics
```

## 🔧 Environment Variables

```bash
PORT=8080                    # Server port
ENVIRONMENT=development      # Environment name
VERSION=1.0.0               # App version
```

## 📂 File Locations

```
Application:     C:/Users/Corbin/go-deployment-demo/
Go Binary:       C:\Program Files\Go\bin\go.exe
GOPATH:          C:\Users\Corbin\go
GOROOT:          C:\Program Files\Go
Docker Image:    go-deployment-demo:1.0.0
K8s Manifests:   C:/Users/Corbin/go-deployment-demo/k8s/
```

## 🐛 Debugging

```bash
# Check Go version
go version

# Check Docker
docker --version
docker ps

# Check Kubernetes
kubectl cluster-info
kubectl get nodes

# View app logs (local)
# Logs go to stdout/stderr

# View app logs (Docker)
docker logs go-demo

# View app logs (K8s)
kubectl logs -l app=go-deployment-demo
```

## 🔄 Update & Rebuild

```bash
# 1. Make code changes in main.go

# 2. Test
go test -v

# 3. Rebuild Docker image
docker build -t go-deployment-demo:1.0.1 .

# 4. Update K8s (if needed)
# Edit k8s/deployment.yaml - change image version

# 5. Apply changes
kubectl apply -f k8s/deployment.yaml

# 6. Check rollout
kubectl rollout status deployment/go-deployment-demo
```

## 📊 Resource Usage

```bash
# Docker stats
docker stats go-demo

# Kubernetes resource usage
kubectl top pods
kubectl top nodes

# Image size
docker images go-deployment-demo
```

## 🔒 Security Checks

```bash
# Scan Docker image (if Trivy installed)
trivy image go-deployment-demo:1.0.0

# Check running user
docker inspect go-demo | grep User

# K8s security context
kubectl get pod <pod-name> -o yaml | grep -A 5 securityContext
```

## ⚡ Performance

```bash
# Benchmark tests
go test -bench=. -benchmem

# Profile CPU
go test -cpuprofile=cpu.prof
go tool pprof cpu.prof

# Profile memory
go test -memprofile=mem.prof
go tool pprof mem.prof
```

## 📦 Dependencies

```bash
# List dependencies
go list -m all

# Update dependencies
go get -u ./...
go mod tidy

# Vendor dependencies
go mod vendor
```

## 🌐 Network

```bash
# Check port availability
netstat -ano | findstr :8080

# Test from another container
docker run --rm curlimages/curl:latest curl http://host.docker.internal:8080/health

# Test K8s service
kubectl run curl-test --image=curlimages/curl:latest -it --rm -- \
  curl http://go-deployment-demo/health
```

## 📝 Quick Tips

1. **Always test before deploying**: `go test -v`
2. **Check image size**: Should be ~10MB
3. **Verify health checks**: `/health` and `/ready` endpoints
4. **Monitor logs**: Use `-f` flag for real-time logs
5. **Use Makefile**: Simplifies common tasks
6. **Environment config**: Never hardcode, use env vars
7. **Resource limits**: Set in K8s deployment
8. **Security**: Run as non-root, read-only filesystem

## 🎯 Troubleshooting Checklist

- [ ] Is Go installed? `go version`
- [ ] Is Docker running? `docker ps`
- [ ] Is port 8080 available? `netstat -ano | findstr :8080`
- [ ] Did tests pass? `go test -v`
- [ ] Is image built? `docker images | grep go-deployment-demo`
- [ ] Are env vars set? Check .env or deployment.yaml
- [ ] Are health checks responding? `curl http://localhost:8080/health`
- [ ] Check logs: `docker logs` or `kubectl logs`

## 📚 Documentation

- **README.md**: Overview and features
- **DEPLOYMENT.md**: Complete deployment guide
- **DEPLOYMENT_SUMMARY.md**: Summary and achievements
- **QUICK_REFERENCE.md**: This file

## 🔗 Quick Links

```bash
# Project directory
cd C:/Users/Corbin/go-deployment-demo

# View README
start README.md

# Open in VS Code (if installed)
code .
```

---

**Last Updated**: 2025-10-03  
**Go Version**: 1.25.1  
**Docker Image**: go-deployment-demo:1.0.0  
**Image Size**: 10.3MB
