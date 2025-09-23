# Catalytic Lattice K8s Agents

Intelligent automation agents for managing Catalytic Lattice API deployments on Kubernetes.

## Overview

This project provides a suite of intelligent agents that automate deployment, monitoring, and scaling of the Catalytic Lattice API service across various Kubernetes environments including local development, GKE, EKS, and AKS.

## Features

### 🚀 Deployment Automation
- Multi-cloud support (GKE, EKS, AKS, Local)
- Automated prerequisite checking
- Namespace management
- Service configuration
- Load balancer setup

### 📊 Health Monitoring
- Real-time health checks
- Pod status monitoring
- Resource usage tracking
- Log analysis
- Error detection and alerting
- Prometheus-compatible metrics

### ⚡ Auto-Scaling
- Intelligent scaling decisions
- Predictive load analysis
- Resource-based scaling
- Cooldown periods
- Flapping prevention
- Custom scaling policies

### 🔧 Resource Management
- CPU/Memory optimization
- Namespace quotas (32 CPU, 64GB max)
- EmptyDir storage management
- StatefulSet support for PostgreSQL

## Project Structure

```
catalytic-lattice-k8s-agents/
├── deployment/              # Deployment automation agents
│   └── deploy-agent.py     # Main deployment orchestrator
├── monitoring/             # Health and monitoring agents
│   └── health-monitor-agent.py  # Health check and metrics collector
├── scaling/                # Auto-scaling agents
│   └── auto-scaling-agent.py    # Intelligent scaling decision maker
├── scripts/                # Utility scripts
│   └── deploy-to-k8s.bat  # Windows deployment script
├── config/                 # Configuration files
├── docs/                   # Documentation
└── README.md              # This file
```

## Prerequisites

### Windows
- Docker Desktop with Kubernetes enabled
- Python 3.8+
- kubectl CLI

### Linux/Mac
- Docker
- kubectl CLI
- Python 3.8+

### Cloud Providers
- **GKE**: gcloud CLI with authentication
- **EKS**: AWS CLI with credentials
- **AKS**: Azure CLI with login

## Quick Start

### Windows Deployment

```batch
# Navigate to scripts directory
cd catalytic-lattice-k8s-agents\scripts

# Run deployment script
deploy-to-k8s.bat
```

### Linux/Mac Deployment

```bash
# Make scripts executable
chmod +x deployment/*.py monitoring/*.py scaling/*.py

# Deploy to local Kubernetes
python deployment/deploy-agent.py local

# Deploy to GKE
python deployment/deploy-agent.py gke

# Deploy to EKS
python deployment/deploy-agent.py eks

# Deploy to AKS
python deployment/deploy-agent.py aks
```

## Agent Details

### Deployment Agent (`deploy-agent.py`)

Handles complete deployment lifecycle:

```python
# Basic usage
python deployment/deploy-agent.py [provider]

# Providers: local, gke, eks, aks
```

**Features:**
- Prerequisite validation
- Cluster credential setup
- Namespace creation
- Deployment manifest generation
- Service configuration
- Auto-scaling setup
- Deployment verification

### Health Monitor Agent (`health-monitor-agent.py`)

Continuous health monitoring and alerting:

```python
# Start monitoring
python monitoring/health-monitor-agent.py

# Custom namespace
python monitoring/health-monitor-agent.py --namespace my-namespace
```

**Monitored Metrics:**
- Deployment readiness
- Pod health and restarts
- CPU/Memory usage
- Request rate and latency
- Error rates
- Log analysis

**Health States:**
- ✅ HEALTHY: All systems operational
- ⚠️ WARNING: Degraded performance
- ❌ CRITICAL: Immediate attention required
- ❓ UNKNOWN: Unable to determine status

### Auto-Scaling Agent (`auto-scaling-agent.py`)

Intelligent workload-based scaling:

```python
# Start auto-scaling
python scaling/auto-scaling-agent.py

# Custom configuration
python scaling/auto-scaling-agent.py \
    --min-replicas 3 \
    --max-replicas 20 \
    --target-cpu 70 \
    --interval 60

# Dry run mode
python scaling/auto-scaling-agent.py --dry-run
```

**Scaling Policies:**
- CPU-based scaling (default: 70% target)
- Memory-based scaling
- Response time consideration
- Predictive scaling using trend analysis
- Cooldown periods (default: 300s)
- Flapping prevention

## Configuration

### Deployment Configuration

```python
config = DeploymentConfig(
    provider=CloudProvider.GKE,
    cluster_name="my-cluster",
    namespace="catalytic-lattice",
    replicas=3,
    cpu_limit="32",
    memory_limit="64Gi",
    auto_scale=True,
    min_replicas=3,
    max_replicas=20,
    target_cpu=80
)
```

### Scaling Policy

```python
policy = ScalingPolicy(
    min_replicas=3,
    max_replicas=20,
    target_cpu=70.0,
    target_memory=70.0,
    target_response_time=500.0,
    scale_up_threshold=80.0,
    scale_down_threshold=30.0,
    scale_up_increment=2,
    scale_down_increment=1,
    cooldown_period=300
)
```

### Alert Thresholds

```python
thresholds = {
    "cpu_critical": 90,
    "cpu_warning": 70,
    "memory_critical": 85,
    "memory_warning": 70,
    "error_rate_critical": 5,
    "error_rate_warning": 2,
    "latency_critical": 1000,
    "latency_warning": 500
}
```

## Production Features

### High Availability
- Minimum 3 API replicas
- StatefulSet for PostgreSQL
- Session affinity for clients
- Health checks and readiness probes

### Resource Management
- Pod CPU limits: 2-32 cores
- Pod memory limits: 4-64GB
- Namespace quotas enforced
- EmptyDir for ephemeral storage

### Monitoring & Observability
- Prometheus metrics endpoint
- Grafana dashboard support
- Structured logging
- Distributed tracing ready

### Security
- RBAC policies
- Network policies
- Secret management
- TLS termination at load balancer

## Kubernetes Commands

### Check Status

```bash
# Get all resources
kubectl get all -n catalytic-lattice

# Check pod status
kubectl get pods -n catalytic-lattice

# View pod logs
kubectl logs -f deployment/catalytic-api -n catalytic-lattice

# Check service endpoint
kubectl get service catalytic-api-service -n catalytic-lattice
```

### Manual Scaling

```bash
# Scale deployment
kubectl scale deployment/catalytic-api --replicas=10 -n catalytic-lattice

# Edit HPA
kubectl edit hpa catalytic-api -n catalytic-lattice
```

### Port Forwarding

```bash
# Forward service port
kubectl port-forward service/catalytic-api-service 8080:8080 -n catalytic-lattice

# Forward Grafana
kubectl port-forward service/grafana-service 3000:3000 -n catalytic-lattice
```

## Cloud-Specific Instructions

### Google Kubernetes Engine (GKE)

```bash
# Get cluster credentials
gcloud container clusters get-credentials my-cluster

# Deploy
./deploy-to-k8s.sh

# Export to GCR
export REGISTRY=gcr.io/my-project/
```

### Amazon EKS

```bash
# Update kubeconfig
aws eks update-kubeconfig --name my-cluster

# Deploy
./deploy-to-k8s.sh

# Export to ECR
export REGISTRY=123456789.dkr.ecr.us-west-2.amazonaws.com/
```

### Azure AKS

```bash
# Get credentials
az aks get-credentials --name my-cluster --resource-group my-rg

# Deploy
./deploy-to-k8s.sh

# Export to ACR
export REGISTRY=myregistry.azurecr.io/
```

## Troubleshooting

### Common Issues

1. **Pods not starting**
   - Check resource limits
   - Verify image availability
   - Review pod events: `kubectl describe pod <pod-name> -n catalytic-lattice`

2. **Service not accessible**
   - Check service type (LoadBalancer vs NodePort)
   - Verify security groups/firewall rules
   - Test with port-forward first

3. **Scaling issues**
   - Check HPA status: `kubectl get hpa -n catalytic-lattice`
   - Verify metrics-server is running
   - Review scaling policies

4. **High resource usage**
   - Check for memory leaks
   - Review application logs
   - Consider vertical scaling

### Debug Commands

```bash
# Detailed pod information
kubectl describe pod <pod-name> -n catalytic-lattice

# Events
kubectl get events -n catalytic-lattice --sort-by='.lastTimestamp'

# Resource usage
kubectl top pods -n catalytic-lattice
kubectl top nodes

# HPA status
kubectl get hpa -n catalytic-lattice --watch
```

## Best Practices

1. **Deployment**
   - Always verify prerequisites before deployment
   - Use namespace isolation
   - Tag Docker images with versions
   - Implement rolling updates

2. **Monitoring**
   - Set up alerts for critical metrics
   - Keep metrics history for trend analysis
   - Monitor both application and infrastructure metrics
   - Implement proper logging

3. **Scaling**
   - Start with conservative scaling policies
   - Monitor for flapping behavior
   - Consider time-based scaling for predictable loads
   - Test scaling behavior under load

4. **Security**
   - Use RBAC for access control
   - Encrypt secrets
   - Implement network policies
   - Regular security scans

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## Support

For issues and questions:
- Create an issue in the repository
- Check existing documentation
- Review agent logs for debugging

## Roadmap

- [ ] Helm chart support
- [ ] GitOps integration (ArgoCD/Flux)
- [ ] Cost optimization agent
- [ ] Disaster recovery automation
- [ ] Multi-region deployment support
- [ ] A/B testing and canary deployments
- [ ] Integration with CI/CD pipelines
- [ ] Advanced ML-based predictive scaling