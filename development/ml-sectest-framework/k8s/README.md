# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying ML-SecTest in production.

## Quick Deploy

```bash
# Create namespace
kubectl apply -f namespace.yaml

# Deploy ConfigMaps and PVCs
kubectl apply -f configmap.yaml
kubectl apply -f pvc.yaml

# Deploy application
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# Verify deployment
kubectl get pods -n ml-sectest
kubectl logs -f deployment/ml-sectest-agents -n ml-sectest
```

## Files

- `namespace.yaml` - Creates ml-sectest namespace
- `configmap.yaml` - Environment configuration
- `deployment.yaml` - Main agent deployment (3 replicas)
- `service.yaml` - ClusterIP service
- `pvc.yaml` - Persistent volume claims for reports and logs

## Scaling

```bash
# Scale up
kubectl scale deployment/ml-sectest-agents --replicas=5 -n ml-sectest

# Scale down
kubectl scale deployment/ml-sectest-agents --replicas=1 -n ml-sectest
```

## Monitoring

```bash
# Watch pods
kubectl get pods -n ml-sectest -w

# View logs
kubectl logs -f -l app=ml-sectest -n ml-sectest

# Describe deployment
kubectl describe deployment/ml-sectest-agents -n ml-sectest
```

## Cleanup

```bash
kubectl delete namespace ml-sectest
```
