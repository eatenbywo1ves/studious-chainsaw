#!/bin/bash

# Deploy Kubernetes Monitoring Stack
# This script installs Prometheus, Grafana, AlertManager, and Node Exporter

set -e

echo "================================================"
echo "Kubernetes Monitoring Stack Deployment"
echo "================================================"

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl is not installed"
    exit 1
fi

# Check cluster connection
echo "Checking cluster connection..."
if ! kubectl cluster-info &> /dev/null; then
    echo "Error: Cannot connect to Kubernetes cluster"
    echo "Please ensure kubectl is configured correctly"
    exit 1
fi

# Create monitoring namespace if it doesn't exist
echo "Creating monitoring namespace..."
kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -

# Deploy monitoring stack
echo "Deploying monitoring components..."
kubectl apply -f k8s-monitoring-stack.yaml

# Wait for Prometheus to be ready
echo "Waiting for Prometheus deployment..."
kubectl wait --for=condition=available --timeout=300s deployment/prometheus -n monitoring

# Wait for Grafana to be ready
echo "Waiting for Grafana deployment..."
kubectl wait --for=condition=available --timeout=300s deployment/grafana -n monitoring

# Wait for AlertManager to be ready
echo "Waiting for AlertManager deployment..."
kubectl wait --for=condition=available --timeout=300s deployment/alertmanager -n monitoring

# Get service URLs
echo ""
echo "================================================"
echo "Monitoring Stack Deployed Successfully!"
echo "================================================"
echo ""
echo "Access URLs (NodePort):"
echo "----------------------"

PROMETHEUS_PORT=$(kubectl get svc prometheus -n monitoring -o jsonpath='{.spec.ports[0].nodePort}')
GRAFANA_PORT=$(kubectl get svc grafana -n monitoring -o jsonpath='{.spec.ports[0].nodePort}')
ALERTMANAGER_PORT=$(kubectl get svc alertmanager -n monitoring -o jsonpath='{.spec.ports[0].nodePort}')

# Get node IP
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')

echo "Prometheus:    http://$NODE_IP:$PROMETHEUS_PORT"
echo "Grafana:       http://$NODE_IP:$GRAFANA_PORT"
echo "               Username: admin"
echo "               Password: catalytic-admin"
echo "AlertManager:  http://$NODE_IP:$ALERTMANAGER_PORT"
echo ""
echo "To import dashboards to Grafana:"
echo "1. Login to Grafana"
echo "2. Go to Dashboards > Import"
echo "3. Upload grafana-dashboards.json"
echo ""

# Check pod status
echo "Pod Status:"
echo "-----------"
kubectl get pods -n monitoring

echo ""
echo "To view logs:"
echo "  kubectl logs -n monitoring deployment/prometheus"
echo "  kubectl logs -n monitoring deployment/grafana"
echo "  kubectl logs -n monitoring deployment/alertmanager"
echo ""
echo "To port-forward locally:"
echo "  kubectl port-forward -n monitoring svc/prometheus 9090:9090"
echo "  kubectl port-forward -n monitoring svc/grafana 3000:3000"
echo ""
echo "Monitoring stack deployment complete!"