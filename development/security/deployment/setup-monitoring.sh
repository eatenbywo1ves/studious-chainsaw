#!/usr/bin/env bash
#
# Monitoring and Alerting Setup Script
# Deploys Prometheus, Grafana, and AlertManager
#

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
ENV="${1:-staging}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     Security Monitoring & Alerting Setup                 ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo "Environment: ${ENV}"
echo ""

# Check prerequisites
check_prerequisites() {
    echo -e "${BLUE}=== Checking Prerequisites ===${NC}"
    echo ""

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        echo -e "${RED}[ERROR] kubectl not found${NC}"
        exit 1
    fi
    echo -e "${GREEN}[OK] kubectl found${NC}"

    # Check cluster connection
    if ! kubectl cluster-info &> /dev/null; then
        echo -e "${RED}[ERROR] Cannot connect to Kubernetes cluster${NC}"
        exit 1
    fi
    echo -e "${GREEN}[OK] Connected to Kubernetes cluster${NC}"

    # Check helm (optional but recommended)
    if command -v helm &> /dev/null; then
        echo -e "${GREEN}[OK] Helm found${NC}"
        HAS_HELM=true
    else
        echo -e "${YELLOW}[WARN] Helm not found - using kubectl apply${NC}"
        HAS_HELM=false
    fi

    echo ""
}

# Create monitoring namespace
create_namespace() {
    echo -e "${BLUE}=== Creating Monitoring Namespace ===${NC}"
    echo ""

    kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
    echo -e "${GREEN}[OK] Namespace created/verified${NC}"
    echo ""
}

# Install Prometheus using Helm (recommended)
install_prometheus_helm() {
    echo -e "${BLUE}=== Installing Prometheus (Helm) ===${NC}"
    echo ""

    # Add Prometheus helm repo
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo update

    # Install Prometheus stack
    helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
        --namespace monitoring \
        --set prometheus.prometheusSpec.retention=30d \
        --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=50Gi \
        --set alertmanager.enabled=true \
        --set grafana.enabled=true \
        --set grafana.adminPassword="CHANGE_ME_${RANDOM}" \
        --wait

    echo -e "${GREEN}[OK] Prometheus stack installed${NC}"
    echo ""
}

# Install Prometheus using kubectl
install_prometheus_kubectl() {
    echo -e "${BLUE}=== Installing Prometheus (kubectl) ===${NC}"
    echo ""

    kubectl apply -f "${SCRIPT_DIR}/monitoring-alerting-setup.yaml"

    echo -e "${GREEN}[OK] Prometheus components deployed${NC}"
    echo ""
}

# Configure Prometheus for security monitoring
configure_prometheus() {
    echo -e "${BLUE}=== Configuring Security Monitoring ===${NC}"
    echo ""

    # Apply security alert rules
    kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-security-rules
  namespace: monitoring
  labels:
    prometheus: kube-prometheus
data:
  security-alerts.yaml: |
    $(cat "${SCRIPT_DIR}/monitoring-alerting-setup.yaml" | grep -A 200 "security-alerts.yml:" | tail -n +2)
EOF

    echo -e "${GREEN}[OK] Security alert rules configured${NC}"
    echo ""
}

# Set up Grafana dashboards
setup_grafana_dashboards() {
    echo -e "${BLUE}=== Setting Up Grafana Dashboards ===${NC}"
    echo ""

    # Get Grafana pod name
    GRAFANA_POD=$(kubectl get pods -n monitoring -l app.kubernetes.io/name=grafana -o jsonpath='{.items[0].metadata.name}')

    if [ -z "$GRAFANA_POD" ]; then
        echo -e "${YELLOW}[WARN] Grafana pod not found - skipping dashboard import${NC}"
        return
    fi

    # Import security dashboard
    echo "Importing security monitoring dashboard..."
    kubectl exec -n monitoring "$GRAFANA_POD" -- grafana-cli dashboard import 12486 || true

    echo -e "${GREEN}[OK] Grafana dashboards configured${NC}"
    echo ""
}

# Configure AlertManager
configure_alertmanager() {
    echo -e "${BLUE}=== Configuring AlertManager ===${NC}"
    echo ""

    # Prompt for notification settings
    echo "Enter notification email (default: ops@company.com):"
    read -r NOTIFICATION_EMAIL
    NOTIFICATION_EMAIL=${NOTIFICATION_EMAIL:-ops@company.com}

    echo "Enter Slack webhook URL (or press Enter to skip):"
    read -r SLACK_WEBHOOK

    # Create AlertManager configuration
    cat > /tmp/alertmanager-config.yaml <<EOF
global:
  smtp_smarthost: 'smtp.gmail.com:587'
  smtp_from: 'alerts@company.com'
  smtp_auth_username: 'alerts@company.com'
  smtp_require_tls: true

route:
  receiver: 'default'
  group_by: ['alertname', 'severity']
  group_wait: 10s
  group_interval: 5m
  repeat_interval: 4h
  routes:
    - match:
        severity: critical
      receiver: 'critical-alerts'
      group_wait: 0s
      repeat_interval: 5m

receivers:
  - name: 'default'
    email_configs:
      - to: '${NOTIFICATION_EMAIL}'

  - name: 'critical-alerts'
    email_configs:
      - to: '${NOTIFICATION_EMAIL}'
        headers:
          Subject: '[CRITICAL] Security Alert'
EOF

    # Add Slack if configured
    if [ -n "$SLACK_WEBHOOK" ]; then
        cat >> /tmp/alertmanager-config.yaml <<EOF
    slack_configs:
      - api_url: '${SLACK_WEBHOOK}'
        channel: '#security-alerts'
        title: 'Critical Security Alert'
EOF
    fi

    # Apply configuration
    kubectl create secret generic alertmanager-config \
        --from-file=alertmanager.yaml=/tmp/alertmanager-config.yaml \
        --namespace monitoring \
        --dry-run=client -o yaml | kubectl apply -f -

    # Clean up
    rm /tmp/alertmanager-config.yaml

    echo -e "${GREEN}[OK] AlertManager configured${NC}"
    echo ""
}

# Deploy metrics exporters for application
deploy_app_metrics() {
    echo -e "${BLUE}=== Deploying Application Metrics Exporters ===${NC}"
    echo ""

    # Redis exporter for rate limiting metrics
    kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis-exporter
  namespace: production
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis-exporter
  template:
    metadata:
      labels:
        app: redis-exporter
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9121"
    spec:
      containers:
        - name: redis-exporter
          image: oliver006/redis_exporter:latest
          ports:
            - containerPort: 9121
          env:
            - name: REDIS_ADDR
              value: "redis:6379"
---
apiVersion: v1
kind: Service
metadata:
  name: redis-exporter
  namespace: production
  labels:
    app: redis-exporter
spec:
  ports:
    - port: 9121
      targetPort: 9121
  selector:
    app: redis-exporter
EOF

    echo -e "${GREEN}[OK] Metrics exporters deployed${NC}"
    echo ""
}

# Verify deployment
verify_deployment() {
    echo -e "${BLUE}=== Verifying Deployment ===${NC}"
    echo ""

    # Check Prometheus
    echo -n "Checking Prometheus... "
    if kubectl get pods -n monitoring -l app.kubernetes.io/name=prometheus -o jsonpath='{.items[0].status.phase}' | grep -q "Running"; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi

    # Check AlertManager
    echo -n "Checking AlertManager... "
    if kubectl get pods -n monitoring -l app.kubernetes.io/name=alertmanager -o jsonpath='{.items[0].status.phase}' | grep -q "Running"; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi

    # Check Grafana
    echo -n "Checking Grafana... "
    if kubectl get pods -n monitoring -l app.kubernetes.io/name=grafana -o jsonpath='{.items[0].status.phase}' | grep -q "Running"; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi

    echo ""
}

# Print access information
print_access_info() {
    echo -e "${BLUE}=== Access Information ===${NC}"
    echo ""

    # Prometheus
    PROMETHEUS_PORT=$(kubectl get svc -n monitoring prometheus-kube-prometheus-prometheus -o jsonpath='{.spec.ports[0].port}' 2>/dev/null || echo "9090")
    echo "Prometheus:"
    echo "  kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus ${PROMETHEUS_PORT}:9090"
    echo "  Then access: http://localhost:${PROMETHEUS_PORT}"
    echo ""

    # Grafana
    GRAFANA_PORT=$(kubectl get svc -n monitoring prometheus-grafana -o jsonpath='{.spec.ports[0].port}' 2>/dev/null || echo "80")
    GRAFANA_PASSWORD=$(kubectl get secret -n monitoring prometheus-grafana -o jsonpath="{.data.admin-password}" 2>/dev/null | base64 --decode || echo "admin")
    echo "Grafana:"
    echo "  kubectl port-forward -n monitoring svc/prometheus-grafana ${GRAFANA_PORT}:80"
    echo "  Then access: http://localhost:${GRAFANA_PORT}"
    echo "  Username: admin"
    echo "  Password: ${GRAFANA_PASSWORD}"
    echo ""

    # AlertManager
    echo "AlertManager:"
    echo "  kubectl port-forward -n monitoring svc/alertmanager-operated 9093:9093"
    echo "  Then access: http://localhost:9093"
    echo ""
}

# Main execution
main() {
    check_prerequisites
    create_namespace

    if [ "$HAS_HELM" = true ]; then
        install_prometheus_helm
    else
        install_prometheus_kubectl
    fi

    configure_prometheus
    configure_alertmanager
    setup_grafana_dashboards
    deploy_app_metrics
    verify_deployment
    print_access_info

    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                           ║"
    echo "║     Monitoring Setup Complete!                           ║"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo ""
    echo "Next steps:"
    echo "  1. Access Grafana and verify dashboards"
    echo "  2. Test alert rules by triggering test events"
    echo "  3. Configure notification channels (email, Slack, PagerDuty)"
    echo "  4. Review and tune alert thresholds"
    echo "  5. Set up log aggregation (ELK stack)"
    echo ""
}

# Run main
main
