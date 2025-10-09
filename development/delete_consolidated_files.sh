#!/bin/bash
# Delete consolidated source files - Phase 3 Cleanup

echo "Deleting consolidated source files..."

# MCP guide sources
rm -f docs/MCP_INTEGRATION_STATUS.md
rm -f services/mcp/MCP_SERVERS_SETUP_GUIDE.md

# Monitoring guide sources  
rm -f monitoring/MONITORING_DEPLOYMENT_GUIDE.md
rm -f saas/MONITORING_GUIDE.md
rm -f docs/monitoring/MONITORING_VALIDATION_COMPLETE.md
rm -f docs/reports/GRAFANA_DASHBOARDS_SUMMARY.md

# Deployment Status sources
rm -f saas/DEPLOYMENT_READINESS_REPORT.md
rm -f saas/PRE_DEPLOYMENT_CHECKLIST.md
rm -f docs/PRODUCTION_DEPLOYMENT_GUIDE.md

echo "Consolidated source files deleted."
echo ""
echo "Files deleted:"
echo "  - docs/MCP_INTEGRATION_STATUS.md"
echo "  - services/mcp/MCP_SERVERS_SETUP_GUIDE.md"
echo "  - monitoring/MONITORING_DEPLOYMENT_GUIDE.md"
echo "  - saas/MONITORING_GUIDE.md"
echo "  - docs/monitoring/MONITORING_VALIDATION_COMPLETE.md"
echo "  - docs/reports/GRAFANA_DASHBOARDS_SUMMARY.md"
echo "  - saas/DEPLOYMENT_READINESS_REPORT.md"
echo "  - saas/PRE_DEPLOYMENT_CHECKLIST.md"
echo "  - docs/PRODUCTION_DEPLOYMENT_GUIDE.md"
echo ""
echo "Total: 9 source files deleted"
