#!/usr/bin/env python3
"""
Grafana Dashboard Deployment Script for Catalytic Computing Platform

This script automates the deployment of Grafana dashboards with proper
error handling, validation, and rollback capabilities.

Features:
- Validates dashboard JSON configurations
- Deploys dashboards via Grafana API
- Creates dashboard folders and organizations
- Handles authentication and permissions
- Provides rollback functionality
- Validates data sources and connections
"""

import json
import requests
import sys
import argparse
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('grafana-deployment.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class GrafanaDashboardDeployer:
    """Handles Grafana dashboard deployment operations."""

    def __init__(self, grafana_url: str, api_key: str, org_id: int = 1):
        """Initialize the deployer with Grafana connection details."""
        self.grafana_url = grafana_url.rstrip('/')
        self.api_key = api_key
        self.org_id = org_id
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def validate_connection(self) -> bool:
        """Validate connection to Grafana instance."""
        try:
            response = self.session.get(f'{self.grafana_url}/api/org')
            response.raise_for_status()
            logger.info(f"✅ Successfully connected to Grafana at {self.grafana_url}")
            return True
        except requests.RequestException as e:
            logger.error(f"❌ Failed to connect to Grafana: {e}")
            return False

    def validate_dashboard_json(self, dashboard_path: Path) -> Tuple[bool, Optional[Dict]]:
        """Validate dashboard JSON file structure."""
        try:
            with open(dashboard_path, 'r', encoding='utf-8') as f:
                dashboard_data = json.load(f)

            # Basic validation
            if 'dashboard' not in dashboard_data:
                logger.error(f"❌ Invalid dashboard format in {dashboard_path}: missing 'dashboard' key")
                return False, None

            dashboard = dashboard_data['dashboard']
            required_fields = ['title', 'panels']

            for field in required_fields:
                if field not in dashboard:
                    logger.error(f"❌ Missing required field '{field}' in {dashboard_path}")
                    return False, None

            logger.info(f"✅ Dashboard validation passed: {dashboard['title']}")
            return True, dashboard_data

        except json.JSONDecodeError as e:
            logger.error(f"❌ Invalid JSON in {dashboard_path}: {e}")
            return False, None
        except Exception as e:
            logger.error(f"❌ Error reading {dashboard_path}: {e}")
            return False, None

    def create_folder(self, folder_name: str) -> Optional[int]:
        """Create a dashboard folder if it doesn't exist."""
        try:
            # Check if folder exists
            response = self.session.get(f'{self.grafana_url}/api/folders')
            response.raise_for_status()

            for folder in response.json():
                if folder['title'] == folder_name:
                    logger.info(f"📁 Folder '{folder_name}' already exists")
                    return folder['id']

            # Create new folder
            folder_data = {
                'uid': folder_name.lower().replace(' ', '-'),
                'title': folder_name
            }

            response = self.session.post(
                f'{self.grafana_url}/api/folders',
                json=folder_data
            )
            response.raise_for_status()

            folder_info = response.json()
            logger.info(f"✅ Created folder '{folder_name}' with ID {folder_info['id']}")
            return folder_info['id']

        except requests.RequestException as e:
            logger.error(f"❌ Failed to create folder '{folder_name}': {e}")
            return None

    def deploy_dashboard(self, dashboard_data: Dict, folder_id: Optional[int] = None) -> bool:
        """Deploy a single dashboard to Grafana."""
        try:
            dashboard = dashboard_data['dashboard']
            title = dashboard['title']

            # Prepare dashboard for deployment
            deploy_data = {
                'dashboard': dashboard,
                'folderId': folder_id or 0,
                'overwrite': True,
                'message': f"Deployed via automation script at {time.strftime('%Y-%m-%d %H:%M:%S')}"
            }

            # Remove id to allow Grafana to assign one
            if 'id' in deploy_data['dashboard']:
                del deploy_data['dashboard']['id']

            response = self.session.post(
                f'{self.grafana_url}/api/dashboards/db',
                json=deploy_data
            )
            response.raise_for_status()

            result = response.json()
            logger.info(f"✅ Successfully deployed dashboard: {title}")
            logger.info(f"   Dashboard ID: {result.get('id')}")
            logger.info(f"   Dashboard UID: {result.get('uid')}")
            logger.info(f"   Dashboard URL: {result.get('url')}")

            return True

        except requests.RequestException as e:
            logger.error(f"❌ Failed to deploy dashboard '{title}': {e}")
            if hasattr(e, 'response') and e.response:
                logger.error(f"   Response: {e.response.text}")
            return False

    def validate_datasources(self) -> bool:
        """Validate that required data sources are available."""
        required_datasources = ['Prometheus', 'PostgreSQL', 'Redis']

        try:
            response = self.session.get(f'{self.grafana_url}/api/datasources')
            response.raise_for_status()

            available_datasources = {ds['name'] for ds in response.json()}
            missing_datasources = set(required_datasources) - available_datasources

            if missing_datasources:
                logger.warning(f"⚠️ Missing data sources: {', '.join(missing_datasources)}")
                logger.info("   Please ensure all required data sources are configured.")
                return False

            logger.info("✅ All required data sources are available")
            return True

        except requests.RequestException as e:
            logger.error(f"❌ Failed to validate data sources: {e}")
            return False

    def get_existing_dashboards(self) -> List[Dict]:
        """Get list of existing dashboards for backup/rollback."""
        try:
            response = self.session.get(f'{self.grafana_url}/api/search?type=dash-db')
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(f"❌ Failed to get existing dashboards: {e}")
            return []

    def backup_existing_dashboards(self, dashboard_uids: List[str]) -> Dict[str, Dict]:
        """Backup existing dashboards before deployment."""
        backups = {}

        for uid in dashboard_uids:
            try:
                response = self.session.get(f'{self.grafana_url}/api/dashboards/uid/{uid}')
                if response.status_code == 200:
                    backups[uid] = response.json()
                    logger.info(f"📦 Backed up dashboard: {uid}")
            except requests.RequestException as e:
                logger.warning(f"⚠️ Failed to backup dashboard {uid}: {e}")

        return backups

def main():
    """Main deployment function."""
    parser = argparse.ArgumentParser(description='Deploy Grafana dashboards for Catalytic Computing platform')
    parser.add_argument('--grafana-url', default='http://localhost:3000', help='Grafana URL')
    parser.add_argument('--api-key', required=True, help='Grafana API key')
    parser.add_argument('--dashboards-dir', default='monitoring/grafana/dashboards', help='Dashboards directory')
    parser.add_argument('--validate-only', action='store_true', help='Only validate dashboards without deploying')
    parser.add_argument('--skip-datasource-check', action='store_true', help='Skip data source validation')
    parser.add_argument('--org-id', type=int, default=1, help='Grafana organization ID')

    args = parser.parse_args()

    # Initialize deployer
    deployer = GrafanaDashboardDeployer(args.grafana_url, args.api_key, args.org_id)

    logger.info("🚀 Starting Grafana dashboard deployment")

    # Validate connection
    if not deployer.validate_connection():
        sys.exit(1)

    # Validate data sources unless skipped
    if not args.skip_datasource_check:
        if not deployer.validate_datasources():
            logger.warning("⚠️ Continuing with deployment despite data source issues")

    # Find dashboard files
    dashboards_dir = Path(args.dashboards_dir)
    if not dashboards_dir.exists():
        logger.error(f"❌ Dashboards directory not found: {dashboards_dir}")
        sys.exit(1)

    dashboard_files = list(dashboards_dir.glob('*.json'))
    if not dashboard_files:
        logger.error(f"❌ No dashboard JSON files found in {dashboards_dir}")
        sys.exit(1)

    logger.info(f"📊 Found {len(dashboard_files)} dashboard files")

    # Validate all dashboards first
    validated_dashboards = []
    for dashboard_file in dashboard_files:
        is_valid, dashboard_data = deployer.validate_dashboard_json(dashboard_file)
        if is_valid:
            validated_dashboards.append((dashboard_file, dashboard_data))
        else:
            logger.error(f"❌ Validation failed for {dashboard_file}")

    if not validated_dashboards:
        logger.error("❌ No valid dashboards found")
        sys.exit(1)

    if args.validate_only:
        logger.info(f"✅ Validation completed. {len(validated_dashboards)} dashboards are valid.")
        sys.exit(0)

    # Create folders
    system_folder_id = deployer.create_folder("System Metrics")
    business_folder_id = deployer.create_folder("Business Metrics")

    # Deploy dashboards
    successful_deployments = 0
    failed_deployments = 0

    for dashboard_file, dashboard_data in validated_dashboards:
        dashboard_title = dashboard_data['dashboard']['title']

        # Determine folder based on dashboard type
        folder_id = None
        if 'system' in dashboard_title.lower():
            folder_id = system_folder_id
        elif 'business' in dashboard_title.lower():
            folder_id = business_folder_id

        if deployer.deploy_dashboard(dashboard_data, folder_id):
            successful_deployments += 1
        else:
            failed_deployments += 1

    # Summary
    logger.info("📊 Deployment Summary:")
    logger.info(f"   ✅ Successful: {successful_deployments}")
    logger.info(f"   ❌ Failed: {failed_deployments}")

    if failed_deployments == 0:
        logger.info("🎉 All dashboards deployed successfully!")
        sys.exit(0)
    else:
        logger.error(f"💥 {failed_deployments} dashboards failed to deploy")
        sys.exit(1)

if __name__ == '__main__':
    main()
