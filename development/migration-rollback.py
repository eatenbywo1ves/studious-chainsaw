#!/usr/bin/env python3
"""
Migration rollback script to restore original directory structure.
Run this script if you need to revert the hybrid monorepo reorganization.
"""

import os
import shutil
from pathlib import Path
import json
from datetime import datetime

# Define rollback mappings (reverse of the migration)
ROLLBACK_MAPPINGS = [
    # Core catalytic files
    ('apps/catalytic/*.py', '.'),
    ('apps/catalytic/*.md', '.'),
    ('apps/catalytic/*.json', '.'),
    
    # API Gateway
    ('apps/api-gateway/production_api_server.py', '.'),
    
    # Shared libraries
    ('libs/constants/constants.py', '.'),
    ('libs/utils/exceptions.py', '.'),
    ('libs/utils/validation.py', '.'),
    
    # MCP servers
    ('services/mcp/*', 'mcp-servers/'),
    
    # Webhooks
    ('services/webhooks/webhook*.py', '.'),
    ('services/webhooks/WEBHOOK_DOCUMENTATION.md', '.'),
    ('services/webhooks/webhooks.db', '.'),
    ('services/webhooks/docker-compose.webhook.yml', '.'),
    ('services/webhooks/Dockerfile.webhook', '.'),
    
    # Tools
    ('tools/claude/claude*.py', '.'),
    ('tools/claude/claude*.json', '.'),
    ('tools/claude/claude*.md', '.'),
    ('tools/claude/claude*.bat', '.'),
    ('tools/claude/setup_claude_audio_hooks.py', '.'),
    ('tools/claude/custom_tools*.py', '.'),
    ('tools/claude/custom_tools*.json', '.'),
    ('tools/claude/tool*.*', '.'),
    
    # Infrastructure
    ('infra/docker/Dockerfile.*', '.'),
    ('infra/docker/docker-compose*.yml', '.'),
    ('infra/k8s/k8s-*.yaml', '.'),
    ('infra/k8s/KUBERNETES_MONITORING_GUIDE.md', '.'),
    ('infra/monitoring/prometheus-config.yml', '.'),
    ('infra/monitoring/alertmanager-config.yml', '.'),
    ('infra/monitoring/grafana-*.*', '.'),
    ('infra/deploy-*.sh', '.'),
    ('infra/verify-deployment.sh', '.'),
    
    # Config files
    ('.config/logging_config.py', 'config/'),
    ('.config/settings.py', 'config/'),
    ('.config/claude_desktop_config.json', 'mcp-configs/'),
    ('.config/pyproject.toml', '.'),
    ('.config/requirements*.txt', '.'),
    ('.config/.coveragerc', '.'),
    ('.config/.env.example', '.'),
    ('.config/.pre-commit-config.yaml', '.'),
    
    # Test files
    ('tests/test_*.py', '.'),
    ('tests/run_tests.py', '.'),
    
    # Documentation
    ('docs/*.md', '.'),
]

def create_backup_manifest():
    """Create a manifest of the current structure before rollback."""
    manifest = {
        'timestamp': datetime.now().isoformat(),
        'directories': [],
        'files': []
    }
    
    for root, dirs, files in os.walk('.'):
        # Skip hidden directories
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        manifest['directories'].extend([os.path.join(root, d) for d in dirs])
        manifest['files'].extend([os.path.join(root, f) for f in files])
    
    manifest_file = f'rollback_manifest_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    with open(manifest_file, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    return manifest_file

def perform_rollback():
    """Execute the rollback operations."""
    print("Starting rollback process...")
    
    # Create necessary directories
    old_dirs = ['mcp-servers', 'config', 'mcp-configs']
    for dir_name in old_dirs:
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
            print(f"Created directory: {dir_name}")
    
    # Move files back
    moved_count = 0
    for source_pattern, dest in ROLLBACK_MAPPINGS:
        source_path = Path(source_pattern)
        
        # Handle wildcards
        if '*' in str(source_path):
            parent = source_path.parent
            pattern = source_path.name
            
            if parent.exists():
                for file_path in parent.glob(pattern):
                    dest_path = Path(dest) / file_path.name if dest != '.' else file_path.name
                    try:
                        if file_path.exists():
                            shutil.move(str(file_path), str(dest_path))
                            print(f"Moved: {file_path} -> {dest_path}")
                            moved_count += 1
                    except Exception as e:
                        print(f"Error moving {file_path}: {e}")
        else:
            # Direct file/directory move
            if source_path.exists():
                dest_path = Path(dest) / source_path.name if dest != '.' else source_path.name
                try:
                    shutil.move(str(source_path), str(dest_path))
                    print(f"Moved: {source_path} -> {dest_path}")
                    moved_count += 1
                except Exception as e:
                    print(f"Error moving {source_path}: {e}")
    
    # Remove empty directories
    new_structure_dirs = ['apps', 'libs', 'services', 'tools', 'infra', 'docs']
    for dir_name in new_structure_dirs:
        try:
            if os.path.exists(dir_name) and not os.listdir(dir_name):
                os.rmdir(dir_name)
                print(f"Removed empty directory: {dir_name}")
        except Exception as e:
            print(f"Could not remove {dir_name}: {e}")
    
    print(f"\nRollback complete! Moved {moved_count} items")

def main():
    """Main rollback function."""
    print("=== Hybrid Monorepo Rollback Script ===\n")
    
    response = input("This will restore the original directory structure. Continue? (yes/no): ")
    if response.lower() != 'yes':
        print("Rollback cancelled.")
        return
    
    # Create backup manifest
    print("\nCreating backup manifest...")
    manifest_file = create_backup_manifest()
    print(f"Manifest saved to: {manifest_file}")
    
    # Perform rollback
    perform_rollback()
    
    print("\nRollback complete!")
    print("Note: You may need to run update_imports.py to restore original import paths.")

if __name__ == "__main__":
    main()