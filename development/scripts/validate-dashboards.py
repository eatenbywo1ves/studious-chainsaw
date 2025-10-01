#!/usr/bin/env python3
"""
Dashboard Validation Script for Catalytic Computing Platform

This script validates Grafana dashboard configurations for:
- JSON syntax and structure
- Required fields and properties
- Query syntax validation
- Panel configuration compliance
- Template variable validation
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DashboardValidator:
    """Validates Grafana dashboard configurations."""
    
    def __init__(self):
        self.required_dashboard_fields = [
            'title', 'panels', 'time', 'timepicker', 'refresh'
        ]
        
        self.required_panel_fields = [
            'id', 'title', 'type', 'gridPos', 'targets'
        ]
        
        self.valid_panel_types = [
            'timeseries', 'stat', 'gauge', 'table', 'piechart', 
            'bargauge', 'geomap', 'graph'
        ]
        
        self.prometheus_functions = [
            'rate', 'increase', 'sum', 'avg', 'max', 'min', 
            'histogram_quantile', 'topk', 'changes', 'offset'
        ]
    
    def validate_json_structure(self, dashboard_path: Path) -> Tuple[bool, Optional[Dict], List[str]]:
        """Validate JSON structure and load dashboard data."""
        errors = []
        
        try:
            with open(dashboard_path, 'r', encoding='utf-8') as f:
                dashboard_data = json.load(f)
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON syntax: {e}")
            return False, None, errors
        except Exception as e:
            errors.append(f"Error reading file: {e}")
            return False, None, errors
        
        # Check root structure
        if 'dashboard' not in dashboard_data:
            errors.append("Missing 'dashboard' root key")
            return False, None, errors
        
        return True, dashboard_data, errors
    
    def validate_dashboard_metadata(self, dashboard: Dict) -> List[str]:
        """Validate dashboard metadata and required fields."""
        errors = []
        
        # Check required fields
        for field in self.required_dashboard_fields:
            if field not in dashboard:
                errors.append(f"Missing required dashboard field: {field}")
        
        # Validate title
        if 'title' in dashboard:
            if not isinstance(dashboard['title'], str) or len(dashboard['title']) == 0:
                errors.append("Dashboard title must be a non-empty string")
        
        # Validate time configuration
        if 'time' in dashboard:
            time_config = dashboard['time']
            if not isinstance(time_config, dict):
                errors.append("Time configuration must be an object")
            else:
                required_time_fields = ['from', 'to']
                for field in required_time_fields:
                    if field not in time_config:
                        errors.append(f"Missing time field: {field}")
        
        return errors
    
    def validate_panels(self, panels: List[Dict]) -> List[str]:
        """Validate dashboard panels configuration."""
        errors = []
        panel_ids = set()
        
        for i, panel in enumerate(panels):
            panel_errors = self.validate_single_panel(panel, i)
            errors.extend(panel_errors)
            
            # Check for duplicate panel IDs
            panel_id = panel.get('id')
            if panel_id is not None:
                if panel_id in panel_ids:
                    errors.append(f"Duplicate panel ID: {panel_id}")
                panel_ids.add(panel_id)
        
        return errors
    
    def validate_single_panel(self, panel: Dict, panel_index: int) -> List[str]:
        """Validate a single panel configuration."""
        errors = []
        
        # Check required fields
        for field in self.required_panel_fields:
            if field not in panel:
                errors.append(f"Panel {panel_index}: Missing required field '{field}'")
        
        # Validate panel type
        panel_type = panel.get('type')
        if panel_type and panel_type not in self.valid_panel_types:
            errors.append(f"Panel {panel_index}: Invalid panel type '{panel_type}'")
        
        # Validate gridPos
        if 'gridPos' in panel:
            grid_pos = panel['gridPos']
            required_grid_fields = ['h', 'w', 'x', 'y']
            for field in required_grid_fields:
                if field not in grid_pos:
                    errors.append(f"Panel {panel_index}: Missing gridPos field '{field}'")
                elif not isinstance(grid_pos[field], int):
                    errors.append(f"Panel {panel_index}: gridPos '{field}' must be an integer")
        
        # Validate targets (queries)
        if 'targets' in panel:
            target_errors = self.validate_panel_targets(panel['targets'], panel_index)
            errors.extend(target_errors)
        
        return errors
    
    def validate_panel_targets(self, targets: List[Dict], panel_index: int) -> List[str]:
        """Validate panel query targets."""
        errors = []
        
        for target_index, target in enumerate(targets):
            # Check for expression (Prometheus query)
            if 'expr' not in target:
                errors.append(f"Panel {panel_index}, Target {target_index}: Missing 'expr' field")
                continue
            
            expr = target['expr']
            if not isinstance(expr, str) or len(expr.strip()) == 0:
                errors.append(f"Panel {panel_index}, Target {target_index}: 'expr' must be a non-empty string")
                continue
            
            # Validate Prometheus query syntax
            query_errors = self.validate_prometheus_query(expr, panel_index, target_index)
            errors.extend(query_errors)
            
            # Validate legendFormat if present
            if 'legendFormat' in target and not isinstance(target['legendFormat'], str):
                errors.append(f"Panel {panel_index}, Target {target_index}: 'legendFormat' must be a string")
        
        return errors
    
    def validate_prometheus_query(self, query: str, panel_index: int, target_index: int) -> List[str]:
        """Validate Prometheus query syntax."""
        errors = []
        
        # Basic syntax checks
        if not query.strip():
            errors.append(f"Panel {panel_index}, Target {target_index}: Empty query")
            return errors
        
        # Check for balanced parentheses
        if query.count('(') != query.count(')'):
            errors.append(f"Panel {panel_index}, Target {target_index}: Unbalanced parentheses in query")
        
        # Check for balanced braces
        if query.count('{') != query.count('}'):
            errors.append(f"Panel {panel_index}, Target {target_index}: Unbalanced braces in query")
        
        # Check for balanced brackets
        if query.count('[') != query.count(']'):
            errors.append(f"Panel {panel_index}, Target {target_index}: Unbalanced brackets in query")
        
        # Validate metric names (basic check)
        metric_pattern = r'[a-zA-Z_:][a-zA-Z0-9_:]*'
        if not re.search(metric_pattern, query):
            errors.append(f"Panel {panel_index}, Target {target_index}: No valid metric names found in query")
        
        # Check for common Prometheus functions
        has_function = any(func in query for func in self.prometheus_functions)
        has_aggregation = any(agg in query for agg in ['sum', 'avg', 'max', 'min', 'count'])
        
        if 'rate(' in query or 'increase(' in query:
            if not re.search(r'\[[0-9]+[smhd]\]', query):
                errors.append(f"Panel {panel_index}, Target {target_index}: rate/increase function missing time range")
        
        return errors
    
    def validate_template_variables(self, templating: Dict) -> List[str]:
        """Validate dashboard template variables."""
        errors = []
        
        if 'list' not in templating:
            return errors
        
        variables = templating['list']
        for i, variable in enumerate(variables):
            if 'name' not in variable:
                errors.append(f"Template variable {i}: Missing 'name' field")
            
            if 'type' not in variable:
                errors.append(f"Template variable {i}: Missing 'type' field")
            
            var_type = variable.get('type')
            if var_type == 'query' and 'query' not in variable:
                errors.append(f"Template variable {i}: Query type variable missing 'query' field")
        
        return errors
    
    def validate_dashboard_file(self, dashboard_path: Path) -> Tuple[bool, List[str]]:
        """Validate a complete dashboard file."""
        logger.info(f"🔍 Validating dashboard: {dashboard_path.name}")
        
        # Validate JSON structure
        is_valid_json, dashboard_data, json_errors = self.validate_json_structure(dashboard_path)
        if not is_valid_json:
            return False, json_errors
        
        dashboard = dashboard_data['dashboard']
        all_errors = []
        
        # Validate dashboard metadata
        metadata_errors = self.validate_dashboard_metadata(dashboard)
        all_errors.extend(metadata_errors)
        
        # Validate panels
        if 'panels' in dashboard:
            panel_errors = self.validate_panels(dashboard['panels'])
            all_errors.extend(panel_errors)
        
        # Validate template variables
        if 'templating' in dashboard:
            template_errors = self.validate_template_variables(dashboard['templating'])
            all_errors.extend(template_errors)
        
        # Validate annotations
        if 'annotations' in dashboard and 'list' in dashboard['annotations']:
            for i, annotation in enumerate(dashboard['annotations']['list']):
                if 'expr' in annotation:
                    query_errors = self.validate_prometheus_query(
                        annotation['expr'], f"annotation-{i}", 0
                    )
                    all_errors.extend(query_errors)
        
        is_valid = len(all_errors) == 0
        
        if is_valid:
            logger.info(f"✅ {dashboard_path.name} - Validation passed")
        else:
            logger.error(f"❌ {dashboard_path.name} - {len(all_errors)} errors found")
            for error in all_errors:
                logger.error(f"   • {error}")
        
        return is_valid, all_errors

def main():
    """Main validation function."""
    # Find dashboard files
    project_root = Path(__file__).parent.parent
    dashboards_dir = project_root / "monitoring" / "grafana" / "dashboards"
    
    if not dashboards_dir.exists():
        logger.error(f"❌ Dashboards directory not found: {dashboards_dir}")
        return False
    
    dashboard_files = list(dashboards_dir.glob("*.json"))
    
    if not dashboard_files:
        logger.error(f"❌ No dashboard files found in {dashboards_dir}")
        return False
    
    logger.info(f"📊 Found {len(dashboard_files)} dashboard files to validate")
    
    validator = DashboardValidator()
    total_valid = 0
    total_invalid = 0
    all_errors = []
    
    for dashboard_file in dashboard_files:
        is_valid, errors = validator.validate_dashboard_file(dashboard_file)
        
        if is_valid:
            total_valid += 1
        else:
            total_invalid += 1
            all_errors.extend([f"{dashboard_file.name}: {error}" for error in errors])
    
    # Summary
    logger.info("\n" + "="*50)
    logger.info("📊 VALIDATION SUMMARY")
    logger.info("="*50)
    logger.info(f"✅ Valid dashboards: {total_valid}")
    logger.info(f"❌ Invalid dashboards: {total_invalid}")
    logger.info(f"📝 Total errors: {len(all_errors)}")
    
    if total_invalid == 0:
        logger.info("\n🎉 All dashboards passed validation!")
        return True
    else:
        logger.error(f"\n💥 {total_invalid} dashboards failed validation")
        logger.error("Please fix the following errors:")
        for error in all_errors[:10]:  # Show first 10 errors
            logger.error(f"   • {error}")
        
        if len(all_errors) > 10:
            logger.error(f"   ... and {len(all_errors) - 10} more errors")
        
        return False

if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)