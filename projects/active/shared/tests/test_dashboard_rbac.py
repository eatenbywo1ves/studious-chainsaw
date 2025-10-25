"""
Comprehensive Test Suite for Dashboard Framework RBAC Integration

Tests all RBAC permission scenarios:
- Dashboard creation with/without permissions
- Dashboard read by owner, shared users, and public dashboards
- Dashboard update by owner and shared users
- Dashboard delete by owner only
- Widget operations with permission checks
- Role-based access (admin, operator, viewer)
- Share dashboard functionality
- Export/import with permissions
"""

import asyncio
import json
import os
import sys
import unittest
from datetime import datetime
from typing import Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analytics.dashboard_framework import (
    DashboardFramework,
    Dashboard,
    WidgetConfig,
    WidgetType,
)
from security.rbac import RBACManager, ResourceType, Action


class TestDashboardRBAC(unittest.TestCase):
    """Test suite for Dashboard Framework RBAC integration"""

    def setUp(self):
        """Set up test fixtures"""
        # Ensure dashboards directory exists
        import os
        os.makedirs("dashboards", exist_ok=True)

        # Create dashboard framework with RBAC enabled
        self.framework = DashboardFramework(
            config={"storage_path": "./test_dashboards"}, enable_rbac=True
        )

        # Set up test users
        self.tenant_id = "test-tenant-001"
        self.owner_user_id = "user-owner-001"
        self.admin_user_id = "user-admin-001"
        self.operator_user_id = "user-operator-001"
        self.viewer_user_id = "user-viewer-001"
        self.shared_user_id = "user-shared-001"
        self.unauthorized_user_id = "user-unauthorized-001"

        # Assign roles to test users via RBAC manager
        rbac = self.framework.rbac_manager
        asyncio.run(
            rbac.assign_role_to_user(
                self.admin_user_id, "tenant_admin", tenant_id=self.tenant_id
            )
        )
        asyncio.run(
            rbac.assign_role_to_user(
                self.operator_user_id, "agent_operator", tenant_id=self.tenant_id
            )
        )
        asyncio.run(
            rbac.assign_role_to_user(
                self.viewer_user_id, "viewer", tenant_id=self.tenant_id
            )
        )

    def tearDown(self):
        """Clean up test fixtures"""
        # Clear all dashboards
        self.framework.dashboards.clear()

    # Test 1: Dashboard creation with permission
    def test_dashboard_creation_with_permission(self):
        """Test that users with CREATE permission can create dashboards"""

        async def run_test():
            dashboard_config = {
                "name": "Test Dashboard",
                "description": "Created by authorized user",
                "tenant_id": self.tenant_id,
                "owner_id": self.admin_user_id,
            }

            # Admin should be able to create dashboard
            dashboard = await self.framework.create_dashboard(
                dashboard_config, user_id=self.admin_user_id
            )

            self.assertIsNotNone(dashboard)
            self.assertEqual(dashboard.name, "Test Dashboard")
            self.assertEqual(dashboard.owner_id, self.admin_user_id)
            self.assertEqual(dashboard.tenant_id, self.tenant_id)

        asyncio.run(run_test())
        print("PASS: Test 1: Dashboard creation with permission - PASSED")

    # Test 2: Dashboard creation without permission
    def test_dashboard_creation_without_permission(self):
        """Test that users without CREATE permission cannot create dashboards"""

        async def run_test():
            dashboard_config = {
                "name": "Unauthorized Dashboard",
                "description": "Should fail",
                "tenant_id": self.tenant_id,
                "owner_id": self.viewer_user_id,
            }

            # Viewer should not be able to create dashboard
            with self.assertRaises(PermissionError) as context:
                await self.framework.create_dashboard(
                    dashboard_config, user_id=self.viewer_user_id
                )

            self.assertIn("Access denied", str(context.exception))

        asyncio.run(run_test())
        print("PASS: Test 2: Dashboard creation without permission - PASSED")

    # Test 3: Dashboard read by owner
    def test_dashboard_read_by_owner(self):
        """Test that dashboard owner can read their own dashboard"""

        async def run_test():
            # Create dashboard
            dashboard_config = {
                "name": "Owner Dashboard",
                "description": "Owned dashboard",
                "tenant_id": self.tenant_id,
                "owner_id": self.admin_user_id,
                "is_public": False,
            }
            dashboard = await self.framework.create_dashboard(
                dashboard_config, user_id=self.admin_user_id
            )

            # Owner should be able to read it
            retrieved = await self.framework.get_dashboard(
                dashboard.id, user_id=self.admin_user_id
            )

            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved.id, dashboard.id)

        asyncio.run(run_test())
        print("PASS: Test 3: Dashboard read by owner - PASSED")

    # Test 4: Dashboard read by shared user
    def test_dashboard_read_by_shared_user(self):
        """Test that shared users can read dashboard"""

        async def run_test():
            # Create dashboard
            dashboard_config = {
                "name": "Shared Dashboard",
                "description": "Shared with specific user",
                "tenant_id": self.tenant_id,
                "owner_id": self.admin_user_id,
                "is_public": False,
                "shared_users": [self.shared_user_id],
            }
            dashboard = await self.framework.create_dashboard(
                dashboard_config, user_id=self.admin_user_id
            )

            # Shared user should be able to read it
            retrieved = await self.framework.get_dashboard(
                dashboard.id, user_id=self.shared_user_id
            )

            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved.id, dashboard.id)

        asyncio.run(run_test())
        print("PASS: Test 4: Dashboard read by shared user - PASSED")

    # Test 5: Dashboard read public
    def test_dashboard_read_public(self):
        """Test that anyone can read public dashboards"""

        async def run_test():
            # Create public dashboard
            dashboard_config = {
                "name": "Public Dashboard",
                "description": "Public dashboard",
                "tenant_id": self.tenant_id,
                "owner_id": self.admin_user_id,
                "is_public": True,
            }
            dashboard = await self.framework.create_dashboard(
                dashboard_config, user_id=self.admin_user_id
            )

            # Any user should be able to read public dashboard
            retrieved = await self.framework.get_dashboard(
                dashboard.id, user_id=self.unauthorized_user_id
            )

            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved.id, dashboard.id)

        asyncio.run(run_test())
        print("PASS: Test 5: Dashboard read public - PASSED")

    # Test 6: Dashboard read unauthorized
    def test_dashboard_read_unauthorized(self):
        """Test that unauthorized users cannot read private dashboards"""

        async def run_test():
            # Create private dashboard
            dashboard_config = {
                "name": "Private Dashboard",
                "description": "Private dashboard",
                "tenant_id": self.tenant_id,
                "owner_id": self.admin_user_id,
                "is_public": False,
            }
            dashboard = await self.framework.create_dashboard(
                dashboard_config, user_id=self.admin_user_id
            )

            # Unauthorized user should not be able to read it
            with self.assertRaises(PermissionError):
                await self.framework.get_dashboard(
                    dashboard.id, user_id=self.unauthorized_user_id
                )

        asyncio.run(run_test())
        print("PASS: Test 6: Dashboard read unauthorized - PASSED")

    # Test 7: Dashboard update by owner
    def test_dashboard_update_by_owner(self):
        """Test that dashboard owner can update their dashboard"""

        async def run_test():
            # Create dashboard
            dashboard_config = {
                "name": "Update Test Dashboard",
                "description": "Original description",
                "tenant_id": self.tenant_id,
                "owner_id": self.admin_user_id,
            }
            dashboard = await self.framework.create_dashboard(
                dashboard_config, user_id=self.admin_user_id
            )

            # Owner should be able to update it
            updated = await self.framework.update_dashboard(
                dashboard.id,
                {"description": "Updated description"},
                user_id=self.admin_user_id,
            )

            self.assertEqual(updated.description, "Updated description")

        asyncio.run(run_test())
        print("PASS: Test 7: Dashboard update by owner - PASSED")

    # Test 8: Dashboard update by shared user
    def test_dashboard_update_by_shared_user(self):
        """Test that shared users can update dashboard"""

        async def run_test():
            # Create dashboard shared with specific user
            dashboard_config = {
                "name": "Shared Update Dashboard",
                "description": "Original description",
                "tenant_id": self.tenant_id,
                "owner_id": self.admin_user_id,
                "shared_users": [self.shared_user_id],
            }
            dashboard = await self.framework.create_dashboard(
                dashboard_config, user_id=self.admin_user_id
            )

            # Shared user should be able to update it
            updated = await self.framework.update_dashboard(
                dashboard.id,
                {"description": "Updated by shared user"},
                user_id=self.shared_user_id,
            )

            self.assertEqual(updated.description, "Updated by shared user")

        asyncio.run(run_test())
        print("PASS: Test 8: Dashboard update by shared user - PASSED")

    # Test 9: Dashboard delete by owner
    def test_dashboard_delete_by_owner(self):
        """Test that dashboard owner can delete their dashboard"""

        async def run_test():
            # Create dashboard
            dashboard_config = {
                "name": "Delete Test Dashboard",
                "description": "Will be deleted",
                "tenant_id": self.tenant_id,
                "owner_id": self.admin_user_id,
            }
            dashboard = await self.framework.create_dashboard(
                dashboard_config, user_id=self.admin_user_id
            )

            # Owner should be able to delete it
            result = await self.framework.delete_dashboard(
                dashboard.id, user_id=self.admin_user_id
            )

            self.assertTrue(result)
            self.assertNotIn(dashboard.id, self.framework.dashboards)

        asyncio.run(run_test())
        print("PASS: Test 9: Dashboard delete by owner - PASSED")

    # Test 10: Dashboard delete by non-owner
    def test_dashboard_delete_by_non_owner(self):
        """Test that non-owners cannot delete dashboard (strict owner-only)"""

        async def run_test():
            # Create dashboard
            dashboard_config = {
                "name": "Protected Dashboard",
                "description": "Cannot be deleted by non-owner",
                "tenant_id": self.tenant_id,
                "owner_id": self.admin_user_id,
                "shared_users": [self.shared_user_id],
            }
            dashboard = await self.framework.create_dashboard(
                dashboard_config, user_id=self.admin_user_id
            )

            # Shared user should NOT be able to delete it
            with self.assertRaises(PermissionError) as context:
                await self.framework.delete_dashboard(
                    dashboard.id, user_id=self.shared_user_id
                )

            self.assertIn("owner", str(context.exception).lower())

        asyncio.run(run_test())
        print("PASS: Test 10: Dashboard delete by non-owner - PASSED")

    # Test 11: Widget operations
    def test_widget_operations(self):
        """Test widget add/update/remove with permission checks"""

        async def run_test():
            # Create dashboard
            dashboard_config = {
                "name": "Widget Test Dashboard",
                "description": "For widget operations",
                "tenant_id": self.tenant_id,
                "owner_id": self.operator_user_id,
            }
            dashboard = await self.framework.create_dashboard(
                dashboard_config, user_id=self.operator_user_id
            )

            # Add widget (owner has permission)
            widget_config = {
                "type": WidgetType.METRIC_CARD.value,
                "title": "Test Widget",
                "x": 0,
                "y": 0,
                "width": 4,
                "height": 3,
            }
            widget = await self.framework.add_widget(
                dashboard.id, widget_config, user_id=self.operator_user_id
            )
            self.assertIsNotNone(widget)

            # Update widget (owner has permission)
            updated_widget = await self.framework.update_widget(
                dashboard.id,
                widget.id,
                {"title": "Updated Widget"},
                user_id=self.operator_user_id,
            )
            self.assertEqual(updated_widget.title, "Updated Widget")

            # Remove widget (owner has permission)
            result = await self.framework.remove_widget(
                dashboard.id, widget.id, user_id=self.operator_user_id
            )
            self.assertTrue(result)

            # Unauthorized user should not be able to add widget
            with self.assertRaises(PermissionError):
                await self.framework.add_widget(
                    dashboard.id, widget_config, user_id=self.unauthorized_user_id
                )

        asyncio.run(run_test())
        print("PASS: Test 11: Widget operations - PASSED")

    # Test 12: Admin access
    def test_admin_access(self):
        """Test that admin users have full access"""

        async def run_test():
            # Admin creates dashboard
            dashboard_config = {
                "name": "Admin Dashboard",
                "description": "Created by admin",
                "tenant_id": self.tenant_id,
                "owner_id": self.admin_user_id,
            }
            dashboard = await self.framework.create_dashboard(
                dashboard_config, user_id=self.admin_user_id
            )

            # Admin can read
            retrieved = await self.framework.get_dashboard(
                dashboard.id, user_id=self.admin_user_id
            )
            self.assertIsNotNone(retrieved)

            # Admin can update
            updated = await self.framework.update_dashboard(
                dashboard.id,
                {"description": "Updated by admin"},
                user_id=self.admin_user_id,
            )
            self.assertEqual(updated.description, "Updated by admin")

            # Admin can delete
            result = await self.framework.delete_dashboard(
                dashboard.id, user_id=self.admin_user_id
            )
            self.assertTrue(result)

        asyncio.run(run_test())
        print("PASS: Test 12: Admin access - PASSED")

    # Test 13: Viewer role access
    def test_viewer_role_access(self):
        """Test that viewer role has read-only access"""

        async def run_test():
            # Admin creates a public dashboard
            dashboard_config = {
                "name": "Public Dashboard for Viewer",
                "description": "Read-only test",
                "tenant_id": self.tenant_id,
                "owner_id": self.admin_user_id,
                "is_public": True,
            }
            dashboard = await self.framework.create_dashboard(
                dashboard_config, user_id=self.admin_user_id
            )

            # Viewer can read public dashboard
            retrieved = await self.framework.get_dashboard(
                dashboard.id, user_id=self.viewer_user_id
            )
            self.assertIsNotNone(retrieved)

            # Viewer cannot create dashboard
            new_config = {
                "name": "Viewer Dashboard",
                "description": "Should fail",
                "tenant_id": self.tenant_id,
                "owner_id": self.viewer_user_id,
            }
            with self.assertRaises(PermissionError):
                await self.framework.create_dashboard(
                    new_config, user_id=self.viewer_user_id
                )

            # Viewer cannot update dashboard
            with self.assertRaises(PermissionError):
                await self.framework.update_dashboard(
                    dashboard.id,
                    {"description": "Should fail"},
                    user_id=self.viewer_user_id,
                )

        asyncio.run(run_test())
        print("PASS: Test 13: Viewer role access - PASSED")

    # Test 14: Share dashboard
    def test_share_dashboard(self):
        """Test share_dashboard functionality"""

        async def run_test():
            # Create dashboard
            dashboard_config = {
                "name": "Dashboard to Share",
                "description": "Will be shared",
                "tenant_id": self.tenant_id,
                "owner_id": self.admin_user_id,
                "is_public": False,
            }
            dashboard = await self.framework.create_dashboard(
                dashboard_config, user_id=self.admin_user_id
            )

            # Share with specific user
            shared = await self.framework.share_dashboard(
                dashboard.id,
                owner_id=self.admin_user_id,
                shared_user_ids=[self.shared_user_id, self.operator_user_id],
            )

            self.assertEqual(len(shared.shared_users), 2)
            self.assertIn(self.shared_user_id, shared.shared_users)
            self.assertIn(self.operator_user_id, shared.shared_users)

            # Make public
            public = await self.framework.share_dashboard(
                dashboard.id, owner_id=self.admin_user_id, is_public=True
            )

            self.assertTrue(public.is_public)

            # Non-owner cannot share
            with self.assertRaises(PermissionError):
                await self.framework.share_dashboard(
                    dashboard.id,
                    owner_id=self.shared_user_id,
                    shared_user_ids=[],
                )

        asyncio.run(run_test())
        print("PASS: Test 14: Share dashboard - PASSED")

    # Test 15: Export/Import
    def test_export_import(self):
        """Test export and import with permission checks"""

        async def run_test():
            # Create dashboard
            dashboard_config = {
                "name": "Export Test Dashboard",
                "description": "Will be exported",
                "tenant_id": self.tenant_id,
                "owner_id": self.admin_user_id,
            }
            dashboard = await self.framework.create_dashboard(
                dashboard_config, user_id=self.admin_user_id
            )

            # Export (owner has permission)
            exported_data = await self.framework.export_dashboard(
                dashboard.id, user_id=self.admin_user_id
            )
            self.assertIsNotNone(exported_data)
            self.assertIsInstance(exported_data, bytes)

            # Import (creates new dashboard)
            imported = await self.framework.import_dashboard(
                exported_data, user_id=self.operator_user_id
            )
            self.assertIsNotNone(imported)
            self.assertNotEqual(imported.id, dashboard.id)  # New ID
            self.assertEqual(imported.owner_id, self.operator_user_id)  # New owner

            # Unauthorized user cannot export private dashboard
            with self.assertRaises(PermissionError):
                await self.framework.export_dashboard(
                    dashboard.id, user_id=self.unauthorized_user_id
                )

            # Import requires user_id
            with self.assertRaises(ValueError):
                await self.framework.import_dashboard(exported_data, user_id=None)

        asyncio.run(run_test())
        print("PASS: Test 15: Export/Import - PASSED")


def run_tests():
    """Run all tests and display results"""
    print("\n" + "=" * 70)
    print("DASHBOARD FRAMEWORK RBAC INTEGRATION TEST SUITE")
    print("=" * 70 + "\n")

    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestDashboardRBAC)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Display summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.wasSuccessful():
        print("\nPASS: ALL TESTS PASSED!")
    else:
        print("\nFAIL: SOME TESTS FAILED")

    print("=" * 70 + "\n")

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
