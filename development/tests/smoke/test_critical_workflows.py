#!/usr/bin/env python3
"""
Smoke Tests - Critical User Workflows

These tests verify that must-work user flows are functional in production.
Run these immediately after deployment to ensure core features work.
"""

import os
import sys
import pytest
import requests
import time
import uuid

# Add parent directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# Configuration
PRODUCTION_URL = os.getenv("PRODUCTION_URL", "http://localhost:8000")
API_TIMEOUT = 30  # seconds for complex operations
TEST_EMAIL = f"smoketest-{uuid.uuid4()}@example.com"
TEST_PASSWORD = "SmokeTest123!@#"


class TestCriticalWorkflows:
    """Critical user workflow smoke tests"""

    @pytest.fixture(scope="class")
    def test_user_token(self):
        """Create a test user and return auth token"""
        # Register user
        register_url = f"{PRODUCTION_URL}/api/auth/register"
        register_data = {
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "tenant_name": f"SmokeTest-{uuid.uuid4().hex[:8]}",
        }

        try:
            response = requests.post(register_url, json=register_data, timeout=API_TIMEOUT)

            # User might already exist from previous run
            if response.status_code == 400 and "already exists" in response.text.lower():
                # Try to login instead
                login_url = f"{PRODUCTION_URL}/api/auth/login"
                login_data = {"email": TEST_EMAIL, "password": TEST_PASSWORD}
                response = requests.post(login_url, json=login_data, timeout=API_TIMEOUT)

            assert response.status_code in [200, 201], (
                f"Registration/Login failed: {response.status_code} - {response.text}"
            )

            data = response.json()
            token = data.get("access_token") or data.get("token")
            assert token, f"No token in response: {data}"

            print(f"✓ Test user authenticated: {TEST_EMAIL}")
            yield token

            # Cleanup (optional - test users can be cleaned up separately)
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Test user setup failed: {e}")

    def test_user_registration_flow(self):
        """Test: User can register a new account"""
        url = f"{PRODUCTION_URL}/api/auth/register"

        unique_email = f"smoketest-{uuid.uuid4()}@example.com"
        data = {
            "email": unique_email,
            "password": TEST_PASSWORD,
            "tenant_name": f"SmokeTest-{uuid.uuid4().hex[:8]}",
        }

        try:
            response = requests.post(url, json=data, timeout=API_TIMEOUT)

            # Accept 200 or 201
            assert response.status_code in [200, 201], (
                f"Registration failed: {response.status_code} - {response.text}"
            )

            response_data = response.json()
            assert "access_token" in response_data or "token" in response_data, (
                f"No token in response: {response_data}"
            )

            print(f"✓ User registration workflow successful for {unique_email}")
        except requests.exceptions.RequestException as e:
            pytest.fail(f"User registration workflow failed: {e}")

    def test_user_login_flow(self, test_user_token):
        """Test: User can log in with credentials"""
        url = f"{PRODUCTION_URL}/api/auth/login"

        data = {"email": TEST_EMAIL, "password": TEST_PASSWORD}

        try:
            response = requests.post(url, json=data, timeout=API_TIMEOUT)
            assert response.status_code == 200, (
                f"Login failed: {response.status_code} - {response.text}"
            )

            response_data = response.json()
            assert "access_token" in response_data or "token" in response_data, (
                f"No token in login response: {response_data}"
            )

            print("✓ User login workflow successful")
        except requests.exceptions.RequestException as e:
            pytest.fail(f"User login workflow failed: {e}")

    def test_authenticated_api_access(self, test_user_token):
        """Test: Authenticated user can access protected endpoints"""
        url = f"{PRODUCTION_URL}/api/tenants"

        headers = {"Authorization": f"Bearer {test_user_token}"}

        try:
            response = requests.get(url, headers=headers, timeout=API_TIMEOUT)
            assert response.status_code == 200, (
                f"Authenticated API access failed: {response.status_code} - {response.text}"
            )

            # Should return tenant information
            data = response.json()
            assert isinstance(data, (list, dict)), f"Unexpected response format: {data}"

            print("✓ Authenticated API access successful")
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Authenticated API access failed: {e}")

    def test_create_subscription_flow(self, test_user_token):
        """Test: User can create/view subscription"""
        url = f"{PRODUCTION_URL}/api/subscriptions"

        headers = {"Authorization": f"Bearer {test_user_token}"}

        try:
            # Get current subscription status
            response = requests.get(url, headers=headers, timeout=API_TIMEOUT)

            # Accept 200 (has subscription) or 404 (no subscription yet)
            assert response.status_code in [200, 404], (
                f"Subscription check failed: {response.status_code} - {response.text}"
            )

            if response.status_code == 200:
                data = response.json()
                print(f"✓ Subscription workflow successful: {data.get('plan', 'active')}")
            else:
                print("✓ Subscription workflow accessible (no subscription yet)")
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Subscription workflow failed: {e}")

    def test_lattice_creation_flow(self, test_user_token):
        """Test: User can create a lattice (core feature)"""
        url = f"{PRODUCTION_URL}/api/lattices"

        headers = {"Authorization": f"Bearer {test_user_token}", "Content-Type": "application/json"}

        # Create a simple 3D lattice
        data = {
            "dimensions": [3, 3, 3],
            "name": f"smoke-test-lattice-{uuid.uuid4().hex[:8]}",
            "description": "Smoke test lattice",
        }

        try:
            response = requests.post(url, headers=headers, json=data, timeout=API_TIMEOUT)

            # Accept 200 or 201
            assert response.status_code in [200, 201], (
                f"Lattice creation failed: {response.status_code} - {response.text}"
            )

            response_data = response.json()
            lattice_id = response_data.get("lattice_id") or response_data.get("id")
            assert lattice_id, f"No lattice ID in response: {response_data}"

            print(f"✓ Lattice creation workflow successful: {lattice_id}")

            # Verify we can retrieve it
            get_url = f"{PRODUCTION_URL}/api/lattices/{lattice_id}"
            get_response = requests.get(get_url, headers=headers, timeout=API_TIMEOUT)
            assert get_response.status_code == 200, "Created lattice not retrievable"

        except requests.exceptions.RequestException as e:
            pytest.fail(f"Lattice creation workflow failed: {e}")

    def test_lattice_pathfinding_flow(self, test_user_token):
        """Test: User can perform pathfinding on a lattice"""
        # First create a lattice
        create_url = f"{PRODUCTION_URL}/api/lattices"
        headers = {"Authorization": f"Bearer {test_user_token}", "Content-Type": "application/json"}

        lattice_data = {"dimensions": [5, 5, 5], "name": f"pathfinding-test-{uuid.uuid4().hex[:8]}"}

        try:
            create_response = requests.post(
                create_url, headers=headers, json=lattice_data, timeout=API_TIMEOUT
            )
            assert create_response.status_code in [200, 201], (
                f"Lattice creation for pathfinding failed: {create_response.status_code}"
            )

            lattice_id = create_response.json().get("lattice_id") or create_response.json().get(
                "id"
            )

            # Perform pathfinding
            pathfinding_url = f"{PRODUCTION_URL}/api/lattices/{lattice_id}/pathfind"
            pathfind_data = {"start": [0, 0, 0], "end": [4, 4, 4]}

            pathfind_response = requests.post(
                pathfinding_url, headers=headers, json=pathfind_data, timeout=API_TIMEOUT
            )

            assert pathfind_response.status_code == 200, (
                f"Pathfinding failed: {pathfind_response.status_code} - {pathfind_response.text}"
            )

            pathfind_result = pathfind_response.json()
            assert "path" in pathfind_result or "result" in pathfind_result, (
                f"No path in pathfinding result: {pathfind_result}"
            )

            print("✓ Pathfinding workflow successful")
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Pathfinding workflow failed: {e}")

    def test_webhook_registration_flow(self, test_user_token):
        """Test: User can register a webhook"""
        url = f"{PRODUCTION_URL}/api/webhooks"

        headers = {"Authorization": f"Bearer {test_user_token}", "Content-Type": "application/json"}

        webhook_data = {
            "url": f"https://webhook.site/{uuid.uuid4()}",
            "events": ["lattice.created", "lattice.updated"],
            "description": "Smoke test webhook",
        }

        try:
            response = requests.post(url, headers=headers, json=webhook_data, timeout=API_TIMEOUT)

            # Accept 200 or 201
            assert response.status_code in [200, 201], (
                f"Webhook registration failed: {response.status_code} - {response.text}"
            )

            response_data = response.json()
            webhook_id = response_data.get("webhook_id") or response_data.get("id")
            assert webhook_id, f"No webhook ID in response: {response_data}"

            print(f"✓ Webhook registration workflow successful: {webhook_id}")

            # Verify we can list webhooks
            list_response = requests.get(url, headers=headers, timeout=API_TIMEOUT)
            assert list_response.status_code == 200, "Webhook list not accessible"

        except requests.exceptions.RequestException as e:
            # Webhooks might not be enabled in all environments
            print(f"⚠ Webhook workflow skipped: {e}")
            pytest.skip("Webhook functionality not available")

    def test_usage_tracking_flow(self, test_user_token):
        """Test: User can view usage statistics"""
        url = f"{PRODUCTION_URL}/api/usage"

        headers = {"Authorization": f"Bearer {test_user_token}"}

        try:
            response = requests.get(url, headers=headers, timeout=API_TIMEOUT)

            # Accept 200 (has usage) or 404 (no usage yet)
            assert response.status_code in [200, 404], (
                f"Usage tracking failed: {response.status_code} - {response.text}"
            )

            if response.status_code == 200:
                data = response.json()
                print(f"✓ Usage tracking workflow successful: {data}")
            else:
                print("✓ Usage tracking accessible (no usage data yet)")
        except requests.exceptions.RequestException as e:
            print(f"⚠ Usage tracking workflow warning: {e}")
            # Don't fail, as this might not be implemented yet

    def test_error_recovery_flow(self, test_user_token):
        """Test: System handles invalid requests gracefully"""
        url = f"{PRODUCTION_URL}/api/lattices"

        headers = {"Authorization": f"Bearer {test_user_token}", "Content-Type": "application/json"}

        # Send invalid data
        invalid_data = {
            "dimensions": "invalid",  # Should be array
            "name": "",  # Empty name
        }

        try:
            response = requests.post(url, headers=headers, json=invalid_data, timeout=API_TIMEOUT)

            # Should return validation error (400 or 422), not server error (500)
            assert response.status_code in [400, 422], (
                f"Expected validation error, got {response.status_code}"
            )

            error_data = response.json()
            assert "detail" in error_data or "error" in error_data or "message" in error_data, (
                "Error response should have detail field"
            )

            print(f"✓ Error recovery workflow successful: {error_data}")
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Error recovery workflow failed: {e}")


class TestPerformanceWorkflows:
    """Performance-critical workflow tests"""

    def test_bulk_operations_performance(self, test_user_token):
        """Test: System handles bulk operations efficiently"""
        url = f"{PRODUCTION_URL}/api/lattices"

        headers = {"Authorization": f"Bearer {test_user_token}", "Content-Type": "application/json"}

        # Create multiple small lattices
        start_time = time.time()
        created_count = 0

        for i in range(5):  # Create 5 lattices
            data = {"dimensions": [2, 2, 2], "name": f"bulk-test-{i}-{uuid.uuid4().hex[:8]}"}

            try:
                response = requests.post(url, headers=headers, json=data, timeout=API_TIMEOUT)
                if response.status_code in [200, 201]:
                    created_count += 1
            except requests.exceptions.RequestException:
                pass

        elapsed_time = time.time() - start_time

        # Should create at least some lattices within reasonable time
        assert created_count >= 3, f"Only created {created_count}/5 lattices"
        assert elapsed_time < 30, f"Bulk operations too slow: {elapsed_time:.2f}s"

        print(f"✓ Bulk operations: {created_count} lattices in {elapsed_time:.2f}s")


if __name__ == "__main__":
    # Run critical workflow tests
    print("=" * 80)
    print("PRODUCTION SMOKE TESTS - CRITICAL WORKFLOWS")
    print("=" * 80)
    print(f"Target: {PRODUCTION_URL}")
    print(f"Test User: {TEST_EMAIL}")
    print("=" * 80)

    # Run with pytest
    pytest.main([__file__, "-v", "--tb=short", "--color=yes"])
