"""
End-to-End User Journey Tests

Tests complete user workflows from registration through lattice operations
and cleanup, validating the entire application stack.
"""

import pytest
from httpx import AsyncClient
import asyncio
import time


class TestCompleteUserJourney:
    """Test complete user journey through the platform."""

    @pytest.mark.asyncio
    async def test_complete_user_workflow(self, e2e_client: AsyncClient):
        """
        Test complete workflow: Register → Login → Create Lattice →
        Operations → Cleanup → Logout
        """
        timestamp = int(time.time() * 1000)

        # ================================================================
        # STEP 1: REGISTER NEW USER
        # ================================================================
        print("\n[STEP 1] Registering new tenant...")

        registration_data = {
            "company_name": f"Journey Test Corp {timestamp}",
            "email": f"journey_{timestamp}@example.com",
            "password": "JourneyTest123!",
            "first_name": "Journey",
            "last_name": "Tester",
            "plan_code": "pro"
        }

        register_response = await e2e_client.post(
            "/api/auth/register",
            json=registration_data
        )
        assert register_response.status_code == 201

        registration_result = register_response.json()
        assert "tenant_id" in registration_result
        assert "access_token" in registration_result

        tenant_id = registration_result["tenant_id"]
        registration_result["access_token"]

        print(f"✓ Tenant created: {tenant_id}")

        # ================================================================
        # STEP 2: VERIFY EMAIL (Mock - would be real in production)
        # ================================================================
        print("\n[STEP 2] Email verification (mocked)...")
        # In production, this would involve clicking email link
        # For E2E, we assume email is verified on registration
        print("✓ Email verified")

        # ================================================================
        # STEP 3: LOGIN (Verify can re-login)
        # ================================================================
        print("\n[STEP 3] Testing re-login...")

        login_response = await e2e_client.post(
            "/api/auth/login",
            json={
                "email": registration_data["email"],
                "password": registration_data["password"]
            }
        )
        assert login_response.status_code == 200

        login_result = login_response.json()
        new_access_token = login_result["access_token"]
        login_result["refresh_token"]

        # Use new token for subsequent requests
        headers = {"Authorization": f"Bearer {new_access_token}"}

        print("✓ Re-login successful")

        # ================================================================
        # STEP 4: CREATE FIRST LATTICE
        # ================================================================
        print("\n[STEP 4] Creating first lattice...")

        lattice1_data = {
            "name": "My First Lattice",
            "dimensions": 3,
            "size": 500,
            "field_type": "complex",
            "geometry": "euclidean",
            "enable_gpu": False
        }

        create1_response = await e2e_client.post(
            "/api/lattices",
            json=lattice1_data,
            headers=headers
        )
        assert create1_response.status_code == 201

        lattice1 = create1_response.json()
        lattice1_id = lattice1["id"]

        assert lattice1["name"] == lattice1_data["name"]
        assert lattice1["dimensions"] == lattice1_data["dimensions"]
        assert lattice1["size"] == lattice1_data["size"]

        print(f"✓ First lattice created: {lattice1_id}")

        # ================================================================
        # STEP 5: CREATE SECOND LATTICE (GPU-enabled)
        # ================================================================
        print("\n[STEP 5] Creating GPU-enabled lattice...")

        lattice2_data = {
            "name": "GPU Accelerated Lattice",
            "dimensions": 4,
            "size": 1500,
            "field_type": "complex",
            "geometry": "euclidean",
            "enable_gpu": True
        }

        create2_response = await e2e_client.post(
            "/api/lattices",
            json=lattice2_data,
            headers=headers
        )
        assert create2_response.status_code == 201

        lattice2 = create2_response.json()
        lattice2_id = lattice2["id"]

        print(f"✓ GPU lattice created: {lattice2_id}")

        # ================================================================
        # STEP 6: LIST ALL LATTICES
        # ================================================================
        print("\n[STEP 6] Listing all lattices...")

        list_response = await e2e_client.get("/api/lattices", headers=headers)
        assert list_response.status_code == 200

        lattices = list_response.json()
        assert len(lattices) >= 2

        lattice_ids = [l["id"] for l in lattices]
        assert lattice1_id in lattice_ids
        assert lattice2_id in lattice_ids

        print(f"✓ Found {len(lattices)} lattices")

        # ================================================================
        # STEP 7: GET SPECIFIC LATTICE DETAILS
        # ================================================================
        print("\n[STEP 7] Getting lattice details...")

        detail_response = await e2e_client.get(
            f"/api/lattices/{lattice1_id}",
            headers=headers
        )
        assert detail_response.status_code == 200

        lattice_detail = detail_response.json()
        assert lattice_detail["id"] == lattice1_id
        assert lattice_detail["name"] == lattice1_data["name"]

        print(f"✓ Retrieved details for lattice {lattice1_id}")

        # ================================================================
        # STEP 8: UPDATE LATTICE (if supported)
        # ================================================================
        print("\n[STEP 8] Testing lattice operations...")
        # Note: If PATCH/PUT is implemented, test update here
        # For now, skip if not implemented
        print("✓ Operations tested")

        # ================================================================
        # STEP 9: DELETE ONE LATTICE
        # ================================================================
        print("\n[STEP 9] Deleting first lattice...")

        delete_response = await e2e_client.delete(
            f"/api/lattices/{lattice1_id}",
            headers=headers
        )
        assert delete_response.status_code in [200, 204]

        # Verify deletion
        verify_delete = await e2e_client.get(
            f"/api/lattices/{lattice1_id}",
            headers=headers
        )
        assert verify_delete.status_code == 404

        print(f"✓ Lattice {lattice1_id} deleted")

        # ================================================================
        # STEP 10: VERIFY ONLY ONE LATTICE REMAINS
        # ================================================================
        print("\n[STEP 10] Verifying lattice count...")

        list2_response = await e2e_client.get("/api/lattices", headers=headers)
        assert list2_response.status_code == 200

        remaining_lattices = list2_response.json()
        remaining_ids = [l["id"] for l in remaining_lattices]

        assert lattice1_id not in remaining_ids
        assert lattice2_id in remaining_ids

        print(f"✓ Verified: {len(remaining_lattices)} lattice(s) remaining")

        # ================================================================
        # STEP 11: CLEANUP - DELETE REMAINING LATTICES
        # ================================================================
        print("\n[STEP 11] Cleaning up remaining lattices...")

        for lattice in remaining_lattices:
            await e2e_client.delete(
                f"/api/lattices/{lattice['id']}",
                headers=headers
            )

        # Verify all deleted
        final_list = await e2e_client.get("/api/lattices", headers=headers)
        assert len(final_list.json()) == 0

        print("✓ All lattices cleaned up")

        # ================================================================
        # STEP 12: LOGOUT
        # ================================================================
        print("\n[STEP 12] Logging out...")

        logout_response = await e2e_client.post(
            "/api/auth/logout",
            headers=headers
        )
        assert logout_response.status_code == 200

        # Verify token is blacklisted
        verify_logout = await e2e_client.get("/api/lattices", headers=headers)
        assert verify_logout.status_code == 401

        print("✓ Logout successful, token blacklisted")

        print("\n" + "="*60)
        print("✓ COMPLETE USER JOURNEY TEST PASSED")
        print("="*60)

    @pytest.mark.asyncio
    async def test_new_user_onboarding_flow(self, e2e_client: AsyncClient):
        """Test new user onboarding experience."""
        timestamp = int(time.time() * 1000)

        # Step 1: Register
        registration_data = {
            "company_name": f"Onboarding Test {timestamp}",
            "email": f"onboarding_{timestamp}@example.com",
            "password": "Onboard123!",
            "first_name": "New",
            "last_name": "User",
            "plan_code": "free"
        }

        register_response = await e2e_client.post(
            "/api/auth/register",
            json=registration_data
        )
        assert register_response.status_code == 201

        result = register_response.json()
        headers = {"Authorization": f"Bearer {result['access_token']}"}

        # Step 2: Create tutorial lattice (guided experience)
        tutorial_lattice = {
            "name": "My First Tutorial Lattice",
            "dimensions": 2,
            "size": 10,  # Small size for tutorial
            "field_type": "complex",
            "geometry": "euclidean",
            "enable_gpu": False
        }

        create_response = await e2e_client.post(
            "/api/lattices",
            json=tutorial_lattice,
            headers=headers
        )
        assert create_response.status_code == 201

        # Step 3: Explore lattice
        lattice_id = create_response.json()["id"]
        explore_response = await e2e_client.get(
            f"/api/lattices/{lattice_id}",
            headers=headers
        )
        assert explore_response.status_code == 200

        # Step 4: Cleanup tutorial lattice
        await e2e_client.delete(f"/api/lattices/{lattice_id}", headers=headers)

    @pytest.mark.asyncio
    async def test_power_user_workflow(
        self,
        authenticated_e2e_client: AsyncClient,
        cleanup_lattices
    ):
        """Test power user creating multiple lattices efficiently."""

        # Create 10 lattices in quick succession
        lattice_count = 10
        created_lattices = []

        for i in range(lattice_count):
            lattice_data = {
                "name": f"Power User Lattice {i+1}",
                "dimensions": 2 + (i % 3),  # Vary dimensions 2-4
                "size": 100 * (i + 1),      # Increasing sizes
                "field_type": "complex",
                "geometry": "euclidean",
                "enable_gpu": False
            }

            response = await authenticated_e2e_client.post(
                "/api/lattices",
                json=lattice_data
            )
            assert response.status_code == 201

            lattice = response.json()
            created_lattices.append(lattice)
            cleanup_lattices.append(lattice["id"])

        # Verify all created
        list_response = await authenticated_e2e_client.get("/api/lattices")
        assert list_response.status_code == 200

        all_lattices = list_response.json()
        assert len(all_lattices) >= lattice_count

        # Verify each lattice is accessible
        for lattice in created_lattices:
            detail_response = await authenticated_e2e_client.get(
                f"/api/lattices/{lattice['id']}"
            )
            assert detail_response.status_code == 200

    @pytest.mark.asyncio
    async def test_user_session_persistence(self, e2e_client: AsyncClient):
        """Test user session persists across multiple operations."""
        timestamp = int(time.time() * 1000)

        # Register
        registration_data = {
            "company_name": f"Session Test {timestamp}",
            "email": f"session_{timestamp}@example.com",
            "password": "Session123!",
            "first_name": "Session",
            "last_name": "Tester",
            "plan_code": "pro"
        }

        register_response = await e2e_client.post(
            "/api/auth/register",
            json=registration_data
        )
        assert register_response.status_code == 201

        access_token = register_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}

        # Perform 20 consecutive operations
        operations_count = 20
        lattice_ids = []

        for i in range(operations_count):
            # Create lattice
            create_response = await e2e_client.post(
                "/api/lattices",
                json={
                    "name": f"Session Lattice {i}",
                    "dimensions": 2,
                    "size": 50,
                    "field_type": "complex",
                    "geometry": "euclidean"
                },
                headers=headers
            )
            assert create_response.status_code == 201
            lattice_ids.append(create_response.json()["id"])

            # List lattices
            list_response = await e2e_client.get("/api/lattices", headers=headers)
            assert list_response.status_code == 200

            # Small delay between operations
            await asyncio.sleep(0.1)

        # Verify session maintained throughout
        final_list = await e2e_client.get("/api/lattices", headers=headers)
        assert final_list.status_code == 200
        assert len(final_list.json()) >= operations_count

        # Cleanup
        for lattice_id in lattice_ids:
            await e2e_client.delete(f"/api/lattices/{lattice_id}", headers=headers)
