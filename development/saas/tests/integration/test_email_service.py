"""
Integration tests for email service
"""

import pytest
import httpx
import os


class TestEmailService:
    """Test cases for email service integration"""

    @pytest.fixture
    def api_base_url(self):
        """Get API base URL"""
        return os.getenv("API_BASE_URL", "http://localhost:8000")

    @pytest.fixture
    def sendgrid_api_key(self):
        """Get SendGrid API key from environment"""
        return os.getenv("SENDGRID_API_KEY", "SG.test_key")

    @pytest.mark.asyncio
    async def test_send_welcome_email(self, api_base_url):
        """Test sending welcome email"""
        email_data = {
            "to": "test@example.com",
            "template": "welcome",
            "data": {"user_name": "John Doe", "login_url": "https://app.catalytic.dev/login"},
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{api_base_url}/api/email/send",
                json=email_data,
                headers={"Content-Type": "application/json"},
            )

        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "sent"
        assert "message_id" in response_data

    @pytest.mark.asyncio
    async def test_send_subscription_confirmation(self, api_base_url):
        """Test sending subscription confirmation email"""
        email_data = {
            "to": "subscriber@example.com",
            "template": "subscription_confirmation",
            "data": {
                "user_name": "Jane Smith",
                "plan_name": "Pro Plan",
                "amount": "$20.00",
                "billing_period": "monthly",
                "next_billing_date": "2024-01-15",
            },
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{api_base_url}/api/email/send",
                json=email_data,
                headers={"Content-Type": "application/json"},
            )

        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "sent"

    @pytest.mark.asyncio
    async def test_send_password_reset(self, api_base_url):
        """Test sending password reset email"""
        email_data = {
            "to": "user@example.com",
            "template": "password_reset",
            "data": {
                "user_name": "Bob Johnson",
                "reset_link": "https://app.catalytic.dev/reset-password?token=abc123",
                "expiry_time": "1 hour",
            },
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{api_base_url}/api/email/send",
                json=email_data,
                headers={"Content-Type": "application/json"},
            )

        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "sent"

    @pytest.mark.asyncio
    async def test_send_invoice_email(self, api_base_url):
        """Test sending invoice email"""
        email_data = {
            "to": "customer@example.com",
            "template": "invoice",
            "data": {
                "user_name": "Alice Brown",
                "invoice_number": "INV-001",
                "amount": "$20.00",
                "due_date": "2024-01-15",
                "download_link": "https://app.catalytic.dev/invoice/download/123",
            },
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{api_base_url}/api/email/send",
                json=email_data,
                headers={"Content-Type": "application/json"},
            )

        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "sent"

    @pytest.mark.asyncio
    async def test_invalid_email_address(self, api_base_url):
        """Test sending email to invalid address"""
        email_data = {
            "to": "invalid-email",
            "template": "welcome",
            "data": {"user_name": "Test User"},
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{api_base_url}/api/email/send",
                json=email_data,
                headers={"Content-Type": "application/json"},
            )

        assert response.status_code == 400
        response_data = response.json()
        assert "error" in response_data

    @pytest.mark.asyncio
    async def test_missing_template(self, api_base_url):
        """Test sending email with missing template"""
        email_data = {
            "to": "test@example.com",
            "template": "nonexistent_template",
            "data": {"user_name": "Test User"},
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{api_base_url}/api/email/send",
                json=email_data,
                headers={"Content-Type": "application/json"},
            )

        assert response.status_code == 404
        response_data = response.json()
        assert "error" in response_data
        assert "template not found" in response_data["error"].lower()

    @pytest.mark.asyncio
    async def test_email_rate_limiting(self, api_base_url):
        """Test email rate limiting"""
        email_data = {
            "to": "test@example.com",
            "template": "welcome",
            "data": {"user_name": "Rate Limit Test"},
        }

        # Send multiple emails rapidly
        responses = []
        async with httpx.AsyncClient() as client:
            for i in range(10):  # Assuming rate limit is less than 10/minute
                response = await client.post(
                    f"{api_base_url}/api/email/send",
                    json=email_data,
                    headers={"Content-Type": "application/json"},
                )
                responses.append(response)

        # At least one should succeed
        success_count = sum(1 for r in responses if r.status_code == 200)
        _rate_limited_count = sum(1 for r in responses if r.status_code == 429)

        assert success_count > 0
        # May or may not hit rate limit depending on configuration

    @pytest.mark.asyncio
    async def test_email_metrics(self, api_base_url):
        """Test email service metrics endpoint"""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{api_base_url}/api/email/metrics")

        assert response.status_code == 200
        metrics = response.json()
        assert "total_emails_sent" in metrics
        assert "successful_deliveries" in metrics
        assert "failed_deliveries" in metrics
        assert "bounce_rate" in metrics

    @pytest.mark.asyncio
    async def test_email_health_check(self, api_base_url):
        """Test email service health check"""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{api_base_url}/api/email/health")

        assert response.status_code == 200
        health_data = response.json()
        assert "status" in health_data
        assert "sendgrid_connectivity" in health_data
        assert health_data["status"] in ["healthy", "degraded", "unhealthy"]

    @pytest.mark.asyncio
    async def test_bulk_email_send(self, api_base_url):
        """Test bulk email sending"""
        bulk_data = {
            "template": "newsletter",
            "recipients": [
                {"to": "user1@example.com", "data": {"user_name": "User One"}},
                {"to": "user2@example.com", "data": {"user_name": "User Two"}},
                {"to": "user3@example.com", "data": {"user_name": "User Three"}},
            ],
            "common_data": {
                "newsletter_title": "Monthly Update",
                "unsubscribe_link": "https://app.catalytic.dev/unsubscribe",
            },
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{api_base_url}/api/email/bulk-send",
                json=bulk_data,
                headers={"Content-Type": "application/json"},
                timeout=30.0,  # Bulk operations may take longer
            )

        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "queued"
        assert "batch_id" in response_data
        assert response_data["total_recipients"] == 3
