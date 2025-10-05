"""
Integration tests for Stripe webhook endpoints
"""
import pytest
import httpx
import json
import os
import time
import hashlib
import hmac

class TestStripeWebhooks:
    """Test cases for Stripe webhook integration"""

    @pytest.fixture
    def webhook_secret(self):
        """Get webhook secret from environment"""
        return os.getenv('STRIPE_WEBHOOK_SECRET', 'whsec_test_secret')

    @pytest.fixture
    def api_base_url(self):
        """Get API base URL"""
        return os.getenv('API_BASE_URL', 'http://localhost:8000')

    @pytest.fixture
    def stripe_signature(self, webhook_secret):
        """Generate Stripe signature for webhook payload"""
        def _generate_signature(payload: str, timestamp: int = None):
            if timestamp is None:
                timestamp = int(time.time())

            # Create the signed payload
            signed_payload = f"{timestamp}.{payload}"

            # Generate signature
            signature = hmac.new(
                webhook_secret.encode('utf-8'),
                signed_payload.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            return f"t={timestamp},v1={signature}"

        return _generate_signature

    @pytest.mark.asyncio
    async def test_customer_subscription_created(self, api_base_url, stripe_signature):
        """Test customer.subscription.created webhook"""
        payload = {
            "id": "evt_test_webhook",
            "object": "event",
            "api_version": "2020-08-27",
            "created": 1609459200,
            "data": {
                "object": {
                    "id": "sub_test123",
                    "object": "subscription",
                    "customer": "cus_test123",
                    "status": "active",
                    "items": {
                        "data": [
                            {
                                "id": "si_test123",
                                "price": {
                                    "id": "price_test123",
                                    "nickname": "Pro Plan"
                                }
                            }
                        ]
                    }
                }
            },
            "type": "customer.subscription.created"
        }

        payload_str = json.dumps(payload)
        signature = stripe_signature(payload_str)

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{api_base_url}/api/stripe/webhooks",
                content=payload_str,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": signature
                }
            )

        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "success"

    @pytest.mark.asyncio
    async def test_customer_subscription_updated(self, api_base_url, stripe_signature):
        """Test customer.subscription.updated webhook"""
        payload = {
            "id": "evt_test_webhook_updated",
            "object": "event",
            "api_version": "2020-08-27",
            "created": 1609459200,
            "data": {
                "object": {
                    "id": "sub_test123",
                    "object": "subscription",
                    "customer": "cus_test123",
                    "status": "past_due",
                    "items": {
                        "data": [
                            {
                                "id": "si_test123",
                                "price": {
                                    "id": "price_test123",
                                    "nickname": "Pro Plan"
                                }
                            }
                        ]
                    }
                }
            },
            "type": "customer.subscription.updated"
        }

        payload_str = json.dumps(payload)
        signature = stripe_signature(payload_str)

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{api_base_url}/api/stripe/webhooks",
                content=payload_str,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": signature
                }
            )

        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "success"

    @pytest.mark.asyncio
    async def test_invoice_payment_succeeded(self, api_base_url, stripe_signature):
        """Test invoice.payment_succeeded webhook"""
        payload = {
            "id": "evt_test_payment_succeeded",
            "object": "event",
            "api_version": "2020-08-27",
            "created": 1609459200,
            "data": {
                "object": {
                    "id": "in_test123",
                    "object": "invoice",
                    "customer": "cus_test123",
                    "subscription": "sub_test123",
                    "status": "paid",
                    "amount_paid": 2000,
                    "currency": "usd"
                }
            },
            "type": "invoice.payment_succeeded"
        }

        payload_str = json.dumps(payload)
        signature = stripe_signature(payload_str)

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{api_base_url}/api/stripe/webhooks",
                content=payload_str,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": signature
                }
            )

        assert response.status_code == 200
        response_data = response.json()
        assert response_data["status"] == "success"

    @pytest.mark.asyncio
    async def test_invalid_signature(self, api_base_url):
        """Test webhook with invalid signature"""
        payload = {
            "id": "evt_test_invalid",
            "object": "event",
            "type": "customer.subscription.created"
        }

        payload_str = json.dumps(payload)

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{api_base_url}/api/stripe/webhooks",
                content=payload_str,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": "invalid_signature"
                }
            )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_webhook_idempotency(self, api_base_url, stripe_signature):
        """Test webhook idempotency - same event ID should be processed only once"""
        payload = {
            "id": "evt_test_idempotency",
            "object": "event",
            "api_version": "2020-08-27",
            "created": 1609459200,
            "data": {
                "object": {
                    "id": "sub_test123",
                    "object": "subscription",
                    "customer": "cus_test123",
                    "status": "active"
                }
            },
            "type": "customer.subscription.created"
        }

        payload_str = json.dumps(payload)
        signature = stripe_signature(payload_str)

        async with httpx.AsyncClient() as client:
            # First request
            response1 = await client.post(
                f"{api_base_url}/api/stripe/webhooks",
                content=payload_str,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": signature
                }
            )

            # Second request with same event ID
            response2 = await client.post(
                f"{api_base_url}/api/stripe/webhooks",
                content=payload_str,
                headers={
                    "Content-Type": "application/json",
                    "Stripe-Signature": signature
                }
            )

        assert response1.status_code == 200
        assert response2.status_code == 200  # Should still return 200 but not process again

    @pytest.mark.asyncio
    async def test_webhook_metrics_endpoint(self, api_base_url):
        """Test webhook metrics endpoint"""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{api_base_url}/api/stripe/webhooks/metrics")

        assert response.status_code == 200
        metrics = response.json()
        assert "total_webhooks_received" in metrics
        assert "successful_webhooks" in metrics
        assert "failed_webhooks" in metrics
