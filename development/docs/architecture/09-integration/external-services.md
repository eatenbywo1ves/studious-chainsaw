# Integration Architecture: External Services

## Integration Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        External Service Integrations                         │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      Catalytic Platform                              │   │
│  │                                                                      │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────┐    │   │
│  │  │  SaaS API │  │ Catalytic │  │ GhidraGo  │  │ Infrastructure│    │   │
│  │  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └───────┬───────┘    │   │
│  └────────┼──────────────┼──────────────┼────────────────┼────────────┘   │
│           │              │              │                │                 │
│           ▼              ▼              ▼                ▼                 │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────────────┐  │
│  │   Stripe   │  │  SendGrid  │  │   Ghidra   │  │  HashiCorp Vault   │  │
│  │  Payments  │  │   Email    │  │  Framework │  │     Secrets        │  │
│  └────────────┘  └────────────┘  └────────────┘  └────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Stripe Integration

### Architecture
```
┌────────────────────────────────────────────────────────────────┐
│                     Stripe Integration                          │
│                                                                 │
│  Outbound API Calls:                                           │
│  ┌─────────┐     ┌─────────────────┐     ┌─────────────────┐  │
│  │ Billing │────►│ Stripe Client   │────►│   Stripe API    │  │
│  │ Service │     │ (stripe-python) │     │                 │  │
│  └─────────┘     └─────────────────┘     └─────────────────┘  │
│                                                                 │
│  Inbound Webhooks:                                             │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────┐  │
│  │   Stripe API    │────►│ Webhook Handler │────►│ Billing │  │
│  │                 │     │ /webhooks/stripe│     │ Service │  │
│  └─────────────────┘     └─────────────────┘     └─────────┘  │
└────────────────────────────────────────────────────────────────┘
```

### Webhook Events Handled
| Event | Action |
|-------|--------|
| `checkout.session.completed` | Create subscription record |
| `invoice.paid` | Record payment, send receipt |
| `invoice.payment_failed` | Alert user, retry logic |
| `customer.subscription.updated` | Sync subscription status |
| `customer.subscription.deleted` | Mark subscription inactive |

### Integration Code
```python
import stripe
from fastapi import HTTPException, Request

class StripeService:
    def __init__(self, api_key: str, webhook_secret: str):
        stripe.api_key = api_key
        self._webhook_secret = webhook_secret

    async def create_checkout_session(
        self,
        customer_id: str,
        price_id: str,
        success_url: str,
        cancel_url: str
    ) -> str:
        session = stripe.checkout.Session.create(
            customer=customer_id,
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=success_url,
            cancel_url=cancel_url
        )
        return session.url

    async def handle_webhook(self, request: Request) -> dict:
        payload = await request.body()
        sig_header = request.headers.get("stripe-signature")

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, self._webhook_secret
            )
        except stripe.error.SignatureVerificationError:
            raise HTTPException(status_code=400, detail="Invalid signature")

        return await self._process_event(event)
```

## SendGrid Integration

### Architecture
```
┌────────────────────────────────────────────────────────────────┐
│                    SendGrid Integration                         │
│                                                                 │
│  ┌─────────┐     ┌─────────────────┐     ┌─────────────────┐  │
│  │  Email  │────►│ SendGrid Client │────►│  SendGrid API   │  │
│  │ Service │     │                 │     │                 │  │
│  └─────────┘     └─────────────────┘     └─────────────────┘  │
│                                                                 │
│  Templates:                                                     │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ d-welcome-001 │ d-reset-002 │ d-invoice-003 │ d-alert │   │
│  └────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
```

### Email Types
| Template ID | Type | Trigger |
|-------------|------|---------|
| d-welcome-001 | Welcome | User registration |
| d-reset-002 | Password Reset | Forgot password |
| d-invoice-003 | Invoice | Payment received |
| d-alert-004 | Alert | System notification |
| d-complete-005 | Job Complete | Analysis finished |

### Integration Code
```python
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, From, To, DynamicTemplateData

class EmailService:
    def __init__(self, api_key: str, from_email: str):
        self._client = SendGridAPIClient(api_key)
        self._from_email = from_email

    async def send_template_email(
        self,
        to_email: str,
        template_id: str,
        data: dict
    ) -> bool:
        message = Mail(
            from_email=From(self._from_email, "Catalytic Platform"),
            to_emails=To(to_email)
        )
        message.template_id = template_id
        message.dynamic_template_data = DynamicTemplateData(data)

        try:
            response = self._client.send(message)
            return response.status_code == 202
        except Exception as e:
            logger.error(f"Email send failed: {e}")
            return False

    async def send_welcome_email(self, user_email: str, user_name: str):
        return await self.send_template_email(
            to_email=user_email,
            template_id="d-welcome-001",
            data={"name": user_name, "login_url": "https://app.catalytic.dev"}
        )
```

## HashiCorp Vault Integration

### Architecture
```
┌────────────────────────────────────────────────────────────────┐
│                     Vault Integration                           │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                    Application                           │  │
│  │  ┌──────────────┐     ┌──────────────────────────────┐ │  │
│  │  │ Vault Client │────►│ AppRole Authentication       │ │  │
│  │  └──────────────┘     └──────────────────────────────┘ │  │
│  └─────────────────────────────────────────────────────────┘  │
│                              │                                  │
│                              ▼                                  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                    HashiCorp Vault                       │  │
│  │  ┌────────────┐  ┌────────────┐  ┌──────────────────┐  │  │
│  │  │ Secret KV  │  │  Database  │  │  Transit Engine  │  │  │
│  │  │  Engine    │  │  Engine    │  │  (Encryption)    │  │  │
│  │  └────────────┘  └────────────┘  └──────────────────┘  │  │
│  └─────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

### Secret Paths
| Path | Type | TTL | Purpose |
|------|------|-----|---------|
| secret/jwt/private | KV v2 | Static | JWT signing key |
| secret/stripe | KV v2 | Static | Stripe API keys |
| secret/sendgrid | KV v2 | Static | SendGrid API key |
| database/creds/app | Dynamic | 1 hour | PostgreSQL credentials |

### Integration Code
```python
import hvac
from functools import lru_cache

class VaultService:
    def __init__(self, url: str, role_id: str, secret_id: str):
        self._client = hvac.Client(url=url)
        self._client.auth.approle.login(
            role_id=role_id,
            secret_id=secret_id
        )

    def get_secret(self, path: str) -> dict:
        response = self._client.secrets.kv.v2.read_secret_version(path=path)
        return response["data"]["data"]

    def get_database_credentials(self, role: str = "app") -> dict:
        response = self._client.secrets.database.generate_credentials(
            name=role
        )
        return {
            "username": response["data"]["username"],
            "password": response["data"]["password"],
            "lease_duration": response["lease_duration"]
        }

    def encrypt(self, plaintext: str, key_name: str = "app") -> str:
        response = self._client.secrets.transit.encrypt_data(
            name=key_name,
            plaintext=base64.b64encode(plaintext.encode()).decode()
        )
        return response["data"]["ciphertext"]

    def decrypt(self, ciphertext: str, key_name: str = "app") -> str:
        response = self._client.secrets.transit.decrypt_data(
            name=key_name,
            ciphertext=ciphertext
        )
        return base64.b64decode(response["data"]["plaintext"]).decode()
```

## Integration Patterns

### Circuit Breaker
All external service calls use circuit breaker pattern to handle failures gracefully.

### Retry Strategy
| Service | Max Retries | Backoff |
|---------|-------------|---------|
| Stripe | 3 | Exponential (1s, 2s, 4s) |
| SendGrid | 3 | Exponential (1s, 2s, 4s) |
| Vault | 5 | Exponential (100ms, 200ms, ...) |

### Timeout Configuration
| Service | Connect | Read | Total |
|---------|---------|------|-------|
| Stripe | 5s | 30s | 60s |
| SendGrid | 5s | 10s | 30s |
| Vault | 5s | 5s | 15s |

---
**Last Updated**: 2024-10-15
