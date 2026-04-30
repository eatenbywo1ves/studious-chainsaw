# ADR-014: SendGrid for Email Delivery

**Status**: Accepted | **Date**: 2024-10-14 | **Deciders**: Product, DevOps

## Decision
Use **SendGrid** (Twilio) for transactional email delivery.

## Rationale
- 99.9% delivery SLA
- Comprehensive analytics and deliverability tracking
- Template management with dynamic content
- DKIM/SPF/DMARC support out of the box
- Generous free tier (100 emails/day)

## Email Types
| Type | Template | Trigger |
|------|----------|---------|
| Welcome | `d-welcome-001` | User registration |
| Password Reset | `d-reset-002` | Forgot password |
| Invoice | `d-invoice-003` | Stripe webhook |
| Alert | `d-alert-004` | System notification |
| Analysis Complete | `d-complete-005` | Job finished |

## Implementation
```python
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

def send_transactional_email(to_email: str, template_id: str, data: dict):
    message = Mail(
        from_email='noreply@catalytic.dev',
        to_emails=to_email
    )
    message.template_id = template_id
    message.dynamic_template_data = data

    sg = SendGridAPIClient(os.environ['SENDGRID_API_KEY'])
    return sg.send(message)
```

## Security
- API keys stored in Vault (rotated quarterly)
- IP whitelisting for webhook callbacks
- Unsubscribe handling per CAN-SPAM

## Alternatives Rejected
- **AWS SES**: More complex setup, less analytics
- **Mailgun**: Higher cost at scale
- **Self-hosted SMTP**: Deliverability challenges

---
**Last Updated**: 2024-10-15
