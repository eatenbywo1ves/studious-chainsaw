# ADR-009: Stripe for Payment Processing

**Status**: Accepted | **Date**: 2024-10-05 | **Deciders**: Product, Architecture

## Decision
Use **Stripe** for payment processing, subscription management, and invoicing.

## Rationale
- PCI DSS Level 1 compliant (no card data touches our servers)
- Excellent webhook infrastructure
- Subscription billing built-in
- Strong documentation and SDKs

## Implementation
```python
# Create checkout session
session = stripe.checkout.Session.create(
    customer=customer_id,
    line_items=[{'price': price_id, 'quantity': 1}],
    mode='subscription',
    success_url='https://app.example.com/success',
    cancel_url='https://app.example.com/cancel'
)
```

## Webhook Events
- `checkout.session.completed` → Create subscription
- `invoice.paid` → Record payment
- `customer.subscription.deleted` → Handle cancellation

## Alternatives Rejected
- **Custom payment processing**: PCI compliance burden too high
- **PayPal**: Less developer-friendly, complex APIs
- **Paddle**: Less flexible pricing models

---
**Last Updated**: 2024-10-15
