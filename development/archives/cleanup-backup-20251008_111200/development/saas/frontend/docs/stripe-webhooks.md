# Stripe Webhooks Documentation

## Overview

This document describes the Stripe webhook implementation for the Catalytic Computing SaaS platform. Webhooks are used to handle payment events and keep the application synchronized with Stripe.

## Webhook Endpoint

**URL**: `/api/stripe/webhooks`
**Method**: POST
**Authentication**: Stripe signature verification

## Supported Events

### Payment Events

#### `checkout.session.completed`
- Triggered when a customer completes a checkout session
- Updates user's plan after successful payment
- Sends welcome email for paid plans
- Logs successful checkout for analytics

#### `invoice.payment_succeeded`
- Triggered when an invoice payment succeeds
- Sends payment confirmation email
- Logs successful payment for billing history

#### `invoice.payment_failed`
- Triggered when an invoice payment fails
- Sends payment failure notification
- Handles account suspension after multiple failures

### Subscription Events

#### `customer.subscription.created`
- Triggered when a new subscription is created
- Updates user's subscription record in database
- Sets up plan limits and permissions
- Logs subscription creation

#### `customer.subscription.updated`
- Triggered when a subscription is modified
- Handles plan changes and cancellations
- Updates subscription status and limits
- Sends cancellation confirmation if needed

#### `customer.subscription.deleted`
- Triggered when a subscription is permanently deleted
- Downgrades user to free plan
- Removes paid plan features
- Sends cancellation confirmation

#### `customer.subscription.trial_will_end`
- Triggered 3 days before trial ends
- Sends trial ending notification
- Prompts user to add payment method

### Customer Events

#### `customer.created`
- Triggered when a new customer is created in Stripe
- Links Stripe customer ID to user record
- Logs customer creation event

#### `customer.updated`
- Triggered when customer information is updated
- Syncs customer data with user profile
- Updates billing information

## Webhook Security

### Signature Verification
All webhooks are verified using Stripe's signature verification:

```typescript
const signature = headers().get('stripe-signature')
const event = stripe.webhooks.constructEvent(body, signature, webhookSecret)
```

### Environment Variables
Required environment variables:
- `STRIPE_WEBHOOK_SECRET`: Secret for webhook signature verification
- `STRIPE_SECRET_KEY`: Stripe secret key for API calls

## Event Processing

### Database Updates
Each webhook event typically involves:
1. Extracting user ID from metadata
2. Updating relevant database records
3. Sending notification emails
4. Logging events for analytics

### Error Handling
- Failed webhook processing is logged with details
- Stripe will retry failed webhooks automatically
- Critical failures trigger admin notifications

### Email Notifications
Email templates are sent for:
- Welcome messages for new paid subscribers
- Payment confirmations and failures
- Trial ending notifications
- Subscription cancellation confirmations
- Account suspension notices

## Testing Webhooks

### Local Development
1. Use Stripe CLI to forward webhooks to local server:
   ```bash
   stripe listen --forward-to localhost:3000/api/stripe/webhooks
   ```

2. Copy the webhook signing secret:
   ```bash
   stripe listen --print-secret
   ```

3. Add secret to `.env.local`:
   ```
   STRIPE_WEBHOOK_SECRET=whsec_...
   ```

### Test Events
Trigger test events using Stripe CLI:
```bash
stripe trigger checkout.session.completed
stripe trigger customer.subscription.created
stripe trigger invoice.payment_failed
```

### Webhook Logs
Monitor webhook processing in:
- Application logs (console output)
- Stripe Dashboard webhook logs
- Database event logs

## Monitoring

### Key Metrics
- Webhook success rate
- Processing latency
- Failed payment notifications
- Subscription churn events

### Alerts
Set up alerts for:
- Webhook failures (>5% failure rate)
- Payment failures (multiple consecutive failures)
- High subscription cancellation rate

## Database Schema

### Subscription Records
```sql
CREATE TABLE user_subscriptions (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  subscription_id VARCHAR(255) UNIQUE,
  customer_id VARCHAR(255),
  plan_code VARCHAR(50),
  status VARCHAR(50),
  current_period_start TIMESTAMP,
  current_period_end TIMESTAMP,
  trial_start TIMESTAMP,
  trial_end TIMESTAMP,
  cancel_at_period_end BOOLEAN,
  canceled_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
```

### Event Logs
```sql
CREATE TABLE webhook_events (
  id UUID PRIMARY KEY,
  event_type VARCHAR(100),
  stripe_event_id VARCHAR(255) UNIQUE,
  user_id UUID,
  data JSONB,
  processed_at TIMESTAMP DEFAULT NOW(),
  status VARCHAR(50) DEFAULT 'processed'
);
```

## Plan Limits Configuration

```typescript
const PLAN_LIMITS = {
  free: {
    apiCalls: 100,
    lattices: 1,
    nodes: 4,
    storage: '1GB',
    support: 'community'
  },
  starter: {
    apiCalls: 1000,
    lattices: 3,
    nodes: 16,
    storage: '10GB',
    support: 'email'
  },
  professional: {
    apiCalls: 10000,
    lattices: 10,
    nodes: 64,
    storage: '100GB',
    support: 'priority'
  },
  enterprise: {
    apiCalls: -1, // unlimited
    lattices: -1,
    nodes: -1,
    storage: 'unlimited',
    support: 'dedicated'
  }
}
```

## Troubleshooting

### Common Issues

1. **Webhook Signature Verification Failed**
   - Check webhook secret configuration
   - Verify endpoint URL in Stripe dashboard
   - Ensure raw body is used for signature verification

2. **Duplicate Event Processing**
   - Implement idempotency using `stripe_event_id`
   - Check for existing event logs before processing

3. **Missing User Metadata**
   - Ensure user ID is included in checkout session metadata
   - Verify customer creation includes user linking

### Debug Tools
- Stripe Dashboard webhook logs
- Application error logs
- Database query logs
- Email delivery logs

## Security Best Practices

1. **Validate All Webhook Events**
   - Always verify signatures
   - Check event types before processing
   - Validate metadata fields

2. **Handle Sensitive Data**
   - Never log payment method details
   - Encrypt stored customer data
   - Follow PCI compliance guidelines

3. **Rate Limiting**
   - Implement webhook rate limiting
   - Monitor for suspicious activity
   - Set up abuse detection

## Integration Checklist

- [ ] Webhook endpoint implemented
- [ ] Signature verification enabled
- [ ] All required events handled
- [ ] Database schema created
- [ ] Email templates configured
- [ ] Monitoring and alerting set up
- [ ] Local testing completed
- [ ] Production webhook URL configured
- [ ] Security review completed
- [ ] Documentation updated