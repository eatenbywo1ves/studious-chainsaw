import { NextRequest, NextResponse } from 'next/server';
import { headers } from 'next/headers';
import { stripe } from '../config/route';
import { createWebhookTimer } from '@/lib/webhook-logger';
import { apiClient } from '@/lib/api-client';
import { EmailHelpers } from '@/lib/email/email-service';
import Stripe from 'stripe';

// Disable body parsing for webhooks
export const dynamic = 'force-dynamic';

// POST /api/stripe/webhooks - Handle Stripe webhook events
export async function POST(request: NextRequest) {
  try {
    const body = await request.text();
    const signature = headers().get('stripe-signature');

    if (!signature) {
      console.error('No stripe-signature header found');
      return NextResponse.json(
        { error: 'No signature provided' },
        { status: 400 }
      );
    }

    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!webhookSecret) {
      console.error('No webhook secret configured');
      return NextResponse.json(
        { error: 'Webhook secret not configured' },
        { status: 500 }
      );
    }

    let event: Stripe.Event;

    try {
      event = stripe.webhooks.constructEvent(body, signature, webhookSecret);
    } catch (err) {
      console.error('Webhook signature verification failed:', err);
      return NextResponse.json(
        { error: 'Invalid signature' },
        { status: 400 }
      );
    }

    console.log(`Received webhook event: ${event.type}`);

    // Create timing logger for this event
    const timer = createWebhookTimer(event.type, event.id);

    try {
      // Handle different event types
      switch (event.type) {
        case 'checkout.session.completed':
          await handleCheckoutSessionCompleted(event.data.object as Stripe.Checkout.Session, timer);
          break;

        case 'customer.subscription.created':
          await handleSubscriptionCreated(event.data.object as Stripe.Subscription, timer);
          break;

        case 'customer.subscription.updated':
          await handleSubscriptionUpdated(event.data.object as Stripe.Subscription, timer);
          break;

        case 'customer.subscription.deleted':
          await handleSubscriptionDeleted(event.data.object as Stripe.Subscription, timer);
          break;

        case 'invoice.payment_succeeded':
          await handleInvoicePaymentSucceeded(event.data.object as Stripe.Invoice, timer);
          break;

        case 'invoice.payment_failed':
          await handleInvoicePaymentFailed(event.data.object as Stripe.Invoice, timer);
          break;

        case 'customer.created':
          await handleCustomerCreated(event.data.object as Stripe.Customer, timer);
          break;

        case 'customer.updated':
          await handleCustomerUpdated(event.data.object as Stripe.Customer, timer);
          break;

        case 'customer.subscription.trial_will_end':
          await handleTrialWillEnd(event.data.object as Stripe.Subscription, timer);
          break;

        default:
          console.log(`Unhandled event type: ${event.type}`);
          timer.success({ metadata: { unhandled: true } });
      }

      // Log successful processing if no specific timer.success() was called
      timer.success();
      return NextResponse.json({ received: true });
    } catch (handlerError) {
      timer.error(handlerError instanceof Error ? handlerError.message : 'Handler failed');
      throw handlerError;
    }
  } catch (error) {
    console.error('Webhook processing error:', error);
    return NextResponse.json(
      { error: 'Webhook processing failed' },
      { status: 500 }
    );
  }
}

// Handle successful checkout session
async function handleCheckoutSessionCompleted(session: Stripe.Checkout.Session, timer: any) {
  console.log('Processing checkout session completed:', session.id);

  const userId = session.metadata?.user_id;
  const planCode = session.metadata?.plan_code;

  try {
    if (!userId) {
      console.error('No user_id in session metadata');
      return;
    }

    // Update user's plan in database via backend API
    try {
      await apiClient.updateCustomerInfo({
        user_id: userId,
        tenant_id: session.metadata?.tenant_id || userId,
        stripe_customer_id: session.customer as string,
        email: session.customer_details?.email || undefined,
        name: session.customer_details?.name || undefined
      });
    } catch (error) {
      console.error('Error updating customer info:', error);
    }

    // Send welcome email for paid plans
    if (planCode && planCode !== 'free' && session.customer_details?.email) {
      await EmailHelpers.sendWelcomeEmail(
        session.customer_details.email,
        session.customer_details.name || 'User',
        planCode
      );
    }

    // Log successful checkout
    await logEvent('checkout_completed', {
      user_id: userId,
      plan_code: planCode,
      session_id: session.id,
      amount: session.amount_total,
      currency: session.currency
    });

    timer.success({
      user_id: userId,
      customer_id: session.customer as string,
      metadata: { plan_code: planCode, amount: session.amount_total }
    });
    console.log(`Checkout completed for user ${userId}, plan: ${planCode}`);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    timer.error(errorMessage, { user_id: userId });
    console.error('Error handling checkout session completed:', error);
    throw error;
  }
}

// Handle subscription creation
async function handleSubscriptionCreated(subscription: Stripe.Subscription, timer: any) {
  console.log('Processing subscription created:', subscription.id);

  try {
    const userId = subscription.metadata?.user_id;
    const planCode = subscription.metadata?.plan_code;

    if (!userId) {
      console.error('No user_id in subscription metadata');
      return;
    }

    // Create subscription in database via backend API
    try {
      // Type assertion for Stripe v18 compatibility - these properties exist at runtime
      const subWithPeriod = subscription as any;
      await apiClient.createSubscription({
        user_id: userId,
        tenant_id: subscription.metadata?.tenant_id || userId,
        stripe_subscription_id: subscription.id,
        stripe_customer_id: subscription.customer as string,
        plan_code: planCode || 'free',
        status: subscription.status,
        current_period_start: new Date(subWithPeriod.current_period_start * 1000),
        current_period_end: new Date(subWithPeriod.current_period_end * 1000),
        trial_start: subscription.trial_start ? new Date(subscription.trial_start * 1000) : undefined,
        trial_end: subscription.trial_end ? new Date(subscription.trial_end * 1000) : undefined
      });
    } catch (error) {
      console.error('Error creating subscription in database:', error);
      throw error;
    }

    // Log subscription creation
    await logEvent('subscription_created', {
      user_id: userId,
      subscription_id: subscription.id,
      plan_code: planCode,
      status: subscription.status
    });

    console.log(`Subscription created for user ${userId}: ${subscription.id}`);
  } catch (error) {
    console.error('Error handling subscription created:', error);
  }
}

// Handle subscription updates
async function handleSubscriptionUpdated(subscription: Stripe.Subscription, timer: any) {
  console.log('Processing subscription updated:', subscription.id);

  try {
    const userId = subscription.metadata?.user_id;

    if (!userId) {
      console.error('No user_id in subscription metadata');
      return;
    }

    // Update subscription in database via backend API
    try {
      // Type assertion for Stripe v18 compatibility - these properties exist at runtime
      const subWithPeriod = subscription as any;
      await apiClient.updateSubscription({
        stripe_subscription_id: subscription.id,
        status: subscription.status,
        current_period_start: new Date(subWithPeriod.current_period_start * 1000),
        current_period_end: new Date(subWithPeriod.current_period_end * 1000),
        cancel_at_period_end: subscription.cancel_at_period_end,
        canceled_at: subscription.canceled_at ? new Date(subscription.canceled_at * 1000) : undefined
      });
    } catch (error) {
      console.error('Error updating subscription in database:', error);
    }

    // Get user's email for notifications
    const userEmail = subscription.metadata?.user_email;

    // Handle cancellation - send email
    if (subscription.cancel_at_period_end && userEmail) {
      // Type assertion for Stripe v18 compatibility
      const subWithPeriod = subscription as any;
      const periodEndDate = new Date(subWithPeriod.current_period_end * 1000);
      const daysLeft = Math.ceil((periodEndDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));

      await EmailHelpers.sendTrialEndingEmail(userEmail, daysLeft);
    }

    // Log subscription update
    await logEvent('subscription_updated', {
      user_id: userId,
      subscription_id: subscription.id,
      status: subscription.status,
      cancel_at_period_end: subscription.cancel_at_period_end
    });

    console.log(`Subscription updated for user ${userId}: ${subscription.id}`);
  } catch (error) {
    console.error('Error handling subscription updated:', error);
  }
}

// Handle subscription deletion
async function handleSubscriptionDeleted(subscription: Stripe.Subscription, timer: any) {
  console.log('Processing subscription deleted:', subscription.id);

  try {
    const userId = subscription.metadata?.user_id;

    if (!userId) {
      console.error('No user_id in subscription metadata');
      return;
    }

    // Downgrade user to free plan via backend API
    try {
      await apiClient.cancelSubscription(userId, subscription.metadata?.tenant_id || userId);
    } catch (error) {
      console.error('Error canceling subscription in database:', error);
    }

    // Send subscription cancellation confirmation
    const userEmail = subscription.metadata?.user_email;
    if (userEmail) {
      await EmailHelpers.sendAccountSuspendedEmail(userEmail, 'Subscription cancelled');
    }

    // Log subscription deletion
    await logEvent('subscription_deleted', {
      user_id: userId,
      subscription_id: subscription.id,
      canceled_at: subscription.canceled_at
    });

    console.log(`Subscription deleted for user ${userId}: ${subscription.id}`);
  } catch (error) {
    console.error('Error handling subscription deleted:', error);
  }
}

// Handle successful invoice payment
async function handleInvoicePaymentSucceeded(invoice: Stripe.Invoice, timer: any) {
  console.log('Processing invoice payment succeeded:', invoice.id);

  try {
    // Type assertion for Stripe v18 compatibility - subscription property exists at runtime
    const invoiceWithSub = invoice as any;
    const subscriptionId = typeof invoiceWithSub.subscription === 'string' ? invoiceWithSub.subscription : invoiceWithSub.subscription?.id;

    if (subscriptionId) {
      // Get subscription details
      const subscription = await stripe.subscriptions.retrieve(subscriptionId);
      const userId = subscription.metadata?.user_id;

      if (userId) {
        // Send payment confirmation email
        const userEmail = subscription.metadata?.user_email;
        if (userEmail) {
          await EmailHelpers.sendPaymentSuccessEmail(userEmail, invoice.amount_paid, invoice.currency);
        }

        // Log successful payment
        await logEvent('payment_succeeded', {
          user_id: userId,
          invoice_id: invoice.id,
          subscription_id: subscriptionId,
          amount: invoice.amount_paid,
          currency: invoice.currency
        });
      }
    }

    console.log(`Invoice payment succeeded: ${invoice.id}`);
  } catch (error) {
    console.error('Error handling invoice payment succeeded:', error);
  }
}

// Handle failed invoice payment
async function handleInvoicePaymentFailed(invoice: Stripe.Invoice, timer: any) {
  console.log('Processing invoice payment failed:', invoice.id);

  try {
    // Type assertion for Stripe v18 compatibility - subscription property exists at runtime
    const invoiceWithSub = invoice as any;
    const subscriptionId = typeof invoiceWithSub.subscription === 'string' ? invoiceWithSub.subscription : invoiceWithSub.subscription?.id;

    if (subscriptionId) {
      // Get subscription details
      const subscription = await stripe.subscriptions.retrieve(subscriptionId);
      const userId = subscription.metadata?.user_id;

      if (userId) {
        // Send payment failure notification
        const userEmail = subscription.metadata?.user_email;
        if (userEmail) {
          await EmailHelpers.sendPaymentFailedEmail(userEmail, invoice.amount_due, invoice.currency);
        }

        // Log failed payment
        await logEvent('payment_failed', {
          user_id: userId,
          invoice_id: invoice.id,
          subscription_id: subscriptionId,
          amount: invoice.amount_due,
          currency: invoice.currency,
          attempt_count: invoice.attempt_count
        });

        // If this is the final attempt, handle subscription suspension
        if (invoice.attempt_count >= 4) {
          const userEmail = subscription.metadata?.user_email;
          const tenantId = subscription.metadata?.tenant_id;
          await handleSubscriptionSuspension(userId, subscriptionId, userEmail, tenantId);
        }
      }
    }

    console.log(`Invoice payment failed: ${invoice.id}`);
  } catch (error) {
    console.error('Error handling invoice payment failed:', error);
  }
}

// Handle customer creation
async function handleCustomerCreated(customer: Stripe.Customer, timer: any) {
  console.log('Processing customer created:', customer.id);

  try {
    const userId = customer.metadata?.user_id;

    if (userId) {
      // Update user record with customer ID via backend API
      try {
        await apiClient.updateCustomerInfo({
          user_id: userId,
          tenant_id: customer.metadata?.tenant_id || userId,
          stripe_customer_id: customer.id,
          email: customer.email || undefined,
          name: customer.name || undefined
        });
      } catch (error) {
        console.error('Error updating customer in database:', error);
      }

      // Log customer creation
      await logEvent('customer_created', {
        user_id: userId,
        customer_id: customer.id,
        email: customer.email
      });
    }

    console.log(`Customer created: ${customer.id}`);
  } catch (error) {
    console.error('Error handling customer created:', error);
  }
}

// Handle customer updates
async function handleCustomerUpdated(customer: Stripe.Customer, timer: any) {
  console.log('Processing customer updated:', customer.id);

  try {
    const userId = customer.metadata?.user_id;

    if (userId) {
      // Update user record with customer changes via backend API
      try {
        await apiClient.updateCustomerInfo({
          user_id: userId,
          tenant_id: customer.metadata?.tenant_id || userId,
          stripe_customer_id: customer.id,
          email: customer.email || undefined,
          name: customer.name || undefined
        });
      } catch (error) {
        console.error('Error updating customer in database:', error);
      }

      // Log customer update
      await logEvent('customer_updated', {
        user_id: userId,
        customer_id: customer.id,
        email: customer.email
      });
    }

    console.log(`Customer updated: ${customer.id}`);
  } catch (error) {
    console.error('Error handling customer updated:', error);
  }
}

// Handle trial ending soon
async function handleTrialWillEnd(subscription: Stripe.Subscription, timer: any) {
  console.log('Processing trial will end:', subscription.id);

  try {
    const userId = subscription.metadata?.user_id;

    if (userId && subscription.trial_end) {
      // Send trial ending notification
      const userEmail = subscription.metadata?.user_email;
      const daysLeft = Math.ceil((subscription.trial_end * 1000 - Date.now()) / (1000 * 60 * 60 * 24));

      if (userEmail && daysLeft > 0) {
        await EmailHelpers.sendTrialEndingEmail(userEmail, daysLeft);
      }

      // Log trial ending notification
      await logEvent('trial_ending', {
        user_id: userId,
        subscription_id: subscription.id,
        trial_end: subscription.trial_end
      });
    }

    console.log(`Trial ending notification sent for subscription: ${subscription.id}`);
  } catch (error) {
    console.error('Error handling trial will end:', error);
  }
}

// Handle subscription suspension due to failed payments
async function handleSubscriptionSuspension(userId: string, subscriptionId: string, userEmail?: string, tenantId?: string) {
  try {
    // Suspend user access via backend API
    try {
      await apiClient.suspendUserAccess({
        user_id: userId,
        tenant_id: tenantId || userId,
        reason: 'payment_failure'
      });
    } catch (error) {
      console.error('Error suspending user access:', error);
    }

    // Send suspension notification
    if (userEmail) {
      await EmailHelpers.sendAccountSuspendedEmail(userEmail, 'Multiple payment failures');
    }

    // Log suspension
    await logEvent('account_suspended', {
      user_id: userId,
      subscription_id: subscriptionId,
      reason: 'payment_failure'
    });

    console.log(`Account suspended for user: ${userId}`);
  } catch (error) {
    console.error('Error handling subscription suspension:', error);
  }
}

// Event logging helper with structured logging
async function logEvent(eventType: string, data: Record<string, any>) {
  try {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event_type: eventType,
      service: 'stripe-webhooks',
      environment: process.env.NODE_ENV || 'development',
      ...data
    };

    // Console logging with structured format
    console.log(JSON.stringify(logEntry));

    // TODO: Future enhancements:
    // 1. Send to Grafana Loki via HTTP API
    // 2. Send to CloudWatch Logs
    // 3. Send to backend API for database logging
    // 4. Send to external analytics service

    // Example backend API logging:
    // await apiClient.logEvent(logEntry)

  } catch (error) {
    console.error('Error logging event:', error);
  }
}
