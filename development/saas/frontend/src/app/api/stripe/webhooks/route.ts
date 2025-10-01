import { NextRequest, NextResponse } from 'next/server'
import { headers } from 'next/headers'
import { stripe } from '../config/route'
import { createWebhookTimer } from '@/lib/webhook-logger'
import Stripe from 'stripe'

// Disable body parsing for webhooks
export const dynamic = 'force-dynamic'

// POST /api/stripe/webhooks - Handle Stripe webhook events
export async function POST(request: NextRequest) {
  try {
    const body = await request.text()
    const signature = headers().get('stripe-signature')

    if (!signature) {
      console.error('No stripe-signature header found')
      return NextResponse.json(
        { error: 'No signature provided' },
        { status: 400 }
      )
    }

    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET
    if (!webhookSecret) {
      console.error('No webhook secret configured')
      return NextResponse.json(
        { error: 'Webhook secret not configured' },
        { status: 500 }
      )
    }

    let event: Stripe.Event

    try {
      event = stripe.webhooks.constructEvent(body, signature, webhookSecret)
    } catch (err) {
      console.error('Webhook signature verification failed:', err)
      return NextResponse.json(
        { error: 'Invalid signature' },
        { status: 400 }
      )
    }

    console.log(`Received webhook event: ${event.type}`)

    // Create timing logger for this event
    const timer = createWebhookTimer(event.type, event.id)

    try {
      // Handle different event types
      switch (event.type) {
        case 'checkout.session.completed':
          await handleCheckoutSessionCompleted(event.data.object as Stripe.Checkout.Session, timer)
          break

        case 'customer.subscription.created':
          await handleSubscriptionCreated(event.data.object as Stripe.Subscription, timer)
          break

        case 'customer.subscription.updated':
          await handleSubscriptionUpdated(event.data.object as Stripe.Subscription, timer)
          break

        case 'customer.subscription.deleted':
          await handleSubscriptionDeleted(event.data.object as Stripe.Subscription, timer)
          break

        case 'invoice.payment_succeeded':
          await handleInvoicePaymentSucceeded(event.data.object as Stripe.Invoice, timer)
          break

        case 'invoice.payment_failed':
          await handleInvoicePaymentFailed(event.data.object as Stripe.Invoice, timer)
          break

        case 'customer.created':
          await handleCustomerCreated(event.data.object as Stripe.Customer, timer)
          break

        case 'customer.updated':
          await handleCustomerUpdated(event.data.object as Stripe.Customer, timer)
          break

        case 'customer.subscription.trial_will_end':
          await handleTrialWillEnd(event.data.object as Stripe.Subscription, timer)
          break

        default:
          console.log(`Unhandled event type: ${event.type}`)
          timer.success({ metadata: { unhandled: true } })
      }

      // Log successful processing if no specific timer.success() was called
      timer.success()
      return NextResponse.json({ received: true })
    } catch (handlerError) {
      timer.error(handlerError instanceof Error ? handlerError.message : 'Handler failed')
      throw handlerError
    }
  } catch (error) {
    console.error('Webhook processing error:', error)
    return NextResponse.json(
      { error: 'Webhook processing failed' },
      { status: 500 }
    )
  }
}

// Handle successful checkout session
async function handleCheckoutSessionCompleted(session: Stripe.Checkout.Session, timer: any) {
  console.log('Processing checkout session completed:', session.id)

  try {
    const userId = session.metadata?.user_id
    const planCode = session.metadata?.plan_code

    if (!userId) {
      console.error('No user_id in session metadata')
      return
    }

    // Update user's plan in database
    // TODO: Implement database update
    // await updateUserPlan(userId, planCode)

    // Send welcome email for paid plans
    if (planCode && planCode !== 'free') {
      await sendWelcomeEmail(session.customer_details?.email || '', planCode)
    }

    // Log successful checkout
    await logEvent('checkout_completed', {
      user_id: userId,
      plan_code: planCode,
      session_id: session.id,
      amount: session.amount_total,
      currency: session.currency,
    })

    timer.success({
      user_id: userId,
      customer_id: session.customer as string,
      metadata: { plan_code: planCode, amount: session.amount_total }
    })
    console.log(`Checkout completed for user ${userId}, plan: ${planCode}`)
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    timer.error(errorMessage, { user_id: userId })
    console.error('Error handling checkout session completed:', error)
    throw error
  }
}

// Handle subscription creation
async function handleSubscriptionCreated(subscription: Stripe.Subscription, timer: any) {
  console.log('Processing subscription created:', subscription.id)

  try {
    const userId = subscription.metadata?.user_id
    const planCode = subscription.metadata?.plan_code

    if (!userId) {
      console.error('No user_id in subscription metadata')
      return
    }

    // Update user's subscription in database
    // TODO: Implement database update
    // await createUserSubscription({
    //   user_id: userId,
    //   subscription_id: subscription.id,
    //   customer_id: subscription.customer,
    //   plan_code: planCode,
    //   status: subscription.status,
    //   current_period_start: subscription.current_period_start,
    //   current_period_end: subscription.current_period_end,
    //   trial_start: subscription.trial_start,
    //   trial_end: subscription.trial_end,
    // })

    // Update user's plan limits
    // await updateUserLimits(userId, planCode)

    // Log subscription creation
    await logEvent('subscription_created', {
      user_id: userId,
      subscription_id: subscription.id,
      plan_code: planCode,
      status: subscription.status,
    })

    console.log(`Subscription created for user ${userId}: ${subscription.id}`)
  } catch (error) {
    console.error('Error handling subscription created:', error)
  }
}

// Handle subscription updates
async function handleSubscriptionUpdated(subscription: Stripe.Subscription) {
  console.log('Processing subscription updated:', subscription.id)

  try {
    const userId = subscription.metadata?.user_id

    if (!userId) {
      console.error('No user_id in subscription metadata')
      return
    }

    // Update subscription in database
    // TODO: Implement database update
    // await updateUserSubscription(subscription.id, {
    //   status: subscription.status,
    //   current_period_start: subscription.current_period_start,
    //   current_period_end: subscription.current_period_end,
    //   cancel_at_period_end: subscription.cancel_at_period_end,
    //   canceled_at: subscription.canceled_at,
    // })

    // Handle plan changes
    if (subscription.items.data.length > 0) {
      const priceId = subscription.items.data[0].price.id
      // TODO: Map price ID to plan code and update user limits
      // const planCode = await getPlanCodeFromPriceId(priceId)
      // await updateUserLimits(userId, planCode)
    }

    // Handle cancellation
    if (subscription.cancel_at_period_end) {
      await sendCancellationEmail(userId, subscription.current_period_end)
    }

    // Log subscription update
    await logEvent('subscription_updated', {
      user_id: userId,
      subscription_id: subscription.id,
      status: subscription.status,
      cancel_at_period_end: subscription.cancel_at_period_end,
    })

    console.log(`Subscription updated for user ${userId}: ${subscription.id}`)
  } catch (error) {
    console.error('Error handling subscription updated:', error)
  }
}

// Handle subscription deletion
async function handleSubscriptionDeleted(subscription: Stripe.Subscription) {
  console.log('Processing subscription deleted:', subscription.id)

  try {
    const userId = subscription.metadata?.user_id

    if (!userId) {
      console.error('No user_id in subscription metadata')
      return
    }

    // Downgrade user to free plan
    // TODO: Implement database update
    // await updateUserPlan(userId, 'free')
    // await updateUserLimits(userId, 'free')

    // Send subscription cancellation confirmation
    await sendSubscriptionCanceledEmail(userId)

    // Log subscription deletion
    await logEvent('subscription_deleted', {
      user_id: userId,
      subscription_id: subscription.id,
      canceled_at: subscription.canceled_at,
    })

    console.log(`Subscription deleted for user ${userId}: ${subscription.id}`)
  } catch (error) {
    console.error('Error handling subscription deleted:', error)
  }
}

// Handle successful invoice payment
async function handleInvoicePaymentSucceeded(invoice: Stripe.Invoice) {
  console.log('Processing invoice payment succeeded:', invoice.id)

  try {
    const subscriptionId = invoice.subscription as string

    if (subscriptionId) {
      // Get subscription details
      const subscription = await stripe.subscriptions.retrieve(subscriptionId)
      const userId = subscription.metadata?.user_id

      if (userId) {
        // Send payment confirmation email
        await sendPaymentSuccessEmail(userId, invoice.amount_paid, invoice.currency)

        // Log successful payment
        await logEvent('payment_succeeded', {
          user_id: userId,
          invoice_id: invoice.id,
          subscription_id: subscriptionId,
          amount: invoice.amount_paid,
          currency: invoice.currency,
        })
      }
    }

    console.log(`Invoice payment succeeded: ${invoice.id}`)
  } catch (error) {
    console.error('Error handling invoice payment succeeded:', error)
  }
}

// Handle failed invoice payment
async function handleInvoicePaymentFailed(invoice: Stripe.Invoice) {
  console.log('Processing invoice payment failed:', invoice.id)

  try {
    const subscriptionId = invoice.subscription as string

    if (subscriptionId) {
      // Get subscription details
      const subscription = await stripe.subscriptions.retrieve(subscriptionId)
      const userId = subscription.metadata?.user_id

      if (userId) {
        // Send payment failure notification
        await sendPaymentFailedEmail(userId, invoice.amount_due, invoice.currency)

        // Log failed payment
        await logEvent('payment_failed', {
          user_id: userId,
          invoice_id: invoice.id,
          subscription_id: subscriptionId,
          amount: invoice.amount_due,
          currency: invoice.currency,
          attempt_count: invoice.attempt_count,
        })

        // If this is the final attempt, handle subscription suspension
        if (invoice.attempt_count >= 4) {
          await handleSubscriptionSuspension(userId, subscriptionId)
        }
      }
    }

    console.log(`Invoice payment failed: ${invoice.id}`)
  } catch (error) {
    console.error('Error handling invoice payment failed:', error)
  }
}

// Handle customer creation
async function handleCustomerCreated(customer: Stripe.Customer) {
  console.log('Processing customer created:', customer.id)

  try {
    const userId = customer.metadata?.user_id

    if (userId) {
      // Update user record with customer ID
      // TODO: Implement database update
      // await updateUserCustomerId(userId, customer.id)

      // Log customer creation
      await logEvent('customer_created', {
        user_id: userId,
        customer_id: customer.id,
        email: customer.email,
      })
    }

    console.log(`Customer created: ${customer.id}`)
  } catch (error) {
    console.error('Error handling customer created:', error)
  }
}

// Handle customer updates
async function handleCustomerUpdated(customer: Stripe.Customer) {
  console.log('Processing customer updated:', customer.id)

  try {
    const userId = customer.metadata?.user_id

    if (userId) {
      // Update user record with customer changes
      // TODO: Implement database update
      // await updateUserCustomerInfo(userId, {
      //   email: customer.email,
      //   name: customer.name,
      //   phone: customer.phone,
      // })

      // Log customer update
      await logEvent('customer_updated', {
        user_id: userId,
        customer_id: customer.id,
        email: customer.email,
      })
    }

    console.log(`Customer updated: ${customer.id}`)
  } catch (error) {
    console.error('Error handling customer updated:', error)
  }
}

// Handle trial ending soon
async function handleTrialWillEnd(subscription: Stripe.Subscription) {
  console.log('Processing trial will end:', subscription.id)

  try {
    const userId = subscription.metadata?.user_id

    if (userId && subscription.trial_end) {
      // Send trial ending notification
      await sendTrialEndingEmail(userId, subscription.trial_end)

      // Log trial ending notification
      await logEvent('trial_ending', {
        user_id: userId,
        subscription_id: subscription.id,
        trial_end: subscription.trial_end,
      })
    }

    console.log(`Trial ending notification sent for subscription: ${subscription.id}`)
  } catch (error) {
    console.error('Error handling trial will end:', error)
  }
}

// Handle subscription suspension due to failed payments
async function handleSubscriptionSuspension(userId: string, subscriptionId: string) {
  try {
    // Suspend user access
    // TODO: Implement database update
    // await suspendUserAccess(userId)

    // Send suspension notification
    await sendAccountSuspendedEmail(userId)

    // Log suspension
    await logEvent('account_suspended', {
      user_id: userId,
      subscription_id: subscriptionId,
      reason: 'payment_failure',
    })

    console.log(`Account suspended for user: ${userId}`)
  } catch (error) {
    console.error('Error handling subscription suspension:', error)
  }
}

// Email helpers (placeholders for actual email service integration)
async function sendWelcomeEmail(email: string, planCode: string) {
  console.log(`Sending welcome email to ${email} for plan: ${planCode}`)
  // TODO: Implement with SendGrid/SES
}

async function sendCancellationEmail(userId: string, periodEnd: number) {
  console.log(`Sending cancellation email to user: ${userId}, period end: ${periodEnd}`)
  // TODO: Implement with SendGrid/SES
}

async function sendSubscriptionCanceledEmail(userId: string) {
  console.log(`Sending subscription canceled email to user: ${userId}`)
  // TODO: Implement with SendGrid/SES
}

async function sendPaymentSuccessEmail(userId: string, amount: number, currency: string) {
  console.log(`Sending payment success email to user: ${userId}, amount: ${amount} ${currency}`)
  // TODO: Implement with SendGrid/SES
}

async function sendPaymentFailedEmail(userId: string, amount: number, currency: string) {
  console.log(`Sending payment failed email to user: ${userId}, amount: ${amount} ${currency}`)
  // TODO: Implement with SendGrid/SES
}

async function sendTrialEndingEmail(userId: string, trialEnd: number) {
  console.log(`Sending trial ending email to user: ${userId}, trial end: ${trialEnd}`)
  // TODO: Implement with SendGrid/SES
}

async function sendAccountSuspendedEmail(userId: string) {
  console.log(`Sending account suspended email to user: ${userId}`)
  // TODO: Implement with SendGrid/SES
}

// Event logging helper
async function logEvent(eventType: string, data: Record<string, any>) {
  try {
    console.log(`Event: ${eventType}`, data)
    // TODO: Implement with actual logging service (e.g., Grafana Loki, CloudWatch)
    // await logger.info(eventType, data)
  } catch (error) {
    console.error('Error logging event:', error)
  }
}