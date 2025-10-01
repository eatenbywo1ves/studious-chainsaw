import { NextRequest, NextResponse } from 'next/server'
import { stripe } from '../config/route'

// GET /api/stripe/subscriptions - Get user's subscriptions
export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const customerId = searchParams.get('customer_id')
    const userId = searchParams.get('user_id')

    // Verify authorization
    const authHeader = request.headers.get('authorization')
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    // TODO: Verify JWT token and get user info
    // const token = authHeader.substring(7)
    // const user = await verifyJWT(token)

    let subscriptions

    if (customerId) {
      // Get subscriptions by customer ID
      subscriptions = await stripe.subscriptions.list({
        customer: customerId,
        status: 'all',
        expand: ['data.default_payment_method', 'data.customer'],
      })
    } else if (userId) {
      // Find customer by user ID and get subscriptions
      const customers = await stripe.customers.list({
        metadata: { user_id: userId },
        limit: 1,
      })

      if (customers.data.length === 0) {
        return NextResponse.json({
          subscriptions: [],
          message: 'No customer found for user',
        })
      }

      subscriptions = await stripe.subscriptions.list({
        customer: customers.data[0].id,
        status: 'all',
        expand: ['data.default_payment_method', 'data.customer'],
      })
    } else {
      return NextResponse.json(
        { error: 'Customer ID or User ID is required' },
        { status: 400 }
      )
    }

    // Format subscription data
    const formattedSubscriptions = subscriptions.data.map(sub => ({
      id: sub.id,
      status: sub.status,
      current_period_start: sub.current_period_start,
      current_period_end: sub.current_period_end,
      cancel_at_period_end: sub.cancel_at_period_end,
      canceled_at: sub.canceled_at,
      trial_start: sub.trial_start,
      trial_end: sub.trial_end,
      metadata: sub.metadata,
      items: sub.items.data.map(item => ({
        id: item.id,
        price: {
          id: item.price.id,
          unit_amount: item.price.unit_amount,
          currency: item.price.currency,
          recurring: item.price.recurring,
        },
        quantity: item.quantity,
      })),
      customer: typeof sub.customer === 'object' ? {
        id: sub.customer.id,
        email: sub.customer.email,
        name: sub.customer.name,
      } : { id: sub.customer },
      default_payment_method: sub.default_payment_method ? {
        type: typeof sub.default_payment_method === 'object' ? sub.default_payment_method.type : 'unknown',
      } : null,
    }))

    return NextResponse.json({
      subscriptions: formattedSubscriptions,
      total: subscriptions.data.length,
    })
  } catch (error) {
    console.error('Error fetching subscriptions:', error)
    return NextResponse.json(
      { error: 'Failed to fetch subscriptions' },
      { status: 500 }
    )
  }
}

// POST /api/stripe/subscriptions - Create or modify subscription
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { action, subscriptionId, customerId, priceId, metadata = {} } = body

    // Verify authorization
    const authHeader = request.headers.get('authorization')
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    switch (action) {
      case 'create':
        if (!customerId || !priceId) {
          return NextResponse.json(
            { error: 'Customer ID and Price ID are required' },
            { status: 400 }
          )
        }

        const newSubscription = await stripe.subscriptions.create({
          customer: customerId,
          items: [{ price: priceId }],
          metadata,
          trial_period_days: metadata.trial_days ? parseInt(metadata.trial_days) : undefined,
          expand: ['default_payment_method', 'customer'],
        })

        return NextResponse.json({
          subscription: newSubscription,
          message: 'Subscription created successfully',
        })

      case 'update':
        if (!subscriptionId) {
          return NextResponse.json(
            { error: 'Subscription ID is required' },
            { status: 400 }
          )
        }

        const updatedSubscription = await stripe.subscriptions.update(subscriptionId, {
          items: priceId ? [{ price: priceId }] : undefined,
          metadata,
          proration_behavior: 'create_prorations',
        })

        return NextResponse.json({
          subscription: updatedSubscription,
          message: 'Subscription updated successfully',
        })

      case 'cancel':
        if (!subscriptionId) {
          return NextResponse.json(
            { error: 'Subscription ID is required' },
            { status: 400 }
          )
        }

        const canceledSubscription = await stripe.subscriptions.update(subscriptionId, {
          cancel_at_period_end: true,
        })

        return NextResponse.json({
          subscription: canceledSubscription,
          message: 'Subscription will be canceled at period end',
        })

      case 'reactivate':
        if (!subscriptionId) {
          return NextResponse.json(
            { error: 'Subscription ID is required' },
            { status: 400 }
          )
        }

        const reactivatedSubscription = await stripe.subscriptions.update(subscriptionId, {
          cancel_at_period_end: false,
        })

        return NextResponse.json({
          subscription: reactivatedSubscription,
          message: 'Subscription reactivated successfully',
        })

      case 'cancel_immediately':
        if (!subscriptionId) {
          return NextResponse.json(
            { error: 'Subscription ID is required' },
            { status: 400 }
          )
        }

        const canceledImmediately = await stripe.subscriptions.cancel(subscriptionId)

        return NextResponse.json({
          subscription: canceledImmediately,
          message: 'Subscription canceled immediately',
        })

      default:
        return NextResponse.json(
          { error: 'Invalid action' },
          { status: 400 }
        )
    }
  } catch (error) {
    console.error('Error managing subscription:', error)
    return NextResponse.json(
      { error: 'Failed to manage subscription' },
      { status: 500 }
    )
  }
}

// DELETE /api/stripe/subscriptions - Cancel subscription
export async function DELETE(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const subscriptionId = searchParams.get('subscription_id')

    if (!subscriptionId) {
      return NextResponse.json(
        { error: 'Subscription ID is required' },
        { status: 400 }
      )
    }

    // Verify authorization
    const authHeader = request.headers.get('authorization')
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    // Cancel subscription immediately
    const canceledSubscription = await stripe.subscriptions.cancel(subscriptionId)

    return NextResponse.json({
      subscription: canceledSubscription,
      message: 'Subscription canceled successfully',
    })
  } catch (error) {
    console.error('Error canceling subscription:', error)
    return NextResponse.json(
      { error: 'Failed to cancel subscription' },
      { status: 500 }
    )
  }
}