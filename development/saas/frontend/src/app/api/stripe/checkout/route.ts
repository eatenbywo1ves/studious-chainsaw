import { NextRequest, NextResponse } from 'next/server'
import { stripe } from '../config/route'

// POST /api/stripe/checkout - Create checkout session
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { priceId, planCode, successUrl, cancelUrl, customerEmail, metadata = {} } = body

    // Validate required fields
    if (!priceId || !planCode) {
      return NextResponse.json(
        { error: 'Price ID and plan code are required' },
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

    // TODO: Verify JWT token and get user info
    // const token = authHeader.substring(7)
    // const user = await verifyJWT(token)

    // For now, we'll use mock user data
    const mockUser = {
      id: 'user_123',
      email: customerEmail || 'test@example.com',
      name: 'Test User',
    }

    // Create or retrieve customer
    let customer
    try {
      // Try to find existing customer by email
      const customers = await stripe.customers.list({
        email: mockUser.email,
        limit: 1,
      })

      if (customers.data.length > 0) {
        customer = customers.data[0]
      } else {
        // Create new customer
        customer = await stripe.customers.create({
          email: mockUser.email,
          name: mockUser.name,
          metadata: {
            user_id: mockUser.id,
          },
        })
      }
    } catch (error) {
      console.error('Error creating/retrieving customer:', error)
      return NextResponse.json(
        { error: 'Failed to create customer' },
        { status: 500 }
      )
    }

    // Create checkout session
    const session = await stripe.checkout.sessions.create({
      customer: customer.id,
      payment_method_types: ['card'],
      line_items: [
        {
          price: priceId,
          quantity: 1,
        },
      ],
      mode: planCode === 'free' ? 'payment' : 'subscription',
      success_url: successUrl || `${request.nextUrl.origin}/dashboard?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: cancelUrl || `${request.nextUrl.origin}/register?cancelled=true`,
      metadata: {
        user_id: mockUser.id,
        plan_code: planCode,
        ...metadata,
      },
      allow_promotion_codes: true,
      billing_address_collection: 'required',
      tax_id_collection: {
        enabled: true,
      },
      // For subscriptions, set up billing
      ...(planCode !== 'free' && {
        subscription_data: {
          metadata: {
            user_id: mockUser.id,
            plan_code: planCode,
          },
          trial_period_days: planCode === 'starter' ? 14 : planCode === 'professional' ? 7 : undefined,
        },
      }),
    })

    return NextResponse.json({
      sessionId: session.id,
      url: session.url,
      customer: {
        id: customer.id,
        email: customer.email,
      },
    })
  } catch (error) {
    console.error('Error creating checkout session:', error)
    return NextResponse.json(
      { error: 'Failed to create checkout session' },
      { status: 500 }
    )
  }
}

// GET /api/stripe/checkout - Retrieve checkout session
export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams
    const sessionId = searchParams.get('session_id')

    if (!sessionId) {
      return NextResponse.json(
        { error: 'Session ID is required' },
        { status: 400 }
      )
    }

    // Retrieve the checkout session
    const session = await stripe.checkout.sessions.retrieve(sessionId, {
      expand: ['customer', 'subscription', 'payment_intent'],
    })

    // Return session details
    return NextResponse.json({
      session: {
        id: session.id,
        status: session.status,
        payment_status: session.payment_status,
        customer_email: session.customer_details?.email,
        amount_total: session.amount_total,
        currency: session.currency,
        metadata: session.metadata,
        subscription: session.subscription ? {
          id: session.subscription,
          status: typeof session.subscription === 'object' ? session.subscription.status : 'active',
        } : null,
      },
    })
  } catch (error) {
    console.error('Error retrieving checkout session:', error)
    return NextResponse.json(
      { error: 'Failed to retrieve checkout session' },
      { status: 500 }
    )
  }
}