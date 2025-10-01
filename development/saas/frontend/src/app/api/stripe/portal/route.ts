import { NextRequest, NextResponse } from 'next/server'
import { stripe } from '../config/route'

// POST /api/stripe/portal - Create billing portal session
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { customerId, returnUrl } = body

    // Validate required fields
    if (!customerId) {
      return NextResponse.json(
        { error: 'Customer ID is required' },
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

    // TODO: Verify JWT token and ensure user owns this customer
    // const token = authHeader.substring(7)
    // const user = await verifyJWT(token)

    // Create billing portal session
    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: returnUrl || `${request.nextUrl.origin}/dashboard`,
      configuration: {
        features: {
          payment_method_update: { enabled: true },
          invoice_history: { enabled: true },
          subscription_cancel: {
            enabled: true,
            mode: 'at_period_end',
            proration_behavior: 'create_prorations',
          },
          subscription_update: {
            enabled: true,
            default_allowed_updates: ['price', 'quantity', 'promotion_code'],
            proration_behavior: 'create_prorations',
          },
        },
        business_profile: {
          headline: 'Manage your Catalytic Computing subscription',
          privacy_policy_url: `${request.nextUrl.origin}/privacy`,
          terms_of_service_url: `${request.nextUrl.origin}/terms`,
        },
      },
    })

    return NextResponse.json({
      url: portalSession.url,
      sessionId: portalSession.id,
    })
  } catch (error) {
    console.error('Error creating billing portal session:', error)
    return NextResponse.json(
      { error: 'Failed to create billing portal session' },
      { status: 500 }
    )
  }
}

// GET /api/stripe/portal - Get portal configuration
export async function GET(request: NextRequest) {
  try {
    // Verify authorization
    const authHeader = request.headers.get('authorization')
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    // List portal configurations
    const configurations = await stripe.billingPortal.configurations.list({
      limit: 10,
    })

    return NextResponse.json({
      configurations: configurations.data.map(config => ({
        id: config.id,
        is_default: config.is_default,
        features: config.features,
        business_profile: config.business_profile,
      })),
    })
  } catch (error) {
    console.error('Error fetching portal configurations:', error)
    return NextResponse.json(
      { error: 'Failed to fetch portal configurations' },
      { status: 500 }
    )
  }
}