import { NextRequest, NextResponse } from 'next/server'
import Stripe from 'stripe'

// Initialize Stripe with secret key
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2024-06-20',
})

// Stripe configuration
export const stripeConfig = {
  publishableKey: process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!,
  secretKey: process.env.STRIPE_SECRET_KEY!,
  webhookSecret: process.env.STRIPE_WEBHOOK_SECRET!,

  // Product and price configurations
  products: {
    free: {
      priceId: process.env.STRIPE_FREE_PRICE_ID || 'price_free',
      features: ['100 API calls/month', 'Basic support', 'Standard compute lattices'],
    },
    starter: {
      priceId: process.env.STRIPE_STARTER_PRICE_ID || 'price_starter',
      features: ['1,000 API calls/month', 'Email support', 'Enhanced lattice management'],
    },
    professional: {
      priceId: process.env.STRIPE_PROFESSIONAL_PRICE_ID || 'price_professional',
      features: ['10,000 API calls/month', 'Priority support', 'Advanced analytics', 'Custom lattice configurations'],
    },
    enterprise: {
      priceId: process.env.STRIPE_ENTERPRISE_PRICE_ID || 'price_enterprise',
      features: ['Unlimited API calls', 'Dedicated support', 'White-label options', 'SLA guarantees'],
    },
  },

  // Webhook events we handle
  webhookEvents: [
    'checkout.session.completed',
    'customer.subscription.created',
    'customer.subscription.updated',
    'customer.subscription.deleted',
    'invoice.payment_succeeded',
    'invoice.payment_failed',
    'customer.created',
    'customer.updated',
  ],
}

// GET /api/stripe/config - Get Stripe public configuration
export async function GET(request: NextRequest) {
  try {
    // Return public configuration (no secrets)
    const publicConfig = {
      publishableKey: stripeConfig.publishableKey,
      products: Object.entries(stripeConfig.products).map(([key, value]) => ({
        planCode: key,
        priceId: value.priceId,
        features: value.features,
      })),
    }

    return NextResponse.json(publicConfig)
  } catch (error) {
    console.error('Error getting Stripe config:', error)
    return NextResponse.json(
      { error: 'Failed to get Stripe configuration' },
      { status: 500 }
    )
  }
}

// POST /api/stripe/config - Update Stripe configuration (admin only)
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { action, ...data } = body

    // Verify admin authorization
    const authHeader = request.headers.get('authorization')
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    // TODO: Verify JWT token and admin role
    // const token = authHeader.substring(7)
    // const user = await verifyJWT(token)
    // if (user.role !== 'admin') {
    //   return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    // }

    switch (action) {
      case 'create_product':
        // Create a new product in Stripe
        const product = await stripe.products.create({
          name: data.name,
          description: data.description,
          metadata: {
            plan_code: data.planCode,
          },
        })

        // Create corresponding price
        const price = await stripe.prices.create({
          product: product.id,
          unit_amount: data.amount, // Amount in cents
          currency: data.currency || 'usd',
          recurring: data.recurring ? {
            interval: data.interval || 'month',
          } : undefined,
        })

        return NextResponse.json({
          product,
          price,
          message: 'Product and price created successfully',
        })

      case 'update_product':
        // Update existing product
        const updatedProduct = await stripe.products.update(data.productId, {
          name: data.name,
          description: data.description,
          metadata: data.metadata,
        })

        return NextResponse.json({
          product: updatedProduct,
          message: 'Product updated successfully',
        })

      case 'create_coupon':
        // Create a coupon
        const coupon = await stripe.coupons.create({
          percent_off: data.percentOff,
          duration: data.duration,
          duration_in_months: data.durationInMonths,
          max_redemptions: data.maxRedemptions,
          metadata: data.metadata,
        })

        return NextResponse.json({
          coupon,
          message: 'Coupon created successfully',
        })

      default:
        return NextResponse.json(
          { error: 'Invalid action' },
          { status: 400 }
        )
    }
  } catch (error) {
    console.error('Error updating Stripe config:', error)
    return NextResponse.json(
      { error: 'Failed to update Stripe configuration' },
      { status: 500 }
    )
  }
}

export { stripe }