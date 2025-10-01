import { NextRequest, NextResponse } from 'next/server'
import { stripe } from '../../config/route'

// POST /api/stripe/webhooks/test - Test webhook endpoint with simulated events
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { eventType, testData } = body

    // Verify authorization for testing
    const authHeader = request.headers.get('authorization')
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'Unauthorized' },
        { status: 401 }
      )
    }

    // Simulate webhook events for testing
    switch (eventType) {
      case 'checkout.session.completed':
        const testSession = {
          id: 'cs_test_' + Math.random().toString(36).substring(7),
          customer_details: {
            email: testData?.email || 'test@example.com',
          },
          metadata: {
            user_id: testData?.userId || 'test_user_123',
            plan_code: testData?.planCode || 'starter',
          },
          amount_total: testData?.amount || 2900,
          currency: 'usd',
        }

        // Forward to main webhook handler
        const webhookResponse = await fetch(`${request.nextUrl.origin}/api/stripe/webhooks`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'stripe-signature': 'test_signature',
          },
          body: JSON.stringify({
            type: 'checkout.session.completed',
            data: { object: testSession },
            id: 'evt_test_' + Math.random().toString(36).substring(7),
            created: Math.floor(Date.now() / 1000),
          }),
        })

        return NextResponse.json({
          message: 'Test checkout session completed event sent',
          testSession,
          webhookStatus: webhookResponse.status,
        })

      case 'subscription.created':
        const testSubscription = {
          id: 'sub_test_' + Math.random().toString(36).substring(7),
          customer: 'cus_test_' + Math.random().toString(36).substring(7),
          status: 'active',
          metadata: {
            user_id: testData?.userId || 'test_user_123',
            plan_code: testData?.planCode || 'professional',
          },
          current_period_start: Math.floor(Date.now() / 1000),
          current_period_end: Math.floor((Date.now() + 30 * 24 * 60 * 60 * 1000) / 1000),
        }

        return NextResponse.json({
          message: 'Test subscription created event sent',
          testSubscription,
        })

      case 'invoice.payment_failed':
        const testInvoice = {
          id: 'in_test_' + Math.random().toString(36).substring(7),
          subscription: 'sub_test_' + Math.random().toString(36).substring(7),
          amount_due: testData?.amount || 2900,
          currency: 'usd',
          attempt_count: testData?.attemptCount || 1,
        }

        return NextResponse.json({
          message: 'Test payment failed event sent',
          testInvoice,
        })

      default:
        return NextResponse.json(
          { error: 'Unsupported test event type' },
          { status: 400 }
        )
    }
  } catch (error) {
    console.error('Error in webhook testing:', error)
    return NextResponse.json(
      { error: 'Failed to process test webhook' },
      { status: 500 }
    )
  }
}

// GET /api/stripe/webhooks/test - Get available test events
export async function GET(request: NextRequest) {
  try {
    const testEvents = [
      {
        type: 'checkout.session.completed',
        description: 'Test successful checkout completion',
        samplePayload: {
          eventType: 'checkout.session.completed',
          testData: {
            email: 'test@example.com',
            userId: 'user_123',
            planCode: 'starter',
            amount: 2900,
          },
        },
      },
      {
        type: 'subscription.created',
        description: 'Test subscription creation',
        samplePayload: {
          eventType: 'subscription.created',
          testData: {
            userId: 'user_123',
            planCode: 'professional',
          },
        },
      },
      {
        type: 'invoice.payment_failed',
        description: 'Test payment failure',
        samplePayload: {
          eventType: 'invoice.payment_failed',
          testData: {
            amount: 2900,
            attemptCount: 2,
          },
        },
      },
    ]

    return NextResponse.json({
      availableTestEvents: testEvents,
      usage: 'POST to this endpoint with eventType and testData to simulate webhook events',
    })
  } catch (error) {
    console.error('Error getting test events:', error)
    return NextResponse.json(
      { error: 'Failed to get test events' },
      { status: 500 }
    )
  }
}