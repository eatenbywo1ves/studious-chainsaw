import { NextRequest, NextResponse } from 'next/server'
import { headers } from 'next/headers'

// Health check endpoint for the frontend service
export async function GET(request: NextRequest) {
  try {
    const startTime = Date.now()
    
    // Basic health checks
    const checks = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      version: process.env.APP_VERSION || '1.0.0',
      checks: {
        server: 'ok',
        memory: getMemoryUsage(),
        uptime: process.uptime(),
        database: await checkDatabaseConnection(),
        external_apis: await checkExternalAPIs()
      }
    }

    const responseTime = Date.now() - startTime
    checks.response_time_ms = responseTime

    // Determine overall health status
    const isHealthy = Object.values(checks.checks).every(check => 
      typeof check === 'string' ? check === 'ok' : check.status === 'ok'
    )

    const status = isHealthy ? 200 : 503
    checks.status = isHealthy ? 'healthy' : 'unhealthy'

    return NextResponse.json(checks, { status })

  } catch (error) {
    return NextResponse.json({
      status: 'error',
      timestamp: new Date().toISOString(),
      error: error instanceof Error ? error.message : 'Unknown error',
      checks: {
        server: 'error'
      }
    }, { status: 500 })
  }
}

function getMemoryUsage() {
  const usage = process.memoryUsage()
  return {
    status: 'ok',
    rss: Math.round(usage.rss / 1024 / 1024),
    heapTotal: Math.round(usage.heapTotal / 1024 / 1024),
    heapUsed: Math.round(usage.heapUsed / 1024 / 1024),
    external: Math.round(usage.external / 1024 / 1024)
  }
}

async function checkDatabaseConnection() {
  try {
    // This would typically check your database connection
    // For now, we'll check if DATABASE_URL is configured
    if (!process.env.DATABASE_URL) {
      return { status: 'warning', message: 'DATABASE_URL not configured' }
    }

    // In a real implementation, you'd test the actual connection
    return { status: 'ok', message: 'Database connection configured' }
  } catch (error) {
    return { 
      status: 'error', 
      message: error instanceof Error ? error.message : 'Database check failed' 
    }
  }
}

async function checkExternalAPIs() {
  const apis = []
  
  // Check Stripe API
  if (process.env.STRIPE_SECRET_KEY) {
    apis.push({ name: 'stripe', status: 'configured' })
  } else {
    apis.push({ name: 'stripe', status: 'not_configured' })
  }
  
  // Check SendGrid API  
  if (process.env.SENDGRID_API_KEY) {
    apis.push({ name: 'sendgrid', status: 'configured' })
  } else {
    apis.push({ name: 'sendgrid', status: 'not_configured' })
  }

  return {
    status: 'ok',
    apis
  }
}