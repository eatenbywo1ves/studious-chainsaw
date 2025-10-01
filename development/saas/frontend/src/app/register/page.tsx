'use client'

import { useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Cpu, Loader2, Check } from 'lucide-react'

export default function RegisterPage() {
  const router = useRouter()
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [formData, setFormData] = useState({
    company_name: '',
    email: '',
    password: '',
    confirmPassword: '',
    first_name: '',
    last_name: '',
    plan_code: 'free'
  })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError(null)

    // Validate passwords match
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match')
      setIsLoading(false)
      return
    }

    // Validate password strength
    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters')
      setIsLoading(false)
      return
    }

    try {
      const { confirmPassword, ...submitData } = formData

      // For free plan, register directly
      if (formData.plan_code === 'free') {
        const response = await fetch('/api/tenants/register', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(submitData),
        })

        if (!response.ok) {
          const data = await response.json()
          throw new Error(data.message || 'Registration failed')
        }

        const data = await response.json()

        // Automatically log in after successful registration
        localStorage.setItem('token', data.access_token)

        // Redirect to dashboard
        router.push('/dashboard')
      } else {
        // For paid plans, first register the user, then redirect to Stripe checkout
        const response = await fetch('/api/tenants/register', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ ...submitData, plan_code: 'free' }), // Register as free first
        })

        if (!response.ok) {
          const data = await response.json()
          throw new Error(data.message || 'Registration failed')
        }

        const data = await response.json()
        localStorage.setItem('token', data.access_token)

        // Get plan price ID and redirect to Stripe checkout
        const planPriceIds: Record<string, string> = {
          starter: 'price_starter_monthly',
          professional: 'price_professional_monthly',
          enterprise: 'price_enterprise_monthly',
        }

        const priceId = planPriceIds[formData.plan_code]
        if (priceId) {
          // Import Stripe utilities dynamically
          const { StripeAPI } = await import('@/lib/stripe')

          try {
            const checkoutData = await StripeAPI.createCheckoutSession({
              priceId,
              planCode: formData.plan_code,
              customerEmail: formData.email,
              successUrl: `${window.location.origin}/dashboard?welcome=true`,
              cancelUrl: `${window.location.origin}/register?cancelled=true`,
              metadata: {
                user_id: data.user_id,
                plan_code: formData.plan_code,
              },
            })

            // Redirect to Stripe checkout
            window.location.href = checkoutData.url
          } catch (stripeError) {
            console.error('Stripe checkout error:', stripeError)
            setError('Failed to initialize payment. Please try again.')
          }
        } else {
          setError('Invalid plan selected')
        }
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setIsLoading(false)
    }
  }

  const plans = [
    { value: 'free', label: 'Free - $0/month', features: '100 API calls/month' },
    { value: 'starter', label: 'Starter - $29/month', features: '1,000 API calls/month' },
    { value: 'professional', label: 'Professional - $99/month', features: '10,000 API calls/month' },
    { value: 'enterprise', label: 'Enterprise - Custom', features: 'Unlimited API calls' }
  ]

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 p-4">
      <Card className="w-full max-w-2xl">
        <CardHeader className="space-y-1">
          <div className="flex items-center justify-center mb-4">
            <Cpu className="h-8 w-8 text-primary" />
          </div>
          <CardTitle className="text-2xl text-center">Create your account</CardTitle>
          <CardDescription className="text-center">
            Start your journey with Catalytic Computing
          </CardDescription>
        </CardHeader>
        <form onSubmit={handleSubmit}>
          <CardContent className="space-y-4">
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="first_name">First Name</Label>
                <Input
                  id="first_name"
                  type="text"
                  placeholder="John"
                  value={formData.first_name}
                  onChange={(e) => setFormData({ ...formData, first_name: e.target.value })}
                  required
                  disabled={isLoading}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="last_name">Last Name</Label>
                <Input
                  id="last_name"
                  type="text"
                  placeholder="Doe"
                  value={formData.last_name}
                  onChange={(e) => setFormData({ ...formData, last_name: e.target.value })}
                  required
                  disabled={isLoading}
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="company_name">Company Name</Label>
              <Input
                id="company_name"
                type="text"
                placeholder="Acme Corp"
                value={formData.company_name}
                onChange={(e) => setFormData({ ...formData, company_name: e.target.value })}
                required
                disabled={isLoading}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="john@example.com"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                required
                disabled={isLoading}
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="Min 8 characters"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  required
                  disabled={isLoading}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirmPassword">Confirm Password</Label>
                <Input
                  id="confirmPassword"
                  type="password"
                  placeholder="Repeat password"
                  value={formData.confirmPassword}
                  onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                  required
                  disabled={isLoading}
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="plan">Subscription Plan</Label>
              <Select
                value={formData.plan_code}
                onValueChange={(value) => setFormData({ ...formData, plan_code: value })}
                disabled={isLoading}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select a plan" />
                </SelectTrigger>
                <SelectContent>
                  {plans.map((plan) => (
                    <SelectItem key={plan.value} value={plan.value}>
                      <div>
                        <div className="font-medium">{plan.label}</div>
                        <div className="text-sm text-muted-foreground">{plan.features}</div>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {formData.plan_code === 'free' && (
              <Alert>
                <Check className="h-4 w-4" />
                <AlertDescription>
                  Start with our free tier and upgrade anytime!
                </AlertDescription>
              </Alert>
            )}
          </CardContent>
          <CardFooter className="flex flex-col space-y-4">
            <Button
              type="submit"
              className="w-full"
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Creating account...
                </>
              ) : (
                'Create account'
              )}
            </Button>
            <p className="text-sm text-center text-muted-foreground">
              Already have an account?{' '}
              <Link href="/login" className="text-primary hover:underline">
                Sign in
              </Link>
            </p>
            <p className="text-xs text-center text-muted-foreground">
              By creating an account, you agree to our{' '}
              <Link href="/terms" className="underline">Terms of Service</Link>
              {' '}and{' '}
              <Link href="/privacy" className="underline">Privacy Policy</Link>
            </p>
          </CardFooter>
        </form>
      </Card>
    </div>
  )
}