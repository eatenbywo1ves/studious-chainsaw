// API Client for calling backend services
// Handles communication between Next.js frontend and Python FastAPI backend

interface ApiClientConfig {
  baseUrl: string
  timeout?: number
}

export class ApiClient {
  private baseUrl: string;
  private timeout: number;

  constructor(config?: Partial<ApiClientConfig>) {
    this.baseUrl = config?.baseUrl || process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    this.timeout = config?.timeout || 10000; // 10 second default timeout
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        }
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(error.detail || `HTTP ${response.status}: ${response.statusText}`);
      }

      return response.json();
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          throw new Error(`Request timeout after ${this.timeout}ms`);
        }
        throw error;
      }
      throw new Error('Unknown error occurred');
    }
  }

  // Subscription endpoints
  async createSubscription(data: {
    user_id: string
    tenant_id: string
    stripe_subscription_id: string
    stripe_customer_id: string
    plan_code: string
    status: string
    current_period_start: Date
    current_period_end: Date
    trial_start?: Date
    trial_end?: Date
    metadata?: Record<string, any>
  }) {
    return this.request('/api/subscriptions/create', {
      method: 'POST',
      body: JSON.stringify({
        ...data,
        current_period_start: data.current_period_start.toISOString(),
        current_period_end: data.current_period_end.toISOString(),
        trial_start: data.trial_start?.toISOString(),
        trial_end: data.trial_end?.toISOString()
      })
    });
  }

  async updateSubscription(data: {
    stripe_subscription_id: string
    status?: string
    current_period_start?: Date
    current_period_end?: Date
    cancel_at_period_end?: boolean
    canceled_at?: Date
    metadata?: Record<string, any>
  }) {
    return this.request('/api/subscriptions/update', {
      method: 'PUT',
      body: JSON.stringify({
        ...data,
        current_period_start: data.current_period_start?.toISOString(),
        current_period_end: data.current_period_end?.toISOString(),
        canceled_at: data.canceled_at?.toISOString()
      })
    });
  }

  async cancelSubscription(userId: string, tenantId: string) {
    return this.request(`/api/subscriptions/cancel?user_id=${userId}&tenant_id=${tenantId}`, {
      method: 'DELETE'
    });
  }

  async updateCustomerInfo(data: {
    user_id: string
    tenant_id: string
    stripe_customer_id: string
    email?: string
    name?: string
  }) {
    return this.request('/api/subscriptions/update-customer', {
      method: 'PUT',
      body: JSON.stringify(data)
    });
  }

  async suspendUserAccess(data: {
    user_id: string
    tenant_id: string
    reason: string
  }) {
    return this.request('/api/subscriptions/suspend', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }

  async getSubscriptionStatus(tenantId: string) {
    return this.request(`/api/subscriptions/status/${tenantId}`, {
      method: 'GET'
    });
  }
}

// Singleton instance
export const apiClient = new ApiClient();
