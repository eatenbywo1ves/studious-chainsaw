/*
Load testing script for Catalytic Computing API using k6
*/

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const apiResponseTime = new Trend('api_response_time');

// Test configuration
export let options = {
  stages: [
    // Ramp-up
    { duration: '2m', target: 10 },   // 10 users for 2 minutes
    { duration: '5m', target: 50 },   // 50 users for 5 minutes  
    { duration: '10m', target: 100 }, // 100 users for 10 minutes
    { duration: '5m', target: 200 },  // 200 users for 5 minutes (stress test)
    
    // Ramp-down
    { duration: '5m', target: 100 },  // Back to 100 users
    { duration: '5m', target: 50 },   // Back to 50 users
    { duration: '2m', target: 0 },    // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<2000'], // 95% of requests must complete within 2s
    http_req_failed: ['rate<0.05'],    // Error rate must be less than 5%
    errors: ['rate<0.05'],             // Custom error rate less than 5%
  },
};

// Base URL configuration
const BASE_URL = __ENV.API_BASE_URL || 'http://localhost:8000';

// Test data
const testUsers = [
  { email: 'test1@example.com', name: 'Test User 1' },
  { email: 'test2@example.com', name: 'Test User 2' },
  { email: 'test3@example.com', name: 'Test User 3' },
];

// Helper function to generate random data
function getRandomUser() {
  return testUsers[Math.floor(Math.random() * testUsers.length)];
}

function getRandomString(length = 10) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Authentication helper
function authenticate() {
  const user = getRandomUser();
  const authPayload = {
    email: user.email,
    password: 'test_password_123'
  };
  
  const authResponse = http.post(`${BASE_URL}/api/auth/login`, JSON.stringify(authPayload), {
    headers: { 'Content-Type': 'application/json' },
  });
  
  if (authResponse.status === 200) {
    const token = JSON.parse(authResponse.body).access_token;
    return { 'Authorization': `Bearer ${token}` };
  }
  return {};
}

// Main test function
export default function() {
  // Health check test
  group('Health Checks', function() {
    const healthResponse = http.get(`${BASE_URL}/api/health`);
    check(healthResponse, {
      'health check status is 200': (r) => r.status === 200,
      'health check response time < 500ms': (r) => r.timings.duration < 500,
    });
    
    errorRate.add(healthResponse.status !== 200);
    apiResponseTime.add(healthResponse.timings.duration);
  });
  
  // API endpoint tests
  group('API Endpoints', function() {
    const headers = authenticate();
    
    // Test user profile endpoint
    const profileResponse = http.get(`${BASE_URL}/api/user/profile`, { headers });
    check(profileResponse, {
      'profile endpoint status is 200 or 401': (r) => [200, 401].includes(r.status),
      'profile response time < 1000ms': (r) => r.timings.duration < 1000,
    });
    
    errorRate.add(![200, 401].includes(profileResponse.status));
    apiResponseTime.add(profileResponse.timings.duration);
    
    // Test subscription endpoint
    const subscriptionResponse = http.get(`${BASE_URL}/api/subscription/status`, { headers });
    check(subscriptionResponse, {
      'subscription endpoint responds': (r) => r.status >= 200 && r.status < 500,
      'subscription response time < 1000ms': (r) => r.timings.duration < 1000,
    });
    
    errorRate.add(subscriptionResponse.status >= 500);
    apiResponseTime.add(subscriptionResponse.timings.duration);
  });
  
  // Database operations test
  group('Database Operations', function() {
    const headers = authenticate();
    
    // Create operation
    const createPayload = {
      name: `Test Item ${getRandomString(5)}`,
      description: `Description ${getRandomString(20)}`,
      type: 'test'
    };
    
    const createResponse = http.post(
      `${BASE_URL}/api/items/create`, 
      JSON.stringify(createPayload), 
      { headers: { ...headers, 'Content-Type': 'application/json' } }
    );
    
    check(createResponse, {
      'create operation succeeds': (r) => [200, 201, 401, 403].includes(r.status),
      'create response time < 2000ms': (r) => r.timings.duration < 2000,
    });
    
    errorRate.add(createResponse.status >= 500);
    apiResponseTime.add(createResponse.timings.duration);
    
    // Read operation
    const readResponse = http.get(`${BASE_URL}/api/items/list`, { headers });
    check(readResponse, {
      'read operation succeeds': (r) => [200, 401, 403].includes(r.status),
      'read response time < 1500ms': (r) => r.timings.duration < 1500,
    });
    
    errorRate.add(readResponse.status >= 500);
    apiResponseTime.add(readResponse.timings.duration);
  });
  
  // Stripe webhook simulation
  group('Webhook Endpoints', function() {
    const webhookPayload = {
      id: `evt_test_${getRandomString(10)}`,
      object: 'event',
      type: 'customer.subscription.created',
      data: {
        object: {
          id: `sub_${getRandomString(10)}`,
          customer: `cus_${getRandomString(10)}`,
          status: 'active'
        }
      }
    };
    
    const webhookResponse = http.post(
      `${BASE_URL}/api/stripe/webhooks/test`,
      JSON.stringify(webhookPayload),
      {
        headers: { 
          'Content-Type': 'application/json',
          'Stripe-Signature': 'test_signature'
        }
      }
    );
    
    check(webhookResponse, {
      'webhook processes correctly': (r) => [200, 400, 401].includes(r.status),
      'webhook response time < 3000ms': (r) => r.timings.duration < 3000,
    });
    
    errorRate.add(webhookResponse.status >= 500);
    apiResponseTime.add(webhookResponse.timings.duration);
  });
  
  // Email service test
  group('Email Service', function() {
    const headers = authenticate();
    
    const emailPayload = {
      to: 'test@example.com',
      template: 'test_template',
      data: {
        user_name: 'Load Test User',
        test_data: getRandomString(50)
      }
    };
    
    const emailResponse = http.post(
      `${BASE_URL}/api/email/send/test`,
      JSON.stringify(emailPayload),
      { headers: { ...headers, 'Content-Type': 'application/json' } }
    );
    
    check(emailResponse, {
      'email service responds': (r) => r.status < 500,
      'email response time < 5000ms': (r) => r.timings.duration < 5000,
    });
    
    errorRate.add(emailResponse.status >= 500);
    apiResponseTime.add(emailResponse.timings.duration);
  });
  
  // GPU compute test (if available)
  group('GPU Compute', function() {
    const computePayload = {
      operation: 'test_compute',
      size: 100,
      iterations: 10
    };
    
    const computeResponse = http.post(
      `${BASE_URL}/api/compute/gpu-test`,
      JSON.stringify(computePayload),
      {
        headers: { 'Content-Type': 'application/json' },
        timeout: '30s'
      }
    );
    
    check(computeResponse, {
      'compute service responds': (r) => r.status < 500,
      'compute response time < 10000ms': (r) => r.timings.duration < 10000,
    });
    
    errorRate.add(computeResponse.status >= 500);
    apiResponseTime.add(computeResponse.timings.duration);
  });
  
  // Random sleep between 1-3 seconds to simulate real user behavior
  sleep(Math.random() * 2 + 1);
}

// Setup function - runs once before the test
export function setup() {
  console.log('Starting load test setup...');
  
  // Verify API is accessible
  const healthCheck = http.get(`${BASE_URL}/api/health`);
  if (healthCheck.status !== 200) {
    console.error('API health check failed during setup');
    return null;
  }
  
  console.log('Load test setup completed successfully');
  return { baseUrl: BASE_URL };
}

// Teardown function - runs once after the test
export function teardown(data) {
  console.log('Load test completed');
  console.log('Final cleanup...');
  
  // Could add cleanup operations here if needed
}

// Handle summary data
export function handleSummary(data) {
  return {
    'load-test-results.json': JSON.stringify(data, null, 2),
    'load-test-summary.txt': textSummary(data, { indent: ' ', enableColors: true }),
  };
}

// Custom text summary helper
function textSummary(data, options = {}) {
  const indent = options.indent || '';
  const summary = [];
  
  summary.push(`${indent}Load Test Summary`);
  summary.push(`${indent}================`);
  summary.push(`${indent}Total VUs: ${data.metrics.vus_max.values.max}`);
  summary.push(`${indent}Total Requests: ${data.metrics.http_reqs.values.count}`);
  summary.push(`${indent}Failed Requests: ${data.metrics.http_req_failed.values.fails || 0}`);
  summary.push(`${indent}Error Rate: ${((data.metrics.http_req_failed.values.rate || 0) * 100).toFixed(2)}%`);
  summary.push(`${indent}Average Response Time: ${data.metrics.http_req_duration.values.avg.toFixed(2)}ms`);
  summary.push(`${indent}95th Percentile Response Time: ${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms`);
  summary.push(`${indent}Throughput: ${data.metrics.http_reqs.values.rate.toFixed(2)} req/s`);
  
  return summary.join('\n');
}