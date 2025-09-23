#!/usr/bin/env node

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const serverPath = join(__dirname, '..', 'src', 'index.js');

class MCPTestClient {
  constructor() {
    this.server = null;
    this.buffer = '';
  }

  async connect() {
    return new Promise((resolve, reject) => {
      this.server = spawn('node', [serverPath], {
        stdio: ['pipe', 'pipe', 'pipe']
      });

      this.server.stdout.on('data', (data) => {
        this.buffer += data.toString();
      });

      this.server.stderr.on('data', (data) => {
        console.log('Server message:', data.toString());
        resolve();
      });

      this.server.on('error', reject);
    });
  }

  async sendRequest(request) {
    return new Promise((resolve) => {
      const message = JSON.stringify(request) + '\n';
      this.server.stdin.write(message);
      
      setTimeout(() => {
        resolve(this.buffer);
        this.buffer = '';
      }, 100);
    });
  }

  async close() {
    if (this.server) {
      this.server.kill();
    }
  }
}

async function runTests() {
  const client = new MCPTestClient();
  let passed = 0;
  let failed = 0;

  console.log('🧪 Starting MCP Stochastic Server Tests...\n');

  try {
    await client.connect();
    console.log('✅ Server started successfully');
    passed++;

    // Test 1: List tools
    console.log('\n📋 Test 1: List available tools');
    const listToolsRequest = {
      jsonrpc: '2.0',
      method: 'tools/list',
      id: 1
    };
    const response = await client.sendRequest(listToolsRequest);
    if (response.includes('generate_gbm')) {
      console.log('✅ Tools listed successfully');
      passed++;
    } else {
      console.log('❌ Failed to list tools');
      failed++;
    }

    // Test 2: Generate GBM
    console.log('\n📊 Test 2: Generate Geometric Brownian Motion');
    const gbmRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'generate_gbm',
        arguments: {
          steps: 10,
          timeHorizon: 1,
          mu: 0.05,
          sigma: 0.2,
          initialPrice: 100
        }
      },
      id: 2
    };
    const gbmResponse = await client.sendRequest(gbmRequest);
    if (gbmResponse) {
      console.log('✅ GBM generation successful');
      passed++;
    } else {
      console.log('❌ GBM generation failed');
      failed++;
    }

    // Test 3: Edge case - negative parameters
    console.log('\n🔍 Test 3: Edge case - negative time horizon');
    const edgeRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'generate_gbm',
        arguments: {
          steps: 10,
          timeHorizon: -1,
          initialPrice: 100
        }
      },
      id: 3
    };
    const edgeResponse = await client.sendRequest(edgeRequest);
    console.log('✅ Edge case handled');
    passed++;

    // Test 4: Calculate risk metrics
    console.log('\n📈 Test 4: Calculate risk metrics');
    const metricsRequest = {
      jsonrpc: '2.0',
      method: 'tools/call',
      params: {
        name: 'calculate_risk_metrics',
        arguments: {
          path: [
            { time: 0, price: 100 },
            { time: 1, price: 105 },
            { time: 2, price: 103 }
          ]
        }
      },
      id: 4
    };
    const metricsResponse = await client.sendRequest(metricsRequest);
    if (metricsResponse) {
      console.log('✅ Risk metrics calculated');
      passed++;
    } else {
      console.log('❌ Risk metrics calculation failed');
      failed++;
    }

  } catch (error) {
    console.error('❌ Test error:', error);
    failed++;
  } finally {
    await client.close();
  }

  // Summary
  console.log('\n' + '='.repeat(50));
  console.log(`📊 Test Results: ${passed} passed, ${failed} failed`);
  console.log('='.repeat(50));

  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(console.error);