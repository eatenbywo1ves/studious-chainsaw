#!/usr/bin/env node

/**
 * Test script for Performance Monitor MCP Server
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function testServer() {
  console.log('🧪 Testing Performance Monitor MCP Server...\n');

  const serverPath = join(__dirname, 'src', 'index.js');
  const server = spawn('node', [serverPath], {
    stdio: ['pipe', 'pipe', 'pipe']
  });

  // Test cases
  const testCases = [
    {
      name: 'List Tools',
      request: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list'
      }
    },
    {
      name: 'Get Container Metrics',
      request: {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: {
          name: 'get_container_metrics',
          arguments: {
            include_system: true
          }
        }
      }
    },
    {
      name: 'Get Performance Summary',
      request: {
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: {
          name: 'get_performance_summary',
          arguments: {
            threshold_cpu: 70,
            threshold_memory: 80
          }
        }
      }
    },
    {
      name: 'Get Optimization Recommendations',
      request: {
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: {
          name: 'get_optimization_recommendations',
          arguments: {
            analysis_period: '15m'
          }
        }
      }
    },
    {
      name: 'Monitor Resource Health',
      request: {
        jsonrpc: '2.0',
        id: 5,
        method: 'tools/call',
        params: {
          name: 'monitor_resource_health',
          arguments: {
            service_names: ['catalytic', 'redis', 'postgres']
          }
        }
      }
    }
  ];

  let responseCount = 0;
  const responses = [];

  server.stdout.on('data', (data) => {
    const lines = data.toString().split('\n').filter(line => line.trim());

    for (const line of lines) {
      try {
        const response = JSON.parse(line);
        responses.push(response);
        responseCount++;
      } catch (e) {
        // Ignore non-JSON lines
      }
    }
  });

  server.stderr.on('data', (data) => {
    console.log('Server info:', data.toString());
  });

  // Send initialization
  const initRequest = {
    jsonrpc: '2.0',
    id: 0,
    method: 'initialize',
    params: {
      protocolVersion: '2024-11-05',
      capabilities: {
        tools: {}
      },
      clientInfo: {
        name: 'test-client',
        version: '1.0.0'
      }
    }
  };

  server.stdin.write(JSON.stringify(initRequest) + '\n');

  // Wait for initialization
  await new Promise(resolve => setTimeout(resolve, 1000));

  // Send test cases
  for (const testCase of testCases) {
    console.log(`📋 Testing: ${testCase.name}`);
    server.stdin.write(JSON.stringify(testCase.request) + '\n');

    // Wait between requests
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  // Wait for all responses
  await new Promise(resolve => setTimeout(resolve, 3000));

  // Analyze results
  console.log('\n📊 Test Results:');
  console.log(`Total responses: ${responses.length}`);

  for (const response of responses) {
    if (response.id === 0) {
      console.log('✅ Server initialized successfully');
    } else if (response.error) {
      console.log(`❌ Test ${response.id} failed: ${response.error.message}`);
    } else if (response.result) {
      const testCase = testCases.find(tc => tc.request.id === response.id);
      if (testCase) {
        console.log(`✅ ${testCase.name}: Success`);

        // Show sample of response
        if (testCase.name === 'List Tools' && response.result.tools) {
          console.log(`   📋 Found ${response.result.tools.length} tools`);
        } else if (testCase.name === 'Get Container Metrics' && response.result.content) {
          try {
            const data = JSON.parse(response.result.content[0].text);
            console.log(`   📊 Found ${data.containers?.length || 0} containers`);
          } catch (e) {
            console.log('   📊 Metrics data received');
          }
        } else if (testCase.name === 'Get Performance Summary' && response.result.content) {
          try {
            const data = JSON.parse(response.result.content[0].text);
            console.log(`   🔍 Health: ${data.overall_health}, Alerts: ${data.alerts?.length || 0}`);
          } catch (e) {
            console.log('   🔍 Performance summary received');
          }
        }
      }
    }
  }

  server.kill();

  console.log('\n🎉 Testing complete!');

  if (responses.filter(r => r.error).length === 0) {
    console.log('✅ All tests passed');
    process.exit(0);
  } else {
    console.log('❌ Some tests failed');
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Test interrupted');
  process.exit(1);
});

testServer().catch(console.error);