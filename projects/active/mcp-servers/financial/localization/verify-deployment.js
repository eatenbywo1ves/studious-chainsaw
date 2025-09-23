#!/usr/bin/env node

/**
 * Financial Localization MCP Server Deployment Verification
 * 
 * This script verifies that the MCP server is properly deployed and functioning.
 * It tests all available tools and resources to ensure production readiness.
 */

import { spawn } from 'child_process';
import { writeFileSync, readFileSync } from 'fs';
import { join } from 'path';

class DeploymentVerifier {
  constructor() {
    this.serverPath = join(process.cwd(), 'src', 'index.js');
    this.testResults = {
      serverStartup: false,
      toolListing: false,
      resourceListing: false,
      toolExecution: {},
      resourceAccess: {},
      overallStatus: 'PENDING'
    };
  }

  async runVerification() {
    console.log('🚀 Starting Financial Localization MCP Server Deployment Verification\\n');
    
    try {
      await this.testServerStartup();
      await this.testToolListing();
      await this.testResourceListing();
      await this.testToolExecution();
      await this.testResourceAccess();
      
      this.generateReport();
      
    } catch (error) {
      console.error('❌ Verification failed:', error.message);
      this.testResults.overallStatus = 'FAILED';
      this.generateReport();
      process.exit(1);
    }
  }

  async testServerStartup() {
    console.log('1️⃣ Testing server startup...');
    
    return new Promise((resolve, reject) => {
      const serverProcess = spawn('node', [this.serverPath], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, NODE_ENV: 'production' }
      });

      let startupSuccess = false;
      
      const timeout = setTimeout(() => {
        serverProcess.kill();
        if (!startupSuccess) {
          reject(new Error('Server startup timeout'));
        }
      }, 5000);

      serverProcess.stderr.on('data', (data) => {
        const output = data.toString();
        if (output.includes('Financial Localization MCP server running')) {
          startupSuccess = true;
          this.testResults.serverStartup = true;
          clearTimeout(timeout);
          serverProcess.kill();
          console.log('   ✅ Server starts successfully');
          resolve();
        }
      });

      serverProcess.on('error', (error) => {
        clearTimeout(timeout);
        reject(new Error(`Server startup failed: ${error.message}`));
      });
    });
  }

  async testToolListing() {
    console.log('2️⃣ Testing tool listing...');
    
    const request = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
      params: {}
    };

    const result = await this.sendMCPRequest(request);
    
    if (result && result.tools && Array.isArray(result.tools)) {
      const expectedTools = [
        'translate_financial_term',
        'format_currency', 
        'get_supported_locales',
        'localize_financial_interface',
        'validate_financial_translation'
      ];
      
      const availableTools = result.tools.map(tool => tool.name);
      const allToolsPresent = expectedTools.every(tool => availableTools.includes(tool));
      
      if (allToolsPresent) {
        this.testResults.toolListing = true;
        console.log('   ✅ All expected tools are available');
        console.log(`   📋 Tools: ${availableTools.join(', ')}`);
      } else {
        const missingTools = expectedTools.filter(tool => !availableTools.includes(tool));
        throw new Error(`Missing tools: ${missingTools.join(', ')}`);
      }
    } else {
      throw new Error('Invalid tool listing response');
    }
  }

  async testResourceListing() {
    console.log('3️⃣ Testing resource listing...');
    
    const request = {
      jsonrpc: '2.0',
      id: 2,
      method: 'resources/list',
      params: {}
    };

    const result = await this.sendMCPRequest(request);
    
    if (result && result.resources && Array.isArray(result.resources)) {
      const expectedResources = [
        'financial://translations/terms',
        'financial://locale/currencies',
        'financial://formats/numbers'
      ];
      
      const availableResources = result.resources.map(resource => resource.uri);
      const allResourcesPresent = expectedResources.every(resource => availableResources.includes(resource));
      
      if (allResourcesPresent) {
        this.testResults.resourceListing = true;
        console.log('   ✅ All expected resources are available');
        console.log(`   📚 Resources: ${availableResources.join(', ')}`);
      } else {
        const missingResources = expectedResources.filter(resource => !availableResources.includes(resource));
        throw new Error(`Missing resources: ${missingResources.join(', ')}`);
      }
    } else {
      throw new Error('Invalid resource listing response');
    }
  }

  async testToolExecution() {
    console.log('4️⃣ Testing tool execution...');
    
    const toolTests = [
      {
        name: 'translate_financial_term',
        args: {
          term: 'portfolio',
          to_language: 'es',
          context: 'portfolio'
        }
      },
      {
        name: 'format_currency',
        args: {
          amount: 1234.56,
          currency: 'USD',
          locale: 'en-US'
        }
      },
      {
        name: 'get_supported_locales',
        args: {}
      }
    ];

    for (const test of toolTests) {
      console.log(`   🔧 Testing ${test.name}...`);
      
      const request = {
        jsonrpc: '2.0',
        id: Date.now(),
        method: 'tools/call',
        params: {
          name: test.name,
          arguments: test.args
        }
      };

      try {
        const result = await this.sendMCPRequest(request);
        
        if (result && result.content && Array.isArray(result.content)) {
          this.testResults.toolExecution[test.name] = 'SUCCESS';
          console.log(`      ✅ ${test.name} executed successfully`);
        } else {
          this.testResults.toolExecution[test.name] = 'FAILED';
          console.log(`      ❌ ${test.name} returned invalid response`);
        }
      } catch (error) {
        this.testResults.toolExecution[test.name] = 'ERROR';
        console.log(`      ❌ ${test.name} execution failed: ${error.message}`);
      }
    }
  }

  async testResourceAccess() {
    console.log('5️⃣ Testing resource access...');
    
    const resources = [
      'financial://translations/terms',
      'financial://locale/currencies',
      'financial://formats/numbers'
    ];

    for (const resourceUri of resources) {
      console.log(`   📖 Testing ${resourceUri}...`);
      
      const request = {
        jsonrpc: '2.0',
        id: Date.now(),
        method: 'resources/read',
        params: {
          uri: resourceUri
        }
      };

      try {
        const result = await this.sendMCPRequest(request);
        
        if (result && result.contents && Array.isArray(result.contents)) {
          this.testResults.resourceAccess[resourceUri] = 'SUCCESS';
          console.log(`      ✅ ${resourceUri} accessible`);
        } else {
          this.testResults.resourceAccess[resourceUri] = 'FAILED';
          console.log(`      ❌ ${resourceUri} returned invalid response`);
        }
      } catch (error) {
        this.testResults.resourceAccess[resourceUri] = 'ERROR';
        console.log(`      ❌ ${resourceUri} access failed: ${error.message}`);
      }
    }
  }

  async sendMCPRequest(request) {
    return new Promise((resolve, reject) => {
      const serverProcess = spawn('node', [this.serverPath], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, NODE_ENV: 'production' }
      });

      let response = '';
      let errorOutput = '';

      const timeout = setTimeout(() => {
        serverProcess.kill();
        reject(new Error('Request timeout'));
      }, 10000);

      serverProcess.stdout.on('data', (data) => {
        response += data.toString();
      });

      serverProcess.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });

      serverProcess.on('close', () => {
        clearTimeout(timeout);
        
        try {
          // Parse the JSON-RPC response
          const lines = response.trim().split('\\n');
          const jsonResponse = lines.find(line => {
            try {
              const parsed = JSON.parse(line);
              return parsed.jsonrpc === '2.0';
            } catch {
              return false;
            }
          });

          if (jsonResponse) {
            const parsed = JSON.parse(jsonResponse);
            if (parsed.error) {
              reject(new Error(parsed.error.message));
            } else {
              resolve(parsed.result);
            }
          } else {
            reject(new Error('No valid JSON-RPC response found'));
          }
        } catch (error) {
          reject(new Error(`Failed to parse response: ${error.message}`));
        }
      });

      serverProcess.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });

      // Send the request
      serverProcess.stdin.write(JSON.stringify(request) + '\\n');
      serverProcess.stdin.end();
    });
  }

  generateReport() {
    const allToolsPassed = Object.values(this.testResults.toolExecution).every(status => status === 'SUCCESS');
    const allResourcesPassed = Object.values(this.testResults.resourceAccess).every(status => status === 'SUCCESS');
    
    const overallSuccess = this.testResults.serverStartup && 
                          this.testResults.toolListing && 
                          this.testResults.resourceListing && 
                          allToolsPassed && 
                          allResourcesPassed;

    this.testResults.overallStatus = overallSuccess ? 'PASSED' : 'FAILED';

    console.log('\\n' + '='.repeat(80));
    console.log('📊 DEPLOYMENT VERIFICATION REPORT');
    console.log('='.repeat(80));
    console.log(`🎯 Overall Status: ${this.testResults.overallStatus === 'PASSED' ? '✅ PASSED' : '❌ FAILED'}`);
    console.log(`🚀 Server Startup: ${this.testResults.serverStartup ? '✅' : '❌'}`);
    console.log(`🔧 Tool Listing: ${this.testResults.toolListing ? '✅' : '❌'}`);
    console.log(`📚 Resource Listing: ${this.testResults.resourceListing ? '✅' : '❌'}`);
    
    console.log('\\n🔧 Tool Execution Results:');
    for (const [tool, status] of Object.entries(this.testResults.toolExecution)) {
      const statusIcon = status === 'SUCCESS' ? '✅' : '❌';
      console.log(`   ${statusIcon} ${tool}: ${status}`);
    }
    
    console.log('\\n📚 Resource Access Results:');
    for (const [resource, status] of Object.entries(this.testResults.resourceAccess)) {
      const statusIcon = status === 'SUCCESS' ? '✅' : '❌';
      console.log(`   ${statusIcon} ${resource}: ${status}`);
    }

    // Save detailed results to file
    const reportPath = 'deployment-verification-report.json';
    writeFileSync(reportPath, JSON.stringify(this.testResults, null, 2));
    console.log(`\\n📄 Detailed report saved to: ${reportPath}`);
    
    console.log('='.repeat(80));
    
    if (this.testResults.overallStatus === 'PASSED') {
      console.log('🎉 Financial Localization MCP Server is ready for production!');
      console.log('\\n🔗 Integration Instructions:');
      console.log('1. Server is configured in ~/.mcp.json');
      console.log('2. Restart Claude Code to load the new server');
      console.log('3. Available tools: translate_financial_term, format_currency, get_supported_locales, localize_financial_interface, validate_financial_translation');
      console.log('4. Available resources: financial://translations/terms, financial://locale/currencies, financial://formats/numbers');
    } else {
      console.log('⚠️  Some tests failed. Please review the results above.');
      process.exit(1);
    }
  }
}

// Run verification if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const verifier = new DeploymentVerifier();
  verifier.runVerification().catch(console.error);
}

export default DeploymentVerifier;