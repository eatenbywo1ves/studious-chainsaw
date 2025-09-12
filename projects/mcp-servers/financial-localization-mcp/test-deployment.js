#!/usr/bin/env node

/**
 * Simple Deployment Test for Financial Localization MCP Server
 * 
 * Quick verification that the server is working correctly.
 */

import { spawn } from 'child_process';
import { join } from 'path';

class SimpleDeploymentTest {
  constructor() {
    this.serverPath = join(process.cwd(), 'src', 'index.js');
    this.passed = 0;
    this.total = 0;
  }

  log(message, type = 'info') {
    const icons = { info: '🔍', success: '✅', error: '❌', warning: '⚠️' };
    console.log(`${icons[type]} ${message}`);
  }

  async runTest(name, testFunction) {
    this.total++;
    this.log(`Testing: ${name}`);
    
    try {
      await testFunction();
      this.passed++;
      this.log(`${name} - PASSED`, 'success');
    } catch (error) {
      this.log(`${name} - FAILED: ${error.message}`, 'error');
    }
  }

  async testServerStartup() {
    return new Promise((resolve, reject) => {
      const serverProcess = spawn('node', [this.serverPath], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, NODE_ENV: 'production' }
      });

      const timeout = setTimeout(() => {
        serverProcess.kill();
        reject(new Error('Server startup timeout'));
      }, 5000);

      serverProcess.stderr.on('data', (data) => {
        const output = data.toString();
        if (output.includes('Financial Localization MCP server running')) {
          clearTimeout(timeout);
          serverProcess.kill();
          resolve();
        }
      });

      serverProcess.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });
  }

  async testMCPConfiguration() {
    const fs = await import('fs/promises');
    try {
      const configPath = 'C:\\Users\\Corbin\\.mcp.json';
      const config = JSON.parse(await fs.readFile(configPath, 'utf-8'));
      
      if (!config.mcpServers || !config.mcpServers['financial-localization']) {
        throw new Error('Financial localization server not found in MCP configuration');
      }
      
      const serverConfig = config.mcpServers['financial-localization'];
      if (!serverConfig.command || !serverConfig.args) {
        throw new Error('Invalid server configuration in MCP config');
      }
    } catch (error) {
      throw new Error(`MCP configuration test failed: ${error.message}`);
    }
  }

  async testServerFiles() {
    const fs = await import('fs/promises');
    const requiredFiles = [
      'src/index.js',
      'src/translator.js',
      'src/currency-formatter.js',
      'src/locale-manager.js',
      'package.json'
    ];

    for (const file of requiredFiles) {
      try {
        await fs.access(file);
      } catch (error) {
        throw new Error(`Required file missing: ${file}`);
      }
    }
  }

  async testPackageJson() {
    const fs = await import('fs/promises');
    try {
      const packageJson = JSON.parse(await fs.readFile('package.json', 'utf-8'));
      
      if (!packageJson.dependencies || !packageJson.dependencies['@modelcontextprotocol/sdk']) {
        throw new Error('Missing MCP SDK dependency');
      }
      
      if (packageJson.type !== 'module') {
        throw new Error('Package.json should have "type": "module"');
      }
    } catch (error) {
      throw new Error(`Package.json validation failed: ${error.message}`);
    }
  }

  async runAllTests() {
    this.log('🚀 Running Financial Localization MCP Server Deployment Tests\\n');

    await this.runTest('Server Files', () => this.testServerFiles());
    await this.runTest('Package.json Configuration', () => this.testPackageJson());
    await this.runTest('Server Startup', () => this.testServerStartup());
    await this.runTest('MCP Configuration', () => this.testMCPConfiguration());

    // Results
    console.log('\\n' + '='.repeat(60));
    console.log('📊 TEST RESULTS');
    console.log('='.repeat(60));
    console.log(`🎯 Tests Passed: ${this.passed}/${this.total}`);
    
    if (this.passed === this.total) {
      this.log('🎉 All tests passed! Server is ready for deployment.', 'success');
      console.log('\\n🔗 Next Steps:');
      console.log('1. Restart Claude Code to load the new MCP server');
      console.log('2. The server will be available as "financial-localization"');
      console.log('3. Test the tools: translate_financial_term, format_currency, etc.');
      console.log('\\n📖 Usage Example:');
      console.log('   Ask Claude: "Can you translate portfolio to Spanish?"');
    } else {
      this.log(`⚠️ ${this.total - this.passed} tests failed. Please fix the issues above.`, 'warning');
      process.exit(1);
    }
  }
}

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const tester = new SimpleDeploymentTest();
  tester.runAllTests().catch(console.error);
}

export default SimpleDeploymentTest;