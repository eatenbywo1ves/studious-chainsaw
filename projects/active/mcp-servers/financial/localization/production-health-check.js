#!/usr/bin/env node

/**
 * Production Health Check for Financial Localization MCP Server
 * 
 * Comprehensive health check to ensure production readiness
 */

import { spawn } from 'child_process';
import { readFileSync, existsSync, statSync } from 'fs';
import { join } from 'path';

console.log('🏥 Financial Localization MCP Server - Production Health Check');
console.log('='.repeat(70));

let healthScore = 0;
const maxScore = 12;

function checkItem(name, condition, details = '') {
  if (condition) {
    console.log(`✅ ${name}`);
    if (details) console.log(`   ${details}`);
    healthScore++;
  } else {
    console.log(`❌ ${name}`);
    if (details) console.log(`   ${details}`);
  }
}

// 1. File System Health
console.log('\n📁 File System Health');
console.log('-'.repeat(30));

const coreFiles = {
  'src/index.js': 'Main server file',
  'src/translator.js': 'Translation engine', 
  'src/currency-formatter.js': 'Currency formatting',
  'src/locale-manager.js': 'Locale management',
  'package.json': 'Package configuration'
};

for (const [file, description] of Object.entries(coreFiles)) {
  const exists = existsSync(file);
  let size = 0;
  if (exists) {
    size = statSync(file).size;
  }
  checkItem(`${description} (${file})`, exists && size > 0, 
    exists ? `${size} bytes` : 'File missing or empty');
}

// 2. Configuration Health  
console.log('\n⚙️ Configuration Health');
console.log('-'.repeat(30));

try {
  const packageJson = JSON.parse(readFileSync('package.json', 'utf-8'));
  checkItem('Package.json valid', true, `v${packageJson.version}`);
  checkItem('MCP SDK dependency', 
    packageJson.dependencies && packageJson.dependencies['@modelcontextprotocol/sdk'],
    packageJson.dependencies ? packageJson.dependencies['@modelcontextprotocol/sdk'] : 'Missing');
} catch (error) {
  checkItem('Package.json valid', false, error.message);
  checkItem('MCP SDK dependency', false, 'Cannot read package.json');
}

try {
  const mcpConfig = JSON.parse(readFileSync('C:\\Users\\Corbin\\.mcp.json', 'utf-8'));
  checkItem('MCP configuration present', 
    mcpConfig.mcpServers && mcpConfig.mcpServers['financial-localization'],
    'Server registered in ~/.mcp.json');
} catch (error) {
  checkItem('MCP configuration present', false, error.message);
}

// 3. Runtime Health
console.log('\n🚀 Runtime Health');
console.log('-'.repeat(30));

const serverPath = join(process.cwd(), 'src', 'index.js');

// Test server startup
await new Promise((resolve) => {
  const serverProcess = spawn('node', [serverPath], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, NODE_ENV: 'production' }
  });

  let startupSuccess = false;
  let errorOutput = '';

  const timeout = setTimeout(() => {
    serverProcess.kill();
    checkItem('Server startup', startupSuccess, 
      startupSuccess ? 'Starts within 5 seconds' : 'Startup timeout or error');
    checkItem('No startup errors', errorOutput.length === 0 || startupSuccess,
      errorOutput ? `Error: ${errorOutput.substring(0, 100)}...` : 'Clean startup');
    resolve();
  }, 5000);

  serverProcess.stderr.on('data', (data) => {
    const output = data.toString();
    if (output.includes('Financial Localization MCP server running')) {
      startupSuccess = true;
      clearTimeout(timeout);
      serverProcess.kill();
      checkItem('Server startup', true, 'Starts successfully');
      checkItem('No startup errors', true, 'Clean startup');
      resolve();
    } else {
      errorOutput += output;
    }
  });

  serverProcess.on('error', (error) => {
    clearTimeout(timeout);
    errorOutput += error.message;
    checkItem('Server startup', false, `Error: ${error.message}`);
    checkItem('No startup errors', false, error.message);
    resolve();
  });
});

// 4. Integration Health
console.log('\n🔗 Integration Health');
console.log('-'.repeat(30));

checkItem('Claude Code integration ready', 
  existsSync('C:\\Users\\Corbin\\.mcp.json') && 
  existsSync(serverPath) &&
  existsSync('package.json'), 
  'All components present for Claude Code integration');

// 5. Production Readiness
console.log('\n🏭 Production Readiness');  
console.log('-'.repeat(30));

const hasProductionScript = existsSync('start-server.js');
const hasDocumentation = existsSync('DEPLOYMENT.md');
const hasHealthCheck = existsSync('quick-test.js');

checkItem('Production startup script', hasProductionScript, 
  hasProductionScript ? 'start-server.js available' : 'Missing production script');

checkItem('Documentation complete', hasDocumentation,
  hasDocumentation ? 'DEPLOYMENT.md present' : 'Missing deployment docs');

// Final Health Assessment
console.log('\n' + '='.repeat(70));
console.log('🎯 HEALTH CHECK SUMMARY');
console.log('='.repeat(70));

const healthPercentage = Math.round((healthScore / maxScore) * 100);
let healthStatus = '';
let statusIcon = '';

if (healthPercentage >= 90) {
  healthStatus = 'EXCELLENT - Production Ready';
  statusIcon = '🟢';
} else if (healthPercentage >= 80) {
  healthStatus = 'GOOD - Minor Issues';
  statusIcon = '🟡';  
} else if (healthPercentage >= 60) {
  healthStatus = 'FAIR - Needs Attention';
  statusIcon = '🟠';
} else {
  healthStatus = 'POOR - Critical Issues';
  statusIcon = '🔴';
}

console.log(`${statusIcon} Overall Health Score: ${healthScore}/${maxScore} (${healthPercentage}%)`);
console.log(`${statusIcon} Status: ${healthStatus}`);

if (healthPercentage >= 90) {
  console.log('\n🎉 PRODUCTION DEPLOYMENT SUCCESSFUL!');
  console.log('\n✨ Next Steps:');
  console.log('1. Restart Claude Code to load the MCP server');
  console.log('2. Test with: "Can you translate portfolio to Spanish?"');
  console.log('3. Explore all 5 financial localization tools');
  console.log('\n📋 Available Tools:');
  console.log('   • translate_financial_term');
  console.log('   • format_currency');  
  console.log('   • get_supported_locales');
  console.log('   • localize_financial_interface');
  console.log('   • validate_financial_translation');
} else {
  console.log('\n⚠️ Issues detected. Please address the failed checks above.');
  console.log('💡 Run individual components to diagnose specific problems.');
}

console.log('\n📄 For detailed information, see: DEPLOYMENT.md');
console.log('🔧 For quick testing, run: node quick-test.js');
console.log('='.repeat(70));