#!/usr/bin/env node

console.log('🚀 Quick Financial Localization MCP Server Test');

import { spawn } from 'child_process';
import { readFileSync, existsSync } from 'fs';

// Test 1: Check server files
console.log('1️⃣ Checking server files...');
const requiredFiles = [
  'src/index.js',
  'src/translator.js', 
  'src/currency-formatter.js',
  'src/locale-manager.js',
  'package.json'
];

let filesOK = true;
for (const file of requiredFiles) {
  if (existsSync(file)) {
    console.log(`   ✅ ${file}`);
  } else {
    console.log(`   ❌ ${file} - MISSING`);
    filesOK = false;
  }
}

// Test 2: Check MCP configuration
console.log('2️⃣ Checking MCP configuration...');
try {
  const mcpConfig = JSON.parse(readFileSync('C:\\Users\\Corbin\\.mcp.json', 'utf-8'));
  if (mcpConfig.mcpServers && mcpConfig.mcpServers['financial-localization']) {
    console.log('   ✅ Financial localization server configured in MCP');
  } else {
    console.log('   ❌ Server not found in MCP configuration');
  }
} catch (error) {
  console.log(`   ❌ Error reading MCP config: ${error.message}`);
}

// Test 3: Test server startup
console.log('3️⃣ Testing server startup...');
const serverProcess = spawn('node', ['src/index.js'], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, NODE_ENV: 'production' }
});

let serverStarted = false;

const timeout = setTimeout(() => {
  if (!serverStarted) {
    console.log('   ❌ Server startup timeout');
    serverProcess.kill();
  }
}, 5000);

serverProcess.stderr.on('data', (data) => {
  const output = data.toString();
  if (output.includes('Financial Localization MCP server running')) {
    serverStarted = true;
    console.log('   ✅ Server started successfully');
    clearTimeout(timeout);
    serverProcess.kill();
    
    // Final summary
    console.log('\n🎯 DEPLOYMENT STATUS');
    console.log('='.repeat(50));
    if (filesOK && serverStarted) {
      console.log('✅ Financial Localization MCP Server is ready!');
      console.log('\n🔄 Next Steps:');
      console.log('1. Restart Claude Code');
      console.log('2. Server will be available as "financial-localization"');
      console.log('3. Test with: "translate portfolio to Spanish"');
    } else {
      console.log('❌ Some issues found. Please fix them before deployment.');
    }
  }
});

serverProcess.on('error', (error) => {
  console.log(`   ❌ Server error: ${error.message}`);
  clearTimeout(timeout);
});