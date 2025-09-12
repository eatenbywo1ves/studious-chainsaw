#!/usr/bin/env node

// Simple test script for Financial Stochastic MCP Server
console.log('Testing Financial Stochastic MCP Server...');

const testCases = [
  {
    name: 'Geometric Brownian Motion',
    tool: 'generate_gbm',
    args: { steps: 252, timeHorizon: 1.0, mu: 0.08, sigma: 0.2, initialPrice: 100 }
  },
  {
    name: 'Ornstein-Uhlenbeck Process',
    tool: 'generate_ou_process',
    args: { steps: 252, timeHorizon: 1.0, kappa: 2.0, theta: 0.04, sigma: 0.2 }
  },
  {
    name: 'Heston Stochastic Volatility',
    tool: 'generate_heston_model',
    args: { steps: 252, timeHorizon: 1.0, mu: 0.08, kappa: 2.0, theta: 0.04, xi: 0.1, rho: -0.7 }
  },
  {
    name: 'Merton Jump Diffusion',
    tool: 'generate_merton_jump',
    args: { steps: 252, timeHorizon: 1.0, mu: 0.08, sigma: 0.2, lambda: 0.1, muJ: -0.1, sigmaJ: 0.15 }
  },
  {
    name: 'Cox-Ingersoll-Ross Interest Rates',
    tool: 'generate_cir_process',
    args: { steps: 252, timeHorizon: 1.0, kappa: 2.0, theta: 0.04, sigma: 0.2, initialRate: 0.03 }
  }
];

console.log('\nAvailable Test Cases:');
testCases.forEach((test, i) => {
  console.log(`${i + 1}. ${test.name}`);
  console.log(`   Tool: ${test.tool}`);
  console.log(`   Args: ${JSON.stringify(test.args)}\n`);
});

console.log('To run the server:');
console.log('npm install && npm start');
console.log('\nTo test with MCP client, add to your MCP config:');
console.log(JSON.stringify({
  "financial-stochastic": {
    "command": "node",
    "args": ["src/index.js"], 
    "cwd": process.cwd()
  }
}, null, 2));