#!/usr/bin/env node

// Simple test script for Multidimensional Stochastic MCP Server
console.log('Testing Multidimensional Stochastic MCP Server...');

const testCases = [
  {
    name: 'Multi-Asset GBM (2 Assets)',
    tool: 'generate_multi_gbm',
    args: {
      steps: 252,
      timeHorizon: 1.0,
      assets: [
        { mu: 0.08, sigma: 0.2, initialPrice: 100 },
        { mu: 0.06, sigma: 0.25, initialPrice: 120 }
      ],
      correlations: { rho_xy: 0.6 }
    }
  },
  {
    name: 'Multi-Asset GBM (3 Assets)', 
    tool: 'generate_multi_gbm',
    args: {
      steps: 252,
      timeHorizon: 1.0,
      assets: [
        { mu: 0.08, sigma: 0.2, initialPrice: 100 },
        { mu: 0.06, sigma: 0.25, initialPrice: 120 },
        { mu: 0.10, sigma: 0.3, initialPrice: 80 }
      ],
      correlations: { rho_xy: 0.6, rho_xz: 0.3, rho_yz: 0.4 }
    }
  },
  {
    name: 'Multi-Process Ornstein-Uhlenbeck',
    tool: 'generate_multi_ou',
    args: {
      steps: 252,
      timeHorizon: 1.0,
      processes: [
        { kappa: 2.0, theta: 0.04, sigma: 0.2, initialValue: 0.03 },
        { kappa: 1.5, theta: 0.05, sigma: 0.15, initialValue: 0.04 }
      ],
      correlations: { rho_xy: 0.5 }
    }
  },
  {
    name: 'Multi-Asset Heston',
    tool: 'generate_multi_heston',
    args: {
      steps: 252,
      timeHorizon: 1.0,
      assets: [
        { mu: 0.08, kappa: 2.0, theta: 0.04, xi: 0.1, rho: -0.7, initialPrice: 100, initialVar: 0.04 },
        { mu: 0.06, kappa: 1.5, theta: 0.05, xi: 0.15, rho: -0.6, initialPrice: 120, initialVar: 0.06 }
      ]
    }
  }
];

console.log('\nAvailable Test Cases:');
testCases.forEach((test, i) => {
  console.log(`${i + 1}. ${test.name}`);
  console.log(`   Tool: ${test.tool}`);
  console.log(`   Args: ${JSON.stringify(test.args, null, 2)}\n`);
});

console.log('Portfolio Analysis Example:');
console.log('After generating multi-asset paths, use calculate_portfolio_metrics with:');
console.log(JSON.stringify({
  path: '...', // Generated path data
  weights: [0.6, 0.4] // Portfolio weights
}, null, 2));

console.log('\nTo run the server:');
console.log('npm install && npm start');
console.log('\nTo test with MCP client, add to your MCP config:');
console.log(JSON.stringify({
  "multidimensional-stochastic": {
    "command": "node",
    "args": ["src/index.js"],
    "cwd": process.cwd()
  }
}, null, 2));