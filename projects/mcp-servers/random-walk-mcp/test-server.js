#!/usr/bin/env node

// Simple test script for Random Walk MCP Server
console.log('Testing Random Walk MCP Server...');

const testCases = [
  {
    name: 'Simple Walk Generation',
    tool: 'generate_simple_walk',
    args: { steps: 100, stepSize: 1.0, dimensions: 2 }
  },
  {
    name: 'Biased Walk Generation', 
    tool: 'generate_biased_walk',
    args: { steps: 100, bias: 0.2, stepSize: 1.0, dimensions: 2 }
  },
  {
    name: 'Levy Walk Generation',
    tool: 'generate_levy_walk', 
    args: { steps: 100, alpha: 1.5, stepSize: 1.0, dimensions: 2 }
  },
  {
    name: 'Correlated Walk Generation',
    tool: 'generate_correlated_walk',
    args: { steps: 100, correlation: 0.7, stepSize: 1.0, dimensions: 2 }
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
  "random-walk": {
    "command": "node", 
    "args": ["src/index.js"],
    "cwd": process.cwd()
  }
}, null, 2));