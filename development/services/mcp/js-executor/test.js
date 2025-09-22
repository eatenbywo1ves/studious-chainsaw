#!/usr/bin/env node
import { Worker } from 'worker_threads';

// Test the JavaScript execution with a simple example
async function testExecutor() {
  console.log('Testing JavaScript Executor...\n');
  
  const testCode = `
    console.log('Hello from sandboxed JavaScript!');
    console.warn('This is a warning');
    
    const fibonacci = (n) => {
      if (n <= 1) return n;
      return fibonacci(n - 1) + fibonacci(n - 2);
    };
    
    console.log('Fibonacci(10):', fibonacci(10));
    
    // Return a value
    'Execution completed successfully! Fibonacci(10) = ' + fibonacci(10);
  `;
  
  return new Promise((resolve, reject) => {
    const workerCode = `
      const { parentPort } = require('worker_threads');
      const { performance } = require('perf_hooks');
      
      const startTime = performance.now();
      const logs = [];
      
      // Override console methods
      console.log = (...args) => logs.push({ type: 'log', message: args.join(' ') });
      console.error = (...args) => logs.push({ type: 'error', message: args.join(' ') });
      console.warn = (...args) => logs.push({ type: 'warn', message: args.join(' ') });
      console.info = (...args) => logs.push({ type: 'info', message: args.join(' ') });
      
      let result = undefined;
      let error = null;
      
      try {
        result = eval(${JSON.stringify(testCode)});
      } catch (e) {
        error = {
          name: e.name,
          message: e.message,
          stack: e.stack
        };
      }
      
      const executionTime = performance.now() - startTime;
      
      parentPort.postMessage({
        result: result !== undefined ? String(result) : undefined,
        logs,
        error,
        executionTime
      });
    `;

    const worker = new Worker(workerCode, { eval: true });
    
    const timer = setTimeout(() => {
      worker.terminate();
      reject(new Error('Execution timed out'));
    }, 5000);
    
    worker.on('message', (data) => {
      clearTimeout(timer);
      worker.terminate();
      
      console.log('=== Console Output ===');
      data.logs.forEach(log => {
        console.log(`[${log.type.toUpperCase()}] ${log.message}`);
      });
      
      if (data.result !== undefined) {
        console.log('\n=== Result ===');
        console.log(data.result);
      }
      
      if (data.error) {
        console.log('\n=== Error ===');
        console.log(`${data.error.name}: ${data.error.message}`);
      }
      
      console.log(`\nExecution time: ${data.executionTime.toFixed(2)}ms`);
      resolve(data);
    });
    
    worker.on('error', (error) => {
      clearTimeout(timer);
      worker.terminate();
      reject(error);
    });
  });
}

// Run the test
testExecutor()
  .then(() => {
    console.log('\n✅ JavaScript Executor test passed!');
  })
  .catch((error) => {
    console.error('\n❌ JavaScript Executor test failed:', error);
    process.exit(1);
  });