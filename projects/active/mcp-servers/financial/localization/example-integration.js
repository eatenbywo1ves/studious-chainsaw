#!/usr/bin/env node

/**
 * Example integration showing how to use the Financial Localization MCP Server
 * with a financial application (like the simulator you showed earlier)
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { spawn } from 'child_process';

class FinancialAppLocalizer {
  constructor() {
    this.client = null;
    this.isConnected = false;
  }

  async connect() {
    try {
      // Spawn the MCP server
      const serverProcess = spawn('node', ['src/index.js'], {
        cwd: process.cwd(),
        stdio: ['pipe', 'pipe', 'inherit']
      });

      // Create transport and client
      const transport = new StdioClientTransport({
        stdin: serverProcess.stdin,
        stdout: serverProcess.stdout
      });

      this.client = new Client({
        name: 'financial-app-localizer',
        version: '1.0.0'
      }, {
        capabilities: {}
      });

      await this.client.connect(transport);
      this.isConnected = true;
      
      console.log('✅ Connected to Financial Localization MCP Server');
      
      // List available tools
      const tools = await this.client.request({
        method: 'tools/list'
      });
      
      console.log('📋 Available tools:', tools.tools.map(t => t.name).join(', '));
      
    } catch (error) {
      console.error('❌ Failed to connect:', error.message);
      throw error;
    }
  }

  async localizeFinancialSimulatorInterface(targetLocale = 'es-ES') {
    if (!this.isConnected) throw new Error('Not connected to MCP server');

    console.log(`🌍 Localizing financial simulator to ${targetLocale}...`);

    // Original interface strings from the financial simulator
    const originalInterface = {
      // Main components
      "Financial Stochastic Process Simulator": "Financial Stochastic Process Simulator",
      "Monte Carlo simulation of financial models and portfolio dynamics": "Monte Carlo simulation of financial models and portfolio dynamics",
      
      // Controls
      "Start": "Start",
      "Pause": "Pause", 
      "Reset": "Reset",
      "Time Horizon (Days)": "Time Horizon (Days)",
      "Simulation Paths": "Simulation Paths",
      "Progress": "Progress",
      
      // Models
      "Stochastic Models": "Stochastic Models",
      "Black-Scholes (GBM)": "Black-Scholes (GBM)",
      "Vasicek Interest Rates": "Vasicek Interest Rates",
      "Heston Stochastic Vol": "Heston Stochastic Vol",
      "Jump Diffusion (Merton)": "Jump Diffusion (Merton)",
      "Portfolio Simulation": "Portfolio Simulation",
      
      // Options
      "Options Pricing": "Options Pricing",
      "Call Option": "Call Option",
      "Put Option": "Put Option",
      "Strike Price": "Strike Price",
      "Delta": "Delta",
      "Gamma": "Gamma",
      "Theta": "Theta",
      "Vega": "Vega",
      
      // Risk metrics
      "Risk Metrics": "Risk Metrics",
      "Expected Return": "Expected Return",
      "Volatility": "Volatility",
      "Sharpe Ratio": "Sharpe Ratio",
      "Max Drawdown": "Max Drawdown",
      "Value at Risk": "Value at Risk",
      "Conditional VaR": "Conditional VaR",
      
      // Portfolio
      "Portfolio Composition": "Portfolio Composition",
      "Stock A": "Stock A",
      "Stock B": "Stock B", 
      "Bond": "Bond",
      "Cash": "Cash",
      
      // Scenarios
      "Market Scenarios": "Market Scenarios",
      "Market Crash": "Market Crash",
      "Economic Growth": "Economic Growth",
      "Rate Shock": "Rate Shock",
      "Volatility Spike": "Volatility Spike",
      
      // Performance metrics
      "Advanced Risk-Adjusted Metrics": "Advanced Risk-Adjusted Metrics",
      "Sortino Ratio": "Sortino Ratio",
      "Calmar Ratio": "Calmar Ratio",
      "Omega Ratio": "Omega Ratio",
      "Information Ratio": "Information Ratio",
      "Tracking Error": "Tracking Error",
      "Portfolio Beta": "Portfolio Beta",
      "Alpha": "Alpha"
    };

    try {
      // Localize the interface
      const response = await this.client.request({
        method: 'tools/call',
        params: {
          name: 'localize_financial_interface',
          arguments: {
            interface_strings: originalInterface,
            target_locale: targetLocale
          }
        }
      });

      const localizedStrings = JSON.parse(response.content[0].text);
      console.log('✅ Interface localized successfully');
      
      return localizedStrings.localized_strings;
      
    } catch (error) {
      console.error('❌ Localization failed:', error.message);
      throw error;
    }
  }

  async formatCurrencyExamples() {
    if (!this.isConnected) throw new Error('Not connected to MCP server');

    console.log('💰 Formatting currency examples...');

    const examples = [
      { amount: 125430.67, currency: 'USD', locale: 'en-US' },
      { amount: 125430.67, currency: 'EUR', locale: 'de-DE' },
      { amount: 125430.67, currency: 'GBP', locale: 'en-GB' },
      { amount: 125430, currency: 'JPY', locale: 'ja-JP' },
      { amount: 125430.67, currency: 'CHF', locale: 'de-CH' },
    ];

    const results = [];
    
    for (const example of examples) {
      try {
        const response = await this.client.request({
          method: 'tools/call',
          params: {
            name: 'format_currency',
            arguments: example
          }
        });
        
        const formatted = JSON.parse(response.content[0].text);
        results.push({
          ...example,
          formatted: formatted.formatted
        });
        
      } catch (error) {
        console.error(`Failed to format ${example.currency}:`, error.message);
      }
    }
    
    console.log('💰 Currency formatting results:');
    results.forEach(result => {
      console.log(`  ${result.currency} (${result.locale}): ${result.formatted}`);
    });
    
    return results;
  }

  async translateFinancialTerms() {
    if (!this.isConnected) throw new Error('Not connected to MCP server');

    console.log('🔤 Translating financial terms...');

    const terms = [
      { term: 'Value at Risk', context: 'risk', language: 'es' },
      { term: 'Black-Scholes', context: 'options', language: 'fr' },
      { term: 'Sharpe Ratio', context: 'portfolio', language: 'de' },
      { term: 'Maximum Drawdown', context: 'risk', language: 'ja' },
      { term: 'Call Option', context: 'options', language: 'zh' },
    ];

    const results = [];
    
    for (const termData of terms) {
      try {
        const response = await this.client.request({
          method: 'tools/call',
          params: {
            name: 'translate_financial_term',
            arguments: {
              term: termData.term,
              to_language: termData.language,
              context: termData.context
            }
          }
        });
        
        const translation = JSON.parse(response.content[0].text);
        results.push({
          ...termData,
          translation: translation.translated_term,
          confidence: translation.confidence
        });
        
      } catch (error) {
        console.error(`Failed to translate ${termData.term}:`, error.message);
      }
    }
    
    console.log('🔤 Translation results:');
    results.forEach(result => {
      console.log(`  "${result.term}" → "${result.translation}" (${result.language}, confidence: ${result.confidence})`);
    });
    
    return results;
  }

  async getSupportedLocales() {
    if (!this.isConnected) throw new Error('Not connected to MCP server');

    try {
      const response = await this.client.request({
        method: 'tools/call',
        params: {
          name: 'get_supported_locales',
          arguments: {}
        }
      });
      
      const locales = JSON.parse(response.content[0].text);
      console.log(`🌍 Supported locales (${locales.total_count}):`);
      
      locales.supported_locales.forEach(locale => {
        console.log(`  ${locale.code}: ${locale.name} (${locale.nativeName})`);
      });
      
      return locales.supported_locales;
      
    } catch (error) {
      console.error('❌ Failed to get locales:', error.message);
      throw error;
    }
  }

  async runCompleteExample() {
    console.log('🚀 Running complete Financial Localization MCP example...\n');
    
    try {
      // Connect to server
      await this.connect();
      
      // Show supported locales
      await this.getSupportedLocales();
      console.log('\n' + '='.repeat(60) + '\n');
      
      // Format currency examples
      await this.formatCurrencyExamples();
      console.log('\n' + '='.repeat(60) + '\n');
      
      // Translate financial terms
      await this.translateFinancialTerms();
      console.log('\n' + '='.repeat(60) + '\n');
      
      // Localize interface to Spanish
      const spanishInterface = await this.localizeFinancialSimulatorInterface('es-ES');
      console.log('🇪🇸 Spanish interface preview:');
      Object.entries(spanishInterface).slice(0, 10).forEach(([key, value]) => {
        console.log(`  "${key}" → "${value}"`);
      });
      console.log(`  ... and ${Object.keys(spanishInterface).length - 10} more`);
      
      console.log('\n✅ Complete example finished successfully!');
      
    } catch (error) {
      console.error('❌ Example failed:', error.message);
      process.exit(1);
    }
  }

  disconnect() {
    if (this.client) {
      this.client.close();
      this.isConnected = false;
      console.log('👋 Disconnected from MCP server');
    }
  }
}

// Run the example
async function main() {
  const localizer = new FinancialAppLocalizer();
  
  // Handle cleanup
  process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down...');
    localizer.disconnect();
    process.exit(0);
  });
  
  await localizer.runCompleteExample();
  localizer.disconnect();
}

// Only run if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}

export { FinancialAppLocalizer };