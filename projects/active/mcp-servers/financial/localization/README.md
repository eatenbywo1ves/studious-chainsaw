# Financial Localization MCP Server

A Model Context Protocol (MCP) server specifically designed for financial application localization, providing comprehensive translation and formatting services for financial terminology, currency formatting, and locale-specific number formatting.

## Features

### 🌍 Multi-Language Support
- **11+ Languages**: English, Spanish, French, German, Italian, Portuguese, Japanese, Korean, Chinese, Russian, Arabic
- **12+ Locales**: Including region-specific formatting (en-US, en-GB, de-DE, fr-FR, etc.)
- **Financial Domain Expertise**: Specialized translations for financial terminology

### 🛠️ Available Tools

#### 1. `translate_financial_term`
Translate financial terminology with context awareness:
```json
{
  "term": "value at risk",
  "to_language": "es",
  "context": "risk"
}
```
Returns: `"Valor en Riesgo"` with confidence score and alternatives.

#### 2. `format_currency`
Format currency amounts according to locale:
```json
{
  "amount": 12345.67,
  "currency": "EUR",
  "locale": "de-DE"
}
```
Returns: `"12.345,67 €"` with proper German formatting.

#### 3. `get_supported_locales`
Get comprehensive list of supported locales and their properties.

#### 4. `localize_financial_interface`
Localize entire interface object structures:
```json
{
  "interface_strings": {
    "portfolio": "Portfolio",
    "risk_analysis": "Risk Analysis"
  },
  "target_locale": "es-ES"
}
```

#### 5. `validate_financial_translation`
Validate translation accuracy with domain-specific compliance checking.

### 📊 Financial Domains Supported

- **General**: Basic financial terms (portfolio, asset, liability, equity)
- **Risk Management**: VaR, CVaR, volatility, correlation, stress testing
- **Options & Derivatives**: Greeks, strike prices, expiration, moneyness
- **Portfolio Management**: Performance metrics, attribution, optimization
- **Trading**: Futures, swaps, forwards, hedging strategies
- **UI Elements**: Buttons, labels, navigation elements

### 🌐 Resources Available

#### Financial Terms Dictionary
- Comprehensive dictionary with 100+ financial terms
- Context-aware translations
- Definitions and alternative translations included

#### Currency Locale Mappings
- Currency symbols and decimal place conventions
- Preferred locales for each currency
- Regional usage information

#### Number Format Patterns
- Locale-specific decimal and thousands separators
- Grouping patterns
- Date and time formatting preferences

## Installation & Setup

### Prerequisites
- Node.js 18+
- MCP-compatible client (like Claude Code)

### Quick Start

1. **Install dependencies:**
```bash
npm install
```

2. **Add to your MCP configuration:**
```json
{
  "mcpServers": {
    "financial-localization": {
      "command": "node",
      "args": ["src/index.js"],
      "cwd": "/path/to/financial-localization-mcp"
    }
  }
}
```

3. **Start the server:**
```bash
npm start
```

## Usage Examples

### Basic Term Translation
```javascript
// Translate "Black-Scholes" to Japanese
const result = await callTool('translate_financial_term', {
  term: 'Black-Scholes',
  to_language: 'ja',
  context: 'options'
});
// Returns: "ブラック・ショールズ"
```

### Currency Formatting
```javascript
// Format Japanese Yen for Japan locale
const formatted = await callTool('format_currency', {
  amount: 1234567,
  currency: 'JPY',
  locale: 'ja-JP'
});
// Returns: "￥1,234,567"
```

### Interface Localization
```javascript
// Localize financial app interface to Spanish
const localized = await callTool('localize_financial_interface', {
  interface_strings: {
    "start_simulation": "Start Simulation",
    "portfolio_value": "Portfolio Value",
    "risk_metrics": "Risk Metrics"
  },
  target_locale: "es-ES"
});
// Returns Spanish translations with proper financial terminology
```

## Integration with Financial Applications

This MCP server is designed to integrate seamlessly with financial applications like:

- **Trading Platforms**: Multi-language support for global users
- **Risk Management Systems**: Localized risk reports and metrics
- **Portfolio Management Tools**: Client-facing interfaces in local languages
- **Financial Simulations**: Localized parameter names and results
- **Regulatory Reporting**: Compliance with local terminology requirements

## Supported Currencies

| Currency | Symbol | Locales | Decimal Places |
|----------|--------|---------|----------------|
| USD | $ | en-US, en-CA | 2 |
| EUR | € | de-DE, fr-FR, es-ES, it-IT | 2 |
| GBP | £ | en-GB | 2 |
| JPY | ¥ | ja-JP | 0 |
| CHF | CHF | de-CH, fr-CH | 2 |
| CNY | ¥ | zh-CN | 2 |
| And more... | | | |

## Advanced Features

### Context-Aware Translation
The server uses financial context to provide accurate translations:
- **Options context**: "strike" → "precio de ejercicio" (Spanish)
- **Risk context**: "exposure" → "exposición al riesgo" (Spanish)
- **Portfolio context**: "allocation" → "asignación de activos" (Spanish)

### Validation & Quality Assurance
- Translation accuracy scoring
- Domain compliance checking
- Alternative translation suggestions
- Confidence level reporting

### Extensibility
- Easy to add new languages
- Configurable translation patterns
- Custom financial domain support
- Plugin architecture ready

## API Reference

### Tool Schemas

All tools follow MCP standard schemas with comprehensive input validation:

- **String parameters**: term, language codes, locale codes
- **Number parameters**: currency amounts, confidence thresholds
- **Object parameters**: interface strings, validation options
- **Enum parameters**: financial contexts, supported languages

### Resource URIs

- `financial://translations/terms` - Complete terms dictionary
- `financial://locale/currencies` - Currency mapping data
- `financial://formats/numbers` - Number formatting patterns

## Contributing

This MCP server is designed for defensive financial applications only. Contributions should focus on:
- Adding new language support
- Expanding financial terminology
- Improving translation accuracy
- Enhancing locale-specific formatting

## License

MIT License - See LICENSE file for details.

---

**Note**: This MCP server provides localization services for defensive financial applications only. It does not provide investment advice or facilitate trading activities.