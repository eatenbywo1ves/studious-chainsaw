export class CurrencyFormatter {
  constructor() {
    this.currencyData = {
      'USD': { symbol: '$', decimalPlaces: 2, locales: ['en-US', 'en-CA'] },
      'EUR': { symbol: '€', decimalPlaces: 2, locales: ['de-DE', 'fr-FR', 'es-ES', 'it-IT'] },
      'GBP': { symbol: '£', decimalPlaces: 2, locales: ['en-GB'] },
      'JPY': { symbol: '¥', decimalPlaces: 0, locales: ['ja-JP'] },
      'CHF': { symbol: 'CHF', decimalPlaces: 2, locales: ['de-CH', 'fr-CH'] },
      'CAD': { symbol: 'C$', decimalPlaces: 2, locales: ['en-CA', 'fr-CA'] },
      'AUD': { symbol: 'A$', decimalPlaces: 2, locales: ['en-AU'] },
      'CNY': { symbol: '¥', decimalPlaces: 2, locales: ['zh-CN'] },
      'INR': { symbol: '₹', decimalPlaces: 2, locales: ['hi-IN', 'en-IN'] },
      'BRL': { symbol: 'R$', decimalPlaces: 2, locales: ['pt-BR'] },
      'RUB': { symbol: '₽', decimalPlaces: 2, locales: ['ru-RU'] },
      'KRW': { symbol: '₩', decimalPlaces: 0, locales: ['ko-KR'] },
    };
  }

  async format(amount, currency = 'USD', locale = 'en-US') {
    const currencyInfo = this.currencyData[currency.toUpperCase()];
    
    if (!currencyInfo) {
      throw new Error(`Unsupported currency: ${currency}`);
    }

    try {
      // Use Intl.NumberFormat for proper localization
      const formatter = new Intl.NumberFormat(locale, {
        style: 'currency',
        currency: currency.toUpperCase(),
        minimumFractionDigits: currencyInfo.decimalPlaces,
        maximumFractionDigits: currencyInfo.decimalPlaces,
      });

      const formatted = formatter.format(amount);

      return {
        formatted: formatted,
        symbol: currencyInfo.symbol,
        decimalPlaces: currencyInfo.decimalPlaces,
        locale: locale,
        currency: currency.toUpperCase(),
        components: this.parseFormattedAmount(formatted, amount, currencyInfo)
      };
    } catch (error) {
      // Fallback formatting
      return this.fallbackFormat(amount, currency, locale, currencyInfo);
    }
  }

  parseFormattedAmount(formatted, originalAmount, currencyInfo) {
    // Extract components of the formatted string
    const parts = new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
    }).formatToParts(originalAmount);

    return {
      currency: currencyInfo.symbol,
      integer: parts.find(part => part.type === 'integer')?.value || '0',
      decimal: parts.find(part => part.type === 'decimal')?.value || '',
      fraction: parts.find(part => part.type === 'fraction')?.value || '',
      group: parts.find(part => part.type === 'group')?.value || ','
    };
  }

  fallbackFormat(amount, currency, locale, currencyInfo) {
    const symbol = currencyInfo.symbol;
    const decimalPlaces = currencyInfo.decimalPlaces;
    
    // Simple fallback formatting
    const formatted = `${symbol}${amount.toFixed(decimalPlaces)}`;
    
    return {
      formatted: formatted,
      symbol: symbol,
      decimalPlaces: decimalPlaces,
      locale: locale,
      currency: currency.toUpperCase(),
      fallback: true
    };
  }

  async formatPercentage(value, locale = 'en-US', decimalPlaces = 2) {
    try {
      const formatter = new Intl.NumberFormat(locale, {
        style: 'percent',
        minimumFractionDigits: decimalPlaces,
        maximumFractionDigits: decimalPlaces,
      });

      return {
        formatted: formatter.format(value / 100),
        value: value,
        locale: locale,
        decimalPlaces: decimalPlaces
      };
    } catch (error) {
      return {
        formatted: `${value.toFixed(decimalPlaces)}%`,
        value: value,
        locale: locale,
        decimalPlaces: decimalPlaces,
        fallback: true
      };
    }
  }

  async formatLargeNumber(number, locale = 'en-US', notation = 'compact') {
    try {
      const formatter = new Intl.NumberFormat(locale, {
        notation: notation, // 'compact', 'scientific', 'engineering'
        compactDisplay: 'short' // 'short' or 'long'
      });

      return {
        formatted: formatter.format(number),
        original: number,
        notation: notation,
        locale: locale
      };
    } catch (error) {
      // Fallback for large numbers
      if (number >= 1e12) {
        return { formatted: `${(number / 1e12).toFixed(1)}T`, original: number, fallback: true };
      } else if (number >= 1e9) {
        return { formatted: `${(number / 1e9).toFixed(1)}B`, original: number, fallback: true };
      } else if (number >= 1e6) {
        return { formatted: `${(number / 1e6).toFixed(1)}M`, original: number, fallback: true };
      } else if (number >= 1e3) {
        return { formatted: `${(number / 1e3).toFixed(1)}K`, original: number, fallback: true };
      }
      
      return { formatted: number.toString(), original: number, fallback: true };
    }
  }

  async getCurrencyLocales() {
    const currencyLocaleMap = {};
    
    for (const [currency, info] of Object.entries(this.currencyData)) {
      currencyLocaleMap[currency] = {
        symbol: info.symbol,
        decimalPlaces: info.decimalPlaces,
        preferredLocales: info.locales,
        regions: this.getCurrencyRegions(currency)
      };
    }
    
    return currencyLocaleMap;
  }

  getCurrencyRegions(currency) {
    const regionMap = {
      'USD': ['United States', 'Ecuador', 'El Salvador', 'Zimbabwe'],
      'EUR': ['Eurozone', 'Germany', 'France', 'Spain', 'Italy', 'Netherlands'],
      'GBP': ['United Kingdom', 'England', 'Scotland', 'Wales', 'Northern Ireland'],
      'JPY': ['Japan'],
      'CHF': ['Switzerland', 'Liechtenstein'],
      'CAD': ['Canada'],
      'AUD': ['Australia'],
      'CNY': ['China'],
      'INR': ['India'],
      'BRL': ['Brazil'],
      'RUB': ['Russia'],
      'KRW': ['South Korea'],
    };
    
    return regionMap[currency] || [currency];
  }

  async convertCurrency(amount, fromCurrency, toCurrency, exchangeRate) {
    // Note: In a real implementation, you would fetch live exchange rates
    // This is a simplified example
    
    if (!exchangeRate) {
      throw new Error('Exchange rate required for currency conversion');
    }
    
    const convertedAmount = amount * exchangeRate;
    const fromFormatted = await this.format(amount, fromCurrency);
    const toFormatted = await this.format(convertedAmount, toCurrency);
    
    return {
      original: {
        amount: amount,
        currency: fromCurrency,
        formatted: fromFormatted.formatted
      },
      converted: {
        amount: convertedAmount,
        currency: toCurrency,
        formatted: toFormatted.formatted
      },
      exchangeRate: exchangeRate,
      timestamp: new Date().toISOString()
    };
  }
}