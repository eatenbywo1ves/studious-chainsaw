export class LocaleManager {
  constructor() {
    this.supportedLocales = {
      'en-US': {
        name: 'English (United States)',
        nativeName: 'English (United States)',
        language: 'en',
        region: 'US',
        currency: 'USD',
        dateFormat: 'MM/DD/YYYY',
        timeFormat: '12h',
        numberFormat: {
          decimal: '.',
          thousands: ',',
          grouping: [3]
        }
      },
      'en-GB': {
        name: 'English (United Kingdom)',
        nativeName: 'English (United Kingdom)',
        language: 'en',
        region: 'GB',
        currency: 'GBP',
        dateFormat: 'DD/MM/YYYY',
        timeFormat: '24h',
        numberFormat: {
          decimal: '.',
          thousands: ',',
          grouping: [3]
        }
      },
      'de-DE': {
        name: 'German (Germany)',
        nativeName: 'Deutsch (Deutschland)',
        language: 'de',
        region: 'DE',
        currency: 'EUR',
        dateFormat: 'DD.MM.YYYY',
        timeFormat: '24h',
        numberFormat: {
          decimal: ',',
          thousands: '.',
          grouping: [3]
        }
      },
      'fr-FR': {
        name: 'French (France)',
        nativeName: 'Français (France)',
        language: 'fr',
        region: 'FR',
        currency: 'EUR',
        dateFormat: 'DD/MM/YYYY',
        timeFormat: '24h',
        numberFormat: {
          decimal: ',',
          thousands: ' ',
          grouping: [3]
        }
      },
      'es-ES': {
        name: 'Spanish (Spain)',
        nativeName: 'Español (España)',
        language: 'es',
        region: 'ES',
        currency: 'EUR',
        dateFormat: 'DD/MM/YYYY',
        timeFormat: '24h',
        numberFormat: {
          decimal: ',',
          thousands: '.',
          grouping: [3]
        }
      },
      'ja-JP': {
        name: 'Japanese (Japan)',
        nativeName: '日本語 (日本)',
        language: 'ja',
        region: 'JP',
        currency: 'JPY',
        dateFormat: 'YYYY/MM/DD',
        timeFormat: '24h',
        numberFormat: {
          decimal: '.',
          thousands: ',',
          grouping: [3]
        }
      },
      'zh-CN': {
        name: 'Chinese (Simplified, China)',
        nativeName: '中文 (简体，中国)',
        language: 'zh',
        region: 'CN',
        currency: 'CNY',
        dateFormat: 'YYYY/MM/DD',
        timeFormat: '24h',
        numberFormat: {
          decimal: '.',
          thousands: ',',
          grouping: [3]
        }
      },
      'ko-KR': {
        name: 'Korean (South Korea)',
        nativeName: '한국어 (대한민국)',
        language: 'ko',
        region: 'KR',
        currency: 'KRW',
        dateFormat: 'YYYY.MM.DD',
        timeFormat: '12h',
        numberFormat: {
          decimal: '.',
          thousands: ',',
          grouping: [3]
        }
      },
      'it-IT': {
        name: 'Italian (Italy)',
        nativeName: 'Italiano (Italia)',
        language: 'it',
        region: 'IT',
        currency: 'EUR',
        dateFormat: 'DD/MM/YYYY',
        timeFormat: '24h',
        numberFormat: {
          decimal: ',',
          thousands: '.',
          grouping: [3]
        }
      },
      'pt-BR': {
        name: 'Portuguese (Brazil)',
        nativeName: 'Português (Brasil)',
        language: 'pt',
        region: 'BR',
        currency: 'BRL',
        dateFormat: 'DD/MM/YYYY',
        timeFormat: '24h',
        numberFormat: {
          decimal: ',',
          thousands: '.',
          grouping: [3]
        }
      },
      'ru-RU': {
        name: 'Russian (Russia)',
        nativeName: 'Русский (Россия)',
        language: 'ru',
        region: 'RU',
        currency: 'RUB',
        dateFormat: 'DD.MM.YYYY',
        timeFormat: '24h',
        numberFormat: {
          decimal: ',',
          thousands: ' ',
          grouping: [3]
        }
      },
      'ar-SA': {
        name: 'Arabic (Saudi Arabia)',
        nativeName: 'العربية (المملكة العربية السعودية)',
        language: 'ar',
        region: 'SA',
        currency: 'SAR',
        dateFormat: 'DD/MM/YYYY',
        timeFormat: '12h',
        direction: 'rtl',
        numberFormat: {
          decimal: '.',
          thousands: ',',
          grouping: [3]
        }
      }
    };

    this.financialTermsMapping = {
      'portfolio': {
        'en': 'Portfolio',
        'de': 'Portfolio',
        'fr': 'Portefeuille',
        'es': 'Cartera',
        'ja': 'ポートフォリオ',
        'zh': '投资组合',
        'ko': '포트폴리오',
        'it': 'Portafoglio',
        'pt': 'Portfólio',
        'ru': 'Портфель',
        'ar': 'محفظة الاستثمار'
      },
      'risk': {
        'en': 'Risk',
        'de': 'Risiko',
        'fr': 'Risque',
        'es': 'Riesgo',
        'ja': 'リスク',
        'zh': '风险',
        'ko': '위험',
        'it': 'Rischio',
        'pt': 'Risco',
        'ru': 'Риск',
        'ar': 'مخاطرة'
      },
      'return': {
        'en': 'Return',
        'de': 'Rendite',
        'fr': 'Rendement',
        'es': 'Rendimiento',
        'ja': '収益',
        'zh': '回报',
        'ko': '수익',
        'it': 'Rendimento',
        'pt': 'Retorno',
        'ru': 'Доходность',
        'ar': 'عائد'
      }
    };
  }

  async getSupportedLocales() {
    return Object.entries(this.supportedLocales).map(([code, info]) => ({
      code: code,
      name: info.name,
      nativeName: info.nativeName,
      language: info.language,
      region: info.region,
      currency: info.currency,
      direction: info.direction || 'ltr'
    }));
  }

  async getLocaleInfo(localeCode) {
    const locale = this.supportedLocales[localeCode];
    if (!locale) {
      throw new Error(`Unsupported locale: ${localeCode}`);
    }

    return {
      ...locale,
      code: localeCode,
      isRTL: locale.direction === 'rtl'
    };
  }

  async formatDate(date, localeCode, options = {}) {
    const locale = this.supportedLocales[localeCode];
    if (!locale) {
      throw new Error(`Unsupported locale: ${localeCode}`);
    }

    try {
      const formatter = new Intl.DateTimeFormat(localeCode, {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        ...options
      });

      return {
        formatted: formatter.format(date),
        locale: localeCode,
        pattern: locale.dateFormat
      };
    } catch (error) {
      // Fallback formatting
      const year = date.getFullYear();
      const month = String(date.getMonth() + 1).padStart(2, '0');
      const day = String(date.getDate()).padStart(2, '0');
      
      let formatted;
      switch (locale.dateFormat) {
        case 'MM/DD/YYYY':
          formatted = `${month}/${day}/${year}`;
          break;
        case 'DD/MM/YYYY':
          formatted = `${day}/${month}/${year}`;
          break;
        case 'DD.MM.YYYY':
          formatted = `${day}.${month}.${year}`;
          break;
        case 'YYYY/MM/DD':
          formatted = `${year}/${month}/${day}`;
          break;
        case 'YYYY.MM.DD':
          formatted = `${year}.${month}.${day}`;
          break;
        default:
          formatted = `${year}-${month}-${day}`;
      }
      
      return {
        formatted: formatted,
        locale: localeCode,
        pattern: locale.dateFormat,
        fallback: true
      };
    }
  }

  async formatTime(date, localeCode, options = {}) {
    const locale = this.supportedLocales[localeCode];
    if (!locale) {
      throw new Error(`Unsupported locale: ${localeCode}`);
    }

    try {
      const formatter = new Intl.DateTimeFormat(localeCode, {
        hour: '2-digit',
        minute: '2-digit',
        hour12: locale.timeFormat === '12h',
        ...options
      });

      return {
        formatted: formatter.format(date),
        locale: localeCode,
        format: locale.timeFormat
      };
    } catch (error) {
      // Fallback formatting
      const hours = date.getHours();
      const minutes = String(date.getMinutes()).padStart(2, '0');
      
      let formatted;
      if (locale.timeFormat === '12h') {
        const displayHours = hours === 0 ? 12 : hours > 12 ? hours - 12 : hours;
        const ampm = hours >= 12 ? 'PM' : 'AM';
        formatted = `${displayHours}:${minutes} ${ampm}`;
      } else {
        formatted = `${String(hours).padStart(2, '0')}:${minutes}`;
      }
      
      return {
        formatted: formatted,
        locale: localeCode,
        format: locale.timeFormat,
        fallback: true
      };
    }
  }

  async getNumberFormats() {
    const formats = {};
    
    for (const [localeCode, locale] of Object.entries(this.supportedLocales)) {
      formats[localeCode] = {
        decimal: locale.numberFormat.decimal,
        thousands: locale.numberFormat.thousands,
        grouping: locale.numberFormat.grouping,
        currency: locale.currency,
        examples: {
          number: this.formatNumberExample(12345.67, locale.numberFormat),
          currency: `${locale.currency} 12,345.67`, // Simplified example
          percentage: '12.34%'
        }
      };
    }
    
    return formats;
  }

  formatNumberExample(number, format) {
    const parts = number.toString().split('.');
    const integerPart = parts[0];
    const decimalPart = parts[1] || '';
    
    // Add thousands separators
    const reversedInteger = integerPart.split('').reverse();
    const groupedInteger = [];
    
    for (let i = 0; i < reversedInteger.length; i += 3) {
      const group = reversedInteger.slice(i, i + 3).reverse().join('');
      groupedInteger.unshift(group);
    }
    
    const formattedInteger = groupedInteger.join(format.thousands);
    
    return decimalPart ? 
      `${formattedInteger}${format.decimal}${decimalPart}` : 
      formattedInteger;
  }

  async getBestLocaleForRegion(region) {
    // Find the best locale match for a given region
    const matches = Object.entries(this.supportedLocales)
      .filter(([code, locale]) => 
        locale.region === region || 
        code.toLowerCase().includes(region.toLowerCase())
      )
      .map(([code, locale]) => ({ code, ...locale }));
    
    return matches.length > 0 ? matches[0] : null;
  }

  async getFinancialTermTranslation(term, language) {
    const termKey = term.toLowerCase();
    const translations = this.financialTermsMapping[termKey];
    
    if (translations && translations[language]) {
      return {
        term: translations[language],
        originalTerm: term,
        language: language,
        available: true
      };
    }
    
    return {
      term: term, // Fallback to original
      originalTerm: term,
      language: language,
      available: false,
      fallback: true
    };
  }

  async detectLocaleFromBrowser(acceptLanguageHeader) {
    // Parse Accept-Language header to detect preferred locales
    const languages = acceptLanguageHeader
      .split(',')
      .map(lang => {
        const parts = lang.trim().split(';');
        const code = parts[0];
        const quality = parts[1] ? parseFloat(parts[1].split('=')[1]) : 1.0;
        return { code, quality };
      })
      .sort((a, b) => b.quality - a.quality);
    
    // Find best matching supported locale
    for (const lang of languages) {
      if (this.supportedLocales[lang.code]) {
        return lang.code;
      }
      
      // Try language-only match (e.g., 'en' matches 'en-US')
      const languageOnly = lang.code.split('-')[0];
      const match = Object.keys(this.supportedLocales)
        .find(locale => locale.startsWith(languageOnly + '-'));
      
      if (match) {
        return match;
      }
    }
    
    return 'en-US'; // Default fallback
  }
}