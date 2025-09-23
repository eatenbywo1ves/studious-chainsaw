import { financialTerms } from './data/financial-terms.js';
import { contextualTranslations } from './data/contextual-translations.js';

export class FinancialTranslator {
  constructor() {
    this.terms = financialTerms;
    this.contextual = contextualTranslations;
  }

  async translateTerm(term, fromLang, toLang, context = 'general') {
    const normalizedTerm = term.toLowerCase().trim();
    
    // Check for exact matches first
    const exactMatch = this.findExactMatch(normalizedTerm, fromLang, toLang, context);
    if (exactMatch) {
      return exactMatch;
    }

    // Check for partial matches or synonyms
    const partialMatch = this.findPartialMatch(normalizedTerm, fromLang, toLang, context);
    if (partialMatch) {
      return partialMatch;
    }

    // Fallback to contextual translation
    return this.contextualTranslate(term, fromLang, toLang, context);
  }

  findExactMatch(term, fromLang, toLang, context) {
    const contextTerms = this.terms[context] || this.terms.general;
    
    for (const [key, translations] of Object.entries(contextTerms)) {
      if (key.toLowerCase() === term || 
          (translations[fromLang] && translations[fromLang].toLowerCase() === term)) {
        
        const translation = translations[toLang];
        if (translation) {
          return {
            term: translation,
            definition: translations.definition || '',
            confidence: 0.95,
            alternatives: this.getAlternatives(key, toLang),
            source: 'exact_match'
          };
        }
      }
    }
    return null;
  }

  findPartialMatch(term, fromLang, toLang, context) {
    const contextTerms = this.terms[context] || this.terms.general;
    
    for (const [key, translations] of Object.entries(contextTerms)) {
      const keyWords = key.toLowerCase().split(' ');
      const termWords = term.split(' ');
      
      // Check if term contains key words or vice versa
      const matchScore = this.calculateMatchScore(keyWords, termWords);
      
      if (matchScore > 0.7) {
        const translation = translations[toLang];
        if (translation) {
          return {
            term: translation,
            definition: translations.definition || '',
            confidence: matchScore * 0.8,
            alternatives: this.getAlternatives(key, toLang),
            source: 'partial_match'
          };
        }
      }
    }
    return null;
  }

  calculateMatchScore(words1, words2) {
    const set1 = new Set(words1);
    const set2 = new Set(words2);
    const intersection = new Set([...set1].filter(x => set2.has(x)));
    const union = new Set([...set1, ...set2]);
    
    return intersection.size / union.size;
  }

  contextualTranslate(term, fromLang, toLang, context) {
    // Use contextual patterns for unknown terms
    const patterns = this.contextual[context] || this.contextual.general;
    
    // Apply transformation patterns based on context
    let translatedTerm = term;
    
    if (patterns && patterns[toLang]) {
      const rules = patterns[toLang];
      
      // Apply prefix/suffix rules
      if (rules.prefixes) {
        for (const [pattern, replacement] of Object.entries(rules.prefixes)) {
          if (term.startsWith(pattern)) {
            translatedTerm = term.replace(pattern, replacement);
            break;
          }
        }
      }
      
      if (rules.suffixes) {
        for (const [pattern, replacement] of Object.entries(rules.suffixes)) {
          if (term.endsWith(pattern)) {
            translatedTerm = translatedTerm.replace(new RegExp(pattern + '$'), replacement);
            break;
          }
        }
      }
    }

    return {
      term: translatedTerm,
      definition: `Contextual translation for: ${term}`,
      confidence: 0.6,
      alternatives: [term], // Fallback to original
      source: 'contextual'
    };
  }

  getAlternatives(termKey, toLang) {
    // Find alternative translations or synonyms
    const alternatives = [];
    
    // Look for related terms in the same context
    for (const context of Object.keys(this.terms)) {
      const contextTerms = this.terms[context];
      for (const [key, translations] of Object.entries(contextTerms)) {
        if (key !== termKey && translations[toLang] && 
            this.isRelated(termKey, key)) {
          alternatives.push(translations[toLang]);
        }
      }
    }
    
    return alternatives.slice(0, 3); // Return top 3 alternatives
  }

  isRelated(term1, term2) {
    // Simple relatedness check based on common words
    const words1 = term1.toLowerCase().split(' ');
    const words2 = term2.toLowerCase().split(' ');
    
    return words1.some(word => words2.includes(word));
  }

  async localizeInterface(interfaceStrings, targetLocale) {
    const [language] = targetLocale.split('-');
    const localized = {};
    
    for (const [key, value] of Object.entries(interfaceStrings)) {
      if (typeof value === 'string') {
        const translation = await this.translateTerm(value, 'en', language, 'general');
        localized[key] = translation.term;
      } else if (typeof value === 'object' && value !== null) {
        localized[key] = await this.localizeInterface(value, targetLocale);
      } else {
        localized[key] = value;
      }
    }
    
    return localized;
  }

  async validateTranslation(originalText, translatedText, language, domain) {
    // Validate translation accuracy and domain compliance
    const issues = [];
    const suggestions = [];
    
    // Check for common translation issues
    if (originalText.length > 0 && translatedText.length === 0) {
      issues.push('Translation is empty');
    }
    
    if (originalText === translatedText) {
      issues.push('Translation identical to original');
    }
    
    // Domain-specific validation
    const domainCompliance = this.validateDomainCompliance(translatedText, domain, language);
    
    // Calculate accuracy score
    const accuracy = Math.max(0, 1 - (issues.length * 0.2));
    
    return {
      isValid: issues.length === 0,
      accuracy: accuracy,
      issues: issues,
      suggestions: suggestions,
      domainCompliance: domainCompliance
    };
  }

  validateDomainCompliance(text, domain, language) {
    const domainTerms = this.terms[domain] || {};
    let complianceScore = 0.8; // Base score
    
    // Check if text uses appropriate domain terminology
    const textWords = text.toLowerCase().split(/\s+/);
    const domainWords = Object.keys(domainTerms).map(term => term.toLowerCase());
    
    const domainWordCount = textWords.filter(word => 
      domainWords.some(domainWord => domainWord.includes(word))
    ).length;
    
    if (domainWordCount > 0) {
      complianceScore = Math.min(1.0, complianceScore + (domainWordCount * 0.1));
    }
    
    return {
      score: complianceScore,
      domainTermsFound: domainWordCount,
      recommendation: complianceScore < 0.7 ? 'Consider using more domain-specific terminology' : 'Good domain compliance'
    };
  }

  async getTermsDictionary() {
    return this.terms;
  }
}