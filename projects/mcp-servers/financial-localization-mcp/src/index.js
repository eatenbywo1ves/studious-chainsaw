#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { FinancialTranslator } from './translator.js';
import { CurrencyFormatter } from './currency-formatter.js';
import { LocaleManager } from './locale-manager.js';

class FinancialLocalizationServer {
  constructor() {
    this.server = new Server(
      {
        name: 'financial-localization-mcp',
        version: '1.0.0',
      },
      {
        capabilities: {
          resources: {},
          tools: {},
        },
      }
    );

    this.translator = new FinancialTranslator();
    this.currencyFormatter = new CurrencyFormatter();
    this.localeManager = new LocaleManager();

    this.setupHandlers();
  }

  setupHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'translate_financial_term',
          description: 'Translate financial terminology to specified language',
          inputSchema: {
            type: 'object',
            properties: {
              term: {
                type: 'string',
                description: 'Financial term to translate',
              },
              from_language: {
                type: 'string',
                description: 'Source language code (e.g., "en")',
                default: 'en',
              },
              to_language: {
                type: 'string',
                description: 'Target language code (e.g., "es", "fr", "de", "ja", "zh")',
              },
              context: {
                type: 'string',
                description: 'Financial context (options, derivatives, portfolio, risk)',
                enum: ['options', 'derivatives', 'portfolio', 'risk', 'general'],
                default: 'general',
              },
            },
            required: ['term', 'to_language'],
          },
        },
        {
          name: 'format_currency',
          description: 'Format currency amounts according to locale',
          inputSchema: {
            type: 'object',
            properties: {
              amount: {
                type: 'number',
                description: 'Currency amount to format',
              },
              currency: {
                type: 'string',
                description: 'Currency code (e.g., "USD", "EUR", "JPY")',
                default: 'USD',
              },
              locale: {
                type: 'string',
                description: 'Locale code (e.g., "en-US", "de-DE", "ja-JP")',
                default: 'en-US',
              },
            },
            required: ['amount'],
          },
        },
        {
          name: 'get_supported_locales',
          description: 'Get list of supported locales and languages',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'localize_financial_interface',
          description: 'Localize entire financial interface strings',
          inputSchema: {
            type: 'object',
            properties: {
              interface_strings: {
                type: 'object',
                description: 'Object containing interface strings to localize',
              },
              target_locale: {
                type: 'string',
                description: 'Target locale (e.g., "es-ES", "fr-FR", "de-DE")',
              },
            },
            required: ['interface_strings', 'target_locale'],
          },
        },
        {
          name: 'validate_financial_translation',
          description: 'Validate accuracy of financial translations',
          inputSchema: {
            type: 'object',
            properties: {
              original_text: {
                type: 'string',
                description: 'Original financial text',
              },
              translated_text: {
                type: 'string',
                description: 'Translated text to validate',
              },
              language: {
                type: 'string',
                description: 'Target language code',
              },
              domain: {
                type: 'string',
                description: 'Financial domain for validation',
                enum: ['derivatives', 'portfolio', 'risk_management', 'trading', 'general'],
                default: 'general',
              },
            },
            required: ['original_text', 'translated_text', 'language'],
          },
        },
      ],
    }));

    // List available resources
    this.server.setRequestHandler(ListResourcesRequestSchema, async () => ({
      resources: [
        {
          uri: 'financial://translations/terms',
          name: 'Financial Terms Dictionary',
          description: 'Comprehensive dictionary of financial terms in multiple languages',
          mimeType: 'application/json',
        },
        {
          uri: 'financial://locale/currencies',
          name: 'Currency Locale Mappings',
          description: 'Mapping of currencies to their preferred locales',
          mimeType: 'application/json',
        },
        {
          uri: 'financial://formats/numbers',
          name: 'Number Format Patterns',
          description: 'Number formatting patterns for different locales',
          mimeType: 'application/json',
        },
      ],
    }));

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'translate_financial_term':
            return await this.handleTranslateFinancialTerm(args);

          case 'format_currency':
            return await this.handleFormatCurrency(args);

          case 'get_supported_locales':
            return await this.handleGetSupportedLocales();

          case 'localize_financial_interface':
            return await this.handleLocalizeInterface(args);

          case 'validate_financial_translation':
            return await this.handleValidateTranslation(args);

          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error.message}`,
            },
          ],
          isError: true,
        };
      }
    });

    // Handle resource reads
    this.server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      const { uri } = request.params;

      try {
        switch (uri) {
          case 'financial://translations/terms':
            return {
              contents: [
                {
                  uri,
                  mimeType: 'application/json',
                  text: JSON.stringify(await this.translator.getTermsDictionary(), null, 2),
                },
              ],
            };

          case 'financial://locale/currencies':
            return {
              contents: [
                {
                  uri,
                  mimeType: 'application/json',
                  text: JSON.stringify(await this.currencyFormatter.getCurrencyLocales(), null, 2),
                },
              ],
            };

          case 'financial://formats/numbers':
            return {
              contents: [
                {
                  uri,
                  mimeType: 'application/json',
                  text: JSON.stringify(await this.localeManager.getNumberFormats(), null, 2),
                },
              ],
            };

          default:
            throw new Error(`Unknown resource: ${uri}`);
        }
      } catch (error) {
        throw new Error(`Failed to read resource ${uri}: ${error.message}`);
      }
    });
  }

  async handleTranslateFinancialTerm(args) {
    const { term, from_language = 'en', to_language, context = 'general' } = args;

    const translation = await this.translator.translateTerm(
      term,
      from_language,
      to_language,
      context
    );

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            original_term: term,
            translated_term: translation.term,
            definition: translation.definition,
            context: context,
            confidence: translation.confidence,
            alternative_translations: translation.alternatives,
          }, null, 2),
        },
      ],
    };
  }

  async handleFormatCurrency(args) {
    const { amount, currency = 'USD', locale = 'en-US' } = args;

    const formatted = await this.currencyFormatter.format(amount, currency, locale);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            original_amount: amount,
            currency: currency,
            locale: locale,
            formatted: formatted.formatted,
            symbol: formatted.symbol,
            decimal_places: formatted.decimalPlaces,
          }, null, 2),
        },
      ],
    };
  }

  async handleGetSupportedLocales() {
    const locales = await this.localeManager.getSupportedLocales();

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            supported_locales: locales,
            total_count: locales.length,
          }, null, 2),
        },
      ],
    };
  }

  async handleLocalizeInterface(args) {
    const { interface_strings, target_locale } = args;

    const localized = await this.translator.localizeInterface(interface_strings, target_locale);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            target_locale: target_locale,
            localized_strings: localized,
            translation_quality: 'high',
          }, null, 2),
        },
      ],
    };
  }

  async handleValidateTranslation(args) {
    const { original_text, translated_text, language, domain = 'general' } = args;

    const validation = await this.translator.validateTranslation(
      original_text,
      translated_text,
      language,
      domain
    );

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            is_valid: validation.isValid,
            accuracy_score: validation.accuracy,
            issues: validation.issues,
            suggestions: validation.suggestions,
            domain_compliance: validation.domainCompliance,
          }, null, 2),
        },
      ],
    };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Financial Localization MCP server running on stdio');
  }
}

const server = new FinancialLocalizationServer();
server.run().catch(console.error);