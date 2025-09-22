#!/usr/bin/env node
const MCPServer = require('../../../base-server');

class FinancialLocalizationServer extends MCPServer {
    constructor() {
        super('financial-localization', '1.0.0');

        // Register financial localization specific methods
        this.registerMethod('format_currency', this.formatCurrency.bind(this));
        this.registerMethod('get_locale_settings', this.getLocaleSettings.bind(this));
    }

    async handleListTools() {
        return {
            tools: [
                {
                    name: 'format_currency',
                    description: 'Format currency values for different locales',
                    inputSchema: {
                        type: 'object',
                        properties: {
                            amount: { type: 'number' },
                            currency: { type: 'string' },
                            locale: { type: 'string' }
                        },
                        required: ['amount', 'currency']
                    }
                }
            ]
        };
    }

    async formatCurrency(params) {
        const { amount, currency = 'USD', locale = 'en-US' } = params;

        try {
            const formatted = new Intl.NumberFormat(locale, {
                style: 'currency',
                currency: currency
            }).format(amount);

            return { formatted, amount, currency, locale };
        } catch (error) {
            throw new Error(`Failed to format currency: ${error.message}`);
        }
    }

    async getLocaleSettings(params) {
        const { locale = 'en-US' } = params;

        return {
            locale,
            dateFormat: new Intl.DateTimeFormat(locale).resolvedOptions(),
            numberFormat: new Intl.NumberFormat(locale).resolvedOptions()
        };
    }
}

// Start the server
const server = new FinancialLocalizationServer();
server.start();