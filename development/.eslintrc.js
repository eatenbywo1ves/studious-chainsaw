module.exports = {
    env: {
        browser: true,
        es2021: true,
        node: true
    },
    extends: [
        'eslint:recommended'
    ],
    parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module'
    },
    rules: {
        // Best Practices
        'no-console': 'warn',
        'no-debugger': 'error',
        'no-eval': 'error',
        'no-implied-eval': 'error',
        'no-new-func': 'error',
        'prefer-const': 'error',
        'no-var': 'error',

        // Style
        'indent': ['error', 4],
        'quotes': ['error', 'single'],
        'semi': ['error', 'always'],
        'comma-dangle': ['error', 'never'],
        'no-trailing-spaces': 'error',
        'eol-last': 'error',

        // ES6+
        'arrow-spacing': 'error',
        'object-shorthand': 'error',
        'prefer-arrow-callback': 'error',
        'prefer-template': 'error',

        // Error Prevention
        'no-undef': 'error',
        'no-unused-vars': ['error', { 'argsIgnorePattern': '^_' }],
        'no-unreachable': 'error'
    },
    globals: {
        'Chart': 'readonly',
        'WebSocket': 'readonly'
    }
};