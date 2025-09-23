/** @type {import('jest').Config} */
module.exports = {
  // Test environment
  testEnvironment: 'jsdom',

  // Setup files
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],

  // Module name mapping
  moduleNameMapper: {
    '^@monorepo/(.*)$': '<rootDir>/packages/$1/src',
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
  },

  // Transform files
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', {
      tsconfig: {
        jsx: 'react-jsx',
      },
    }],
  },

  // Test patterns
  testMatch: [
    '<rootDir>/packages/**/__tests__/**/*.(test|spec).(ts|tsx)',
    '<rootDir>/__tests__/**/*.(test|spec).(ts|tsx)'
  ],

  // Coverage collection
  collectCoverageFrom: [
    'packages/**/*.{ts,tsx}',
    '!packages/**/*.d.ts',
    '!packages/**/node_modules/**',
    '!packages/**/dist/**',
    '!packages/**/build/**',
    '!**/__tests__/**',
  ],

  // Coverage thresholds
  coverageThreshold: {
    global: {
      branches: 50,  // Lowered initial threshold
      functions: 50,
      lines: 50,
      statements: 50,
    },
  },

  // Coverage reporting
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],

  // Ignore patterns
  testPathIgnorePatterns: [
    '<rootDir>/node_modules/',
    '<rootDir>/dist/',
    '<rootDir>/build/',
    '<rootDir>/coverage/',
    '<rootDir>/active/', // Ignore active directory to avoid duplicates
  ],

  // Other settings
  verbose: true,
  testTimeout: 10000,
  clearMocks: true,
  restoreMocks: true,
};