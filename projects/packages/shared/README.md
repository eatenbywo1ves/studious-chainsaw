# @monorepo/shared

Shared utilities, types, and constants for the projects monorepo.

## Overview

This package provides the foundational utilities and type definitions used across all workspace packages. It serves as the common dependency for consistent behavior and type safety throughout the monorepo.

## Installation

```bash
# Install in the monorepo root
npm install

# Or install in a specific workspace
npm install @monorepo/shared --workspace=my-package
```

## Usage

### Types

```typescript
import type {
  Vector2D,
  Vector3D,
  StochasticConfig,
  RandomWalkOptions
} from '@monorepo/shared';

// Use in your component
const position: Vector2D = { x: 10, y: 20 };
const config: StochasticConfig = {
  steps: 1000,
  volatility: 0.2,
  drift: 0.05
};
```

### Utilities

```typescript
import {
  clamp,
  randomGaussian,
  formatCurrency,
  debounce
} from '@monorepo/shared';

// Mathematical utilities
const bounded = clamp(value, 0, 100);
const sample = randomGaussian(0, 1);

// Formatting utilities
const price = formatCurrency(1234.56, 'USD'); // "$1,234.56"

// Performance utilities
const debouncedHandler = debounce(handler, 300);
```

### Constants

```typescript
import {
  COLORS,
  CHART_DEFAULTS,
  API_ENDPOINTS
} from '@monorepo/shared';

// Theme colors
const primary = COLORS.PRIMARY;
const accent = COLORS.ACCENT;

// Chart configuration
const chartConfig = {
  ...CHART_DEFAULTS,
  width: 800,
  height: 400
};
```

## API Reference

### Types

#### Vector Types
```typescript
interface Vector2D {
  x: number;
  y: number;
}

interface Vector3D extends Vector2D {
  z: number;
}
```

#### Configuration Types
```typescript
interface StochasticConfig {
  steps: number;
  volatility: number;
  drift: number;
  seed?: number;
}

interface RandomWalkOptions {
  dimensions: number;
  stepSize: number;
  boundary?: {
    min: Vector2D;
    max: Vector2D;
  };
}
```

#### Chart Types
```typescript
interface ChartData {
  timestamp: number;
  value: number;
  metadata?: Record<string, any>;
}

interface ChartConfig {
  width: number;
  height: number;
  margin: {
    top: number;
    right: number;
    bottom: number;
    left: number;
  };
}
```

### Utilities

#### Mathematical Functions
```typescript
// Clamp value between min and max
function clamp(value: number, min: number, max: number): number;

// Generate random number from normal distribution
function randomGaussian(mean: number, stdDev: number): number;

// Calculate distance between two points
function distance(a: Vector2D, b: Vector2D): number;

// Linear interpolation
function lerp(start: number, end: number, t: number): number;
```

#### Formatting Functions
```typescript
// Format number as currency
function formatCurrency(value: number, currency: string): string;

// Format number with specified decimal places
function formatNumber(value: number, decimals: number): string;

// Format percentage
function formatPercentage(value: number, decimals: number): string;
```

#### Performance Utilities
```typescript
// Debounce function calls
function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void;

// Throttle function calls
function throttle<T extends (...args: any[]) => any>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void;

// Memoize function results
function memoize<T extends (...args: any[]) => any>(
  func: T
): T;
```

### Constants

#### Colors
```typescript
export const COLORS = {
  PRIMARY: '#0066cc',
  SECONDARY: '#6c757d',
  SUCCESS: '#28a745',
  WARNING: '#ffc107',
  ERROR: '#dc3545',
  INFO: '#17a2b8'
} as const;
```

#### Chart Defaults
```typescript
export const CHART_DEFAULTS = {
  width: 600,
  height: 400,
  margin: {
    top: 20,
    right: 20,
    bottom: 20,
    left: 20
  }
} as const;
```

## Development

### Building
```bash
npm run build
```

### Development Mode
```bash
npm run dev
```

### Testing
```bash
# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test:coverage
```

### Type Checking
```bash
npm run typecheck
```

## Architecture

### Module Structure
```
src/
├── types/           # TypeScript type definitions
│   ├── index.ts
│   ├── vectors.ts
│   ├── charts.ts
│   └── config.ts
├── utils/           # Utility functions
│   ├── index.ts
│   ├── math.ts
│   ├── format.ts
│   └── performance.ts
├── constants/       # Application constants
│   ├── index.ts
│   ├── colors.ts
│   └── charts.ts
└── index.ts         # Main export file
```

### Export Strategy
- **Named Exports**: All utilities and types use named exports
- **Type-only Exports**: Types are exported with `export type`
- **Tree Shaking**: All exports are tree-shakeable
- **Barrel Exports**: Single entry point via index.ts

### Dependency Policy
- **Zero Runtime Dependencies**: Only TypeScript and Node types
- **Minimal API Surface**: Keep exports focused and minimal
- **Backward Compatibility**: Semantic versioning and deprecation notices

## Best Practices

### Type Definitions
- Use `interface` for object shapes that might be extended
- Use `type` for unions, primitives, and computed types
- Export types with `export type` for better tree shaking
- Provide comprehensive JSDoc comments

### Utility Functions
- Keep functions pure and side-effect free
- Provide comprehensive input validation
- Include performance optimizations where appropriate
- Write comprehensive unit tests

### Constants
- Use `const assertions` for immutable objects
- Group related constants in modules
- Provide TypeScript literal types where possible
- Document usage examples

## Migration Guide

### From v0.x to v1.x
1. Update import statements to use named imports
2. Replace deprecated utility functions
3. Update type definitions to new interfaces
4. Run type checker to identify issues

### Breaking Changes
- Removed default exports in favor of named exports
- Renamed `Position2D` to `Vector2D` for consistency
- Updated `ChartConfig` interface structure
- Removed deprecated `randomSeed` function

## Contributing

1. Follow the [monorepo contributing guidelines](../../CONTRIBUTING.md)
2. Add tests for any new utilities or types
3. Update documentation for API changes
4. Run `npm run check` before committing

## License

MIT License - see the [LICENSE](../../LICENSE) file for details.