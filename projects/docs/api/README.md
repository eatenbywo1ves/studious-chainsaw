# API Documentation

Comprehensive TypeScript API documentation generated from source code using TypeDoc.

## Overview

This directory contains auto-generated API documentation for all packages in the monorepo. The documentation is built from TypeScript source code and provides detailed information about:

- **Types and Interfaces**: Complete type definitions with examples
- **Functions and Methods**: Parameter descriptions and return types
- **Classes and Components**: React component props and class methods
- **Modules and Exports**: Package structure and available imports

## Documentation Structure

```
docs/api/
├── README.md                           # This file
├── index.html                          # Main documentation entry point
├── packages/
│   ├── shared/                         # @monorepo/shared API docs
│   │   ├── index.html
│   │   ├── modules/
│   │   ├── interfaces/
│   │   └── functions/
│   ├── stochastic-components/          # Stochastic components API
│   │   ├── index.html
│   │   ├── components/
│   │   ├── hooks/
│   │   └── utilities/
│   └── random-walk-components/         # Random walk components API
│       ├── index.html
│       ├── components/
│       ├── hooks/
│       └── algorithms/
├── mcp-servers/                        # MCP server APIs
│   ├── financial-stochastic-mcp/
│   ├── random-walk-mcp/
│   └── multidimensional-stochastic-mcp/
└── financial-apps/                     # Application APIs
    ├── financial-simulator/
    └── tldraw-demo/
```

## Generating Documentation

### Prerequisites

Install TypeDoc and required plugins:

```bash
npm install --save-dev typedoc @typedoc/plugin-pages typedoc-plugin-mermaid
```

### Build All Documentation

```bash
# Generate complete API documentation
npm run docs:build

# Generate documentation for specific package
npm run docs:build --workspace=@monorepo/stochastic-components

# Serve documentation locally
npm run docs:serve
```

### TypeDoc Configuration

```javascript
// typedoc.config.js
module.exports = {
  entryPoints: [
    "packages/shared/src/index.ts",
    "packages/stochastic-components/src/index.ts",
    "packages/random-walk-components/src/index.ts"
  ],
  out: "docs/api",
  name: "Projects Monorepo API Documentation",
  includeVersion: true,
  excludePrivate: true,
  excludeProtected: true,
  excludeExternals: true,
  readme: "docs/api/README.md",
  theme: "default",
  plugin: ["@typedoc/plugin-pages", "typedoc-plugin-mermaid"],
  categorizeByGroup: true,
  categoryOrder: [
    "Components",
    "Hooks",
    "Utilities",
    "Types",
    "Constants"
  ],
  sort: ["source-order"],
  kindSortOrder: [
    "Reference",
    "Project",
    "Module",
    "Namespace",
    "Enum",
    "EnumMember",
    "Class",
    "Interface",
    "TypeAlias",
    "Constructor",
    "Property",
    "Variable",
    "Function",
    "Accessor",
    "Method",
    "Parameter",
    "TypeParameter",
    "TypeLiteral",
    "CallSignature",
    "ConstructorSignature",
    "IndexSignature",
    "GetSignature",
    "SetSignature"
  ],
  navigation: {
    includeCategories: true,
    includeGroups: true
  }
};
```

## Package Documentation

### @monorepo/shared

**Purpose**: Core utilities and type definitions

**Key Exports**:
- `Vector2D`, `Vector3D` - Geometric types
- `StochasticConfig` - Process configuration
- `clamp`, `lerp` - Math utilities
- `formatCurrency` - Formatting functions

**Example Usage**:
```typescript
import { Vector2D, clamp } from '@monorepo/shared';

const position: Vector2D = { x: 10, y: 20 };
const bounded = clamp(value, 0, 100);
```

[View Complete API →](./packages/shared/index.html)

### @monorepo/stochastic-components

**Purpose**: React components for stochastic process visualization

**Key Components**:
- `StochasticChart` - Interactive stochastic process visualization
- `MultidimensionalVisualizer` - 3D process rendering
- `ProcessControls` - Real-time parameter controls
- `StatisticsPanel` - Metrics display

**Key Hooks**:
- `useStochasticProcess` - Process state management
- `useRealTimeData` - Data streaming
- `useWalkAnimation` - Animation controls

**Example Usage**:
```typescript
import { StochasticChart, useStochasticProcess } from '@monorepo/stochastic-components';

function MyApp() {
  const { data, isRunning, start, stop } = useStochasticProcess({
    processType: 'brownian',
    steps: 1000
  });

  return (
    <StochasticChart
      data={data}
      onDataUpdate={(newData) => console.log(newData)}
    />
  );
}
```

[View Complete API →](./packages/stochastic-components/index.html)

### @monorepo/random-walk-components

**Purpose**: Random walk analysis and visualization components

**Key Components**:
- `RandomWalkChart` - Primary walk visualization
- `PathComparison` - Multi-walk comparison
- `WalkStatistics` - Statistical analysis
- `InteractiveWalkBuilder` - Algorithm builder

**Key Algorithms**:
- Simple Random Walk
- Biased Random Walk
- Levy Flight
- Self-Avoiding Walk

**Example Usage**:
```typescript
import { RandomWalkChart, useRandomWalk } from '@monorepo/random-walk-components';

function WalkDemo() {
  const { path, start, reset } = useRandomWalk({
    walkType: 'simple',
    steps: 1000,
    stepSize: 1
  });

  return (
    <RandomWalkChart
      path={path}
      animated={true}
      showStatistics={true}
    />
  );
}
```

[View Complete API →](./packages/random-walk-components/index.html)

## MCP Server APIs

### Financial Stochastic MCP Server

**Purpose**: Financial modeling and risk analysis via MCP protocol

**Available Tools**:
- `generate_gbm` - Geometric Brownian Motion
- `generate_ou_process` - Ornstein-Uhlenbeck Process
- `calculate_risk_metrics` - Risk analysis
- `price_option` - Option pricing

**Example Usage**:
```typescript
const client = new MCPClient();
await client.connect('financial-stochastic-mcp');

const result = await client.callTool('generate_gbm', {
  steps: 252,
  timeHorizon: 1.0,
  mu: 0.05,
  sigma: 0.2,
  initialPrice: 100
});
```

[View Complete API →](./mcp-servers/financial-stochastic-mcp/index.html)

## TypeScript Types Reference

### Core Types

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

#### Process Configuration
```typescript
interface StochasticConfig {
  steps: number;
  volatility: number;
  drift: number;
  seed?: number;
}

interface RandomWalkOptions {
  walkType: WalkType;
  dimensions: 1 | 2 | 3;
  stepSize: number;
  boundary?: Boundary;
}
```

#### Chart Data
```typescript
interface ChartData {
  timestamp: number;
  value: number;
  metadata?: Record<string, any>;
}

interface WalkPoint extends Vector2D {
  step: number;
  timestamp: number;
}
```

### Component Props

#### StochasticChart Props
```typescript
interface StochasticChartProps {
  processType?: ProcessType;
  steps?: number;
  volatility?: number;
  drift?: number;
  width?: number;
  height?: number;
  animated?: boolean;
  onDataUpdate?: (data: ChartData[]) => void;
}
```

#### RandomWalkChart Props
```typescript
interface RandomWalkChartProps {
  walkType?: WalkType;
  steps?: number;
  dimensions?: 1 | 2 | 3;
  stepSize?: number;
  boundary?: Boundary;
  animated?: boolean;
  showTrails?: boolean;
  onWalkComplete?: (path: WalkPoint[]) => void;
}
```

### Hook Return Types

#### useStochasticProcess
```typescript
interface StochasticProcessState {
  data: ChartData[];
  isRunning: boolean;
  parameters: StochasticConfig;
  statistics: ProcessStatistics;
  start: () => void;
  stop: () => void;
  reset: () => void;
  updateParameters: (params: Partial<StochasticConfig>) => void;
}
```

#### useRandomWalk
```typescript
interface RandomWalkState {
  path: WalkPoint[];
  currentPosition: Vector2D;
  isWalking: boolean;
  statistics: WalkStatistics;
  start: () => void;
  pause: () => void;
  reset: () => void;
  step: () => void;
}
```

## Documentation Standards

### JSDoc Comments

All public APIs include comprehensive JSDoc comments:

```typescript
/**
 * Generates a geometric Brownian motion path for financial modeling.
 *
 * This function simulates stock price movements using the standard GBM model
 * commonly used in quantitative finance for option pricing and risk analysis.
 *
 * @param config - Configuration parameters for the GBM process
 * @param config.steps - Number of time steps to simulate
 * @param config.timeHorizon - Total time period in years
 * @param config.mu - Annual drift rate (expected return)
 * @param config.sigma - Annual volatility (standard deviation)
 * @param config.initialPrice - Starting price of the asset
 * @param config.seed - Optional random seed for reproducibility
 *
 * @returns Array of price points with timestamps and metadata
 *
 * @example
 * ```typescript
 * const path = generateGBM({
 *   steps: 252,
 *   timeHorizon: 1.0,
 *   mu: 0.08,
 *   sigma: 0.2,
 *   initialPrice: 100
 * });
 *
 * console.log(`Final price: ${path[path.length - 1].value}`);
 * ```
 *
 * @see {@link https://en.wikipedia.org/wiki/Geometric_Brownian_motion | Geometric Brownian Motion}
 * @since 1.0.0
 */
export function generateGBM(config: GBMConfig): ChartData[] {
  // Implementation...
}
```

### Type Documentation

Complex types include detailed descriptions:

```typescript
/**
 * Configuration for stochastic process generation.
 *
 * @public
 */
interface StochasticConfig {
  /** Number of time steps to generate (must be positive) */
  steps: number;

  /** Volatility parameter (typically 0.1 to 0.5 for financial assets) */
  volatility: number;

  /** Drift parameter (annual rate, e.g., 0.05 for 5% annual return) */
  drift: number;

  /**
   * Random seed for reproducible results (optional)
   * @defaultValue undefined (uses system random)
   */
  seed?: number;
}
```

### Component Documentation

React components include usage examples and prop descriptions:

```typescript
/**
 * Interactive chart component for visualizing stochastic processes.
 *
 * Supports multiple process types including Brownian motion, geometric Brownian motion,
 * and Ornstein-Uhlenbeck processes. Provides real-time parameter adjustment and
 * statistical analysis.
 *
 * @param props - Component properties
 *
 * @example
 * Basic usage:
 * ```tsx
 * <StochasticChart
 *   processType="brownian"
 *   steps={1000}
 *   volatility={0.2}
 * />
 * ```
 *
 * @example
 * With event handlers:
 * ```tsx
 * <StochasticChart
 *   processType="geometric-brownian"
 *   onDataUpdate={(data) => console.log('New data:', data)}
 *   onParameterChange={(params) => saveParameters(params)}
 * />
 * ```
 *
 * @public
 */
export function StochasticChart(props: StochasticChartProps): JSX.Element {
  // Implementation...
}
```

## Viewing Documentation

### Local Development

```bash
# Build and serve documentation
npm run docs:build
npm run docs:serve

# Open in browser
open http://localhost:3000/docs/api
```

### Production Deployment

The documentation is automatically built and deployed with each release:

- **Latest**: https://your-domain.com/docs/api/
- **Versioned**: https://your-domain.com/docs/api/v1.2.3/

### Search and Navigation

The generated documentation includes:
- **Full-text search** across all APIs
- **Hierarchical navigation** by package and module
- **Cross-references** between related types and functions
- **Source code links** to GitHub repository

## Contributing to Documentation

### Writing Good JSDoc

1. **Be Descriptive**: Explain what the function does, not just how
2. **Include Examples**: Provide realistic usage examples
3. **Document Parameters**: Describe each parameter's purpose and constraints
4. **Link Related Items**: Use `@see` tags for related functions
5. **Add Since Tags**: Track when APIs were introduced

### Documentation Workflow

1. **Write JSDoc**: Add comprehensive comments to source code
2. **Build Locally**: Test documentation generation
3. **Review Output**: Check rendered documentation for clarity
4. **Commit Changes**: Include documentation updates in PRs
5. **Automated Build**: CI/CD automatically rebuilds documentation

### Quality Standards

- **Coverage**: All public APIs must have JSDoc comments
- **Accuracy**: Documentation must match implementation
- **Examples**: Include working code examples
- **Links**: Maintain valid cross-references
- **Freshness**: Update documentation with code changes

---

This API documentation provides comprehensive reference material for all packages in the monorepo, enabling developers to effectively use and contribute to the codebase.