# @monorepo/stochastic-components

React components for multidimensional stochastic process visualization and analysis.

## Overview

This package provides a comprehensive set of React components for visualizing and interacting with stochastic processes, including Brownian motion, geometric Brownian motion, and custom multidimensional processes. Built with React 19, TypeScript, and optimized for performance.

## Installation

```bash
# Install in the monorepo
npm install

# Use in external projects
npm install @monorepo/stochastic-components
```

## Quick Start

```tsx
import React from 'react';
import {
  StochasticChart,
  MultidimensionalVisualizer,
  ProcessControls
} from '@monorepo/stochastic-components';

function App() {
  return (
    <div>
      <h1>Stochastic Process Visualization</h1>
      <StochasticChart
        processType="brownian"
        steps={1000}
        dimensions={2}
        volatility={0.2}
        drift={0.05}
      />
    </div>
  );
}
```

## Components

### StochasticChart

Interactive chart for visualizing stochastic processes with real-time updates.

```tsx
import { StochasticChart } from '@monorepo/stochastic-components';

<StochasticChart
  processType="geometric-brownian"
  steps={1000}
  volatility={0.3}
  drift={0.1}
  initialValue={100}
  width={800}
  height={400}
  onDataUpdate={(data) => console.log('New data:', data)}
/>
```

#### Props
| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `processType` | `'brownian' \| 'geometric-brownian' \| 'ornstein-uhlenbeck'` | `'brownian'` | Type of stochastic process |
| `steps` | `number` | `1000` | Number of simulation steps |
| `volatility` | `number` | `0.2` | Process volatility parameter |
| `drift` | `number` | `0.0` | Drift parameter |
| `initialValue` | `number` | `0` | Starting value |
| `width` | `number` | `600` | Chart width in pixels |
| `height` | `number` | `400` | Chart height in pixels |
| `seed` | `number` | `undefined` | Random seed for reproducibility |
| `onDataUpdate` | `(data: ChartData[]) => void` | `undefined` | Callback for data updates |

### MultidimensionalVisualizer

3D visualization component for multidimensional stochastic processes.

```tsx
import { MultidimensionalVisualizer } from '@monorepo/stochastic-components';

<MultidimensionalVisualizer
  dimensions={3}
  steps={500}
  particleCount={10}
  colorScheme="viridis"
  showTrails={true}
  enableRotation={true}
/>
```

#### Props
| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `dimensions` | `2 \| 3 \| 4` | `3` | Number of dimensions |
| `steps` | `number` | `500` | Simulation steps |
| `particleCount` | `number` | `1` | Number of particles |
| `colorScheme` | `string` | `'default'` | Color scheme for visualization |
| `showTrails` | `boolean` | `true` | Show particle trails |
| `enableRotation` | `boolean` | `true` | Enable 3D rotation |

### ProcessControls

Control panel for adjusting process parameters in real-time.

```tsx
import { ProcessControls } from '@monorepo/stochastic-components';

<ProcessControls
  processType="brownian"
  onParameterChange={(params) => updateProcess(params)}
  showAdvanced={true}
  presets={['conservative', 'moderate', 'aggressive']}
/>
```

#### Props
| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `processType` | `ProcessType` | `'brownian'` | Current process type |
| `onParameterChange` | `(params: ProcessParameters) => void` | Required | Parameter change callback |
| `showAdvanced` | `boolean` | `false` | Show advanced controls |
| `presets` | `string[]` | `[]` | Available parameter presets |

### HeatmapVisualizer

Display correlation heatmaps for multidimensional processes.

```tsx
import { HeatmapVisualizer } from '@monorepo/stochastic-components';

<HeatmapVisualizer
  data={correlationMatrix}
  labels={['X', 'Y', 'Z']}
  colorScheme="RdBu"
  showValues={true}
  interactive={true}
/>
```

### StatisticsPanel

Real-time statistics display for process metrics.

```tsx
import { StatisticsPanel } from '@monorepo/stochastic-components';

<StatisticsPanel
  data={processData}
  metrics={['mean', 'variance', 'skewness', 'kurtosis']}
  refreshInterval={1000}
  showHistogram={true}
/>
```

## Hooks

### useStochasticProcess

Custom hook for managing stochastic process state and simulation.

```tsx
import { useStochasticProcess } from '@monorepo/stochastic-components';

function MyComponent() {
  const {
    data,
    isRunning,
    parameters,
    start,
    stop,
    reset,
    updateParameters
  } = useStochasticProcess({
    processType: 'brownian',
    steps: 1000,
    autoStart: true
  });

  return (
    <div>
      <button onClick={isRunning ? stop : start}>
        {isRunning ? 'Stop' : 'Start'}
      </button>
      <button onClick={reset}>Reset</button>
    </div>
  );
}
```

### useRealTimeData

Hook for streaming real-time data updates.

```tsx
import { useRealTimeData } from '@monorepo/stochastic-components';

function RealTimeChart() {
  const { data, isConnected, error } = useRealTimeData({
    endpoint: '/api/stochastic-stream',
    bufferSize: 1000,
    updateInterval: 100
  });

  if (error) return <div>Error: {error.message}</div>;
  if (!isConnected) return <div>Connecting...</div>;

  return <StochasticChart data={data} />;
}
```

## Advanced Usage

### Custom Process Implementation

```tsx
import { createCustomProcess } from '@monorepo/stochastic-components';

const customProcess = createCustomProcess({
  name: 'jump-diffusion',
  generator: (params) => {
    // Custom process logic
    return generateJumpDiffusionPath(params);
  },
  defaultParams: {
    jumpIntensity: 0.1,
    jumpSize: 0.05,
    volatility: 0.2
  }
});

<StochasticChart processType={customProcess} />
```

### Performance Optimization

```tsx
import {
  StochasticChart,
  useWebWorkerSimulation
} from '@monorepo/stochastic-components';

function HighPerformanceChart() {
  const { data, isComputing } = useWebWorkerSimulation({
    processType: 'brownian',
    steps: 100000, // Large dataset
    workerCount: 4  // Parallel processing
  });

  return (
    <StochasticChart
      data={data}
      virtualizeData={true}    // Virtualize large datasets
      useMemoization={true}    // Cache expensive calculations
      reducedMotion={false}    // Full animations
    />
  );
}
```

### Integration with External Libraries

```tsx
import { StochasticChart } from '@monorepo/stochastic-components';
import * as d3 from 'd3';

function D3IntegratedChart() {
  const customRenderer = useCallback((data, container) => {
    // Custom D3 rendering logic
    const svg = d3.select(container);
    // ... D3 implementation
  }, []);

  return (
    <StochasticChart
      customRenderer={customRenderer}
      renderingEngine="d3"
    />
  );
}
```

## Theming

### CSS Custom Properties

```css
:root {
  --stochastic-primary-color: #0066cc;
  --stochastic-secondary-color: #6c757d;
  --stochastic-background-color: #ffffff;
  --stochastic-grid-color: #e9ecef;
  --stochastic-text-color: #333333;
  --stochastic-border-radius: 4px;
  --stochastic-font-family: 'Inter', sans-serif;
}
```

### Theme Provider

```tsx
import { ThemeProvider } from '@monorepo/stochastic-components';

const customTheme = {
  colors: {
    primary: '#ff6b6b',
    secondary: '#4ecdc4',
    background: '#fafafa'
  },
  fonts: {
    body: 'Roboto, sans-serif',
    mono: 'Fira Code, monospace'
  }
};

function App() {
  return (
    <ThemeProvider theme={customTheme}>
      <StochasticChart />
    </ThemeProvider>
  );
}
```

## Testing

### Component Testing

```tsx
import { render, screen } from '@testing-library/react';
import { StochasticChart } from '@monorepo/stochastic-components';

test('renders stochastic chart with correct data', () => {
  render(
    <StochasticChart
      processType="brownian"
      steps={100}
      data-testid="stochastic-chart"
    />
  );

  expect(screen.getByTestId('stochastic-chart')).toBeInTheDocument();
});
```

### Simulation Testing

```tsx
import { generateBrownianMotion } from '@monorepo/stochastic-components';

test('generates correct number of data points', () => {
  const data = generateBrownianMotion({ steps: 1000, seed: 42 });
  expect(data).toHaveLength(1000);
});
```

## Performance Considerations

### Optimization Strategies

1. **Virtualization**: Large datasets use virtual scrolling
2. **Web Workers**: Heavy computations run in background threads
3. **Memoization**: Expensive calculations are cached
4. **RAF Throttling**: Animations use requestAnimationFrame
5. **Bundle Splitting**: Code splitting for better loading

### Memory Management

```tsx
import { StochasticChart } from '@monorepo/stochastic-components';

function MemoryEfficientChart() {
  return (
    <StochasticChart
      maxDataPoints={10000}      // Limit data retention
      gcInterval={30000}         // Garbage collection interval
      useOffscreenCanvas={true}  // Offscreen rendering
    />
  );
}
```

## API Reference

### Types

```typescript
interface ProcessParameters {
  steps: number;
  volatility: number;
  drift: number;
  initialValue?: number;
  seed?: number;
}

interface ChartData {
  timestamp: number;
  value: number;
  metadata?: Record<string, any>;
}

type ProcessType =
  | 'brownian'
  | 'geometric-brownian'
  | 'ornstein-uhlenbeck'
  | 'jump-diffusion'
  | 'custom';
```

### Utilities

```typescript
// Process generators
function generateBrownianMotion(params: ProcessParameters): ChartData[];
function generateGeometricBrownianMotion(params: ProcessParameters): ChartData[];

// Statistical functions
function calculateMean(data: number[]): number;
function calculateVolatility(data: number[]): number;
function calculateCorrelation(x: number[], y: number[]): number;

// Visualization helpers
function createColorScale(data: number[], scheme: string): (value: number) => string;
function formatDataForChart(data: ChartData[]): ChartData[];
```

## Migration Guide

### From v1.x to v2.x

1. **Component Props**: Some prop names have changed for consistency
2. **Hook APIs**: Updated hook signatures for better TypeScript support
3. **Theming**: New theme provider with CSS custom properties
4. **Performance**: Automatic optimization features enabled by default

### Breaking Changes

- `StochasticChart.onUpdate` renamed to `onDataUpdate`
- `ProcessControls.onChange` renamed to `onParameterChange`
- Removed deprecated `SimpleChart` component
- Updated minimum React version to 19.0.0

## Contributing

1. Follow the [monorepo guidelines](../../CONTRIBUTING.md)
2. Add Storybook stories for new components
3. Include comprehensive tests
4. Update documentation for API changes
5. Test with multiple React versions

## Roadmap

- **WebGL Renderer**: GPU-accelerated visualization
- **Real-time Streaming**: WebSocket integration
- **Machine Learning**: Predictive modeling features
- **Mobile Support**: React Native compatibility
- **Accessibility**: Full WCAG 2.1 compliance

## License

MIT License - see the [LICENSE](../../LICENSE) file for details.