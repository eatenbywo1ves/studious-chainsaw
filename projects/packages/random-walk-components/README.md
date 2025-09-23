# @monorepo/random-walk-components

React components for random walk analysis, visualization, and interactive exploration.

## Overview

A specialized component library for creating interactive random walk visualizations. Features multiple random walk algorithms, real-time path generation, statistical analysis, and educational tools for understanding stochastic processes.

## Installation

```bash
# Install in the monorepo
npm install

# Use in external projects
npm install @monorepo/random-walk-components
```

## Quick Start

```tsx
import React from 'react';
import {
  RandomWalkChart,
  PathComparison,
  WalkStatistics
} from '@monorepo/random-walk-components';

function App() {
  return (
    <div>
      <h1>Random Walk Analysis</h1>
      <RandomWalkChart
        steps={1000}
        dimensions={2}
        stepSize={1}
        animated={true}
      />
    </div>
  );
}
```

## Core Components

### RandomWalkChart

Primary component for visualizing random walk paths with interactive controls.

```tsx
import { RandomWalkChart } from '@monorepo/random-walk-components';

<RandomWalkChart
  walkType="simple"
  steps={1000}
  dimensions={2}
  stepSize={1}
  boundary={{ min: { x: -50, y: -50 }, max: { x: 50, y: 50 } }}
  showGrid={true}
  showTrails={true}
  animationSpeed="normal"
  onWalkComplete={(path) => console.log('Walk completed:', path)}
/>
```

#### Props
| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `walkType` | `WalkType` | `'simple'` | Type of random walk algorithm |
| `steps` | `number` | `1000` | Number of steps in the walk |
| `dimensions` | `1 \| 2 \| 3` | `2` | Spatial dimensions |
| `stepSize` | `number` | `1` | Size of each step |
| `boundary` | `Boundary` | `undefined` | Optional boundary constraints |
| `showGrid` | `boolean` | `true` | Display coordinate grid |
| `showTrails` | `boolean` | `true` | Show walk trail |
| `animated` | `boolean` | `true` | Enable step-by-step animation |
| `animationSpeed` | `Speed` | `'normal'` | Animation playback speed |

### PathComparison

Compare multiple random walk paths side-by-side with statistical overlays.

```tsx
import { PathComparison } from '@monorepo/random-walk-components';

<PathComparison
  walks={[
    { id: 'walk1', steps: 1000, seed: 42, color: '#ff6b6b' },
    { id: 'walk2', steps: 1000, seed: 123, color: '#4ecdc4' },
    { id: 'walk3', steps: 1000, seed: 456, color: '#45b7d1' }
  ]}
  showStatistics={true}
  showConfidenceIntervals={true}
  comparisonMetric="displacement"
/>
```

#### Props
| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `walks` | `WalkConfig[]` | Required | Array of walk configurations |
| `showStatistics` | `boolean` | `true` | Display statistical summaries |
| `showConfidenceIntervals` | `boolean` | `false` | Show confidence bands |
| `comparisonMetric` | `Metric` | `'displacement'` | Primary comparison metric |
| `syncAnimation` | `boolean` | `true` | Synchronize walk animations |

### WalkStatistics

Real-time statistical analysis panel for random walk properties.

```tsx
import { WalkStatistics } from '@monorepo/random-walk-components';

<WalkStatistics
  walkData={pathData}
  metrics={['displacement', 'variance', 'meanSquareDisplacement']}
  showHistograms={true}
  updateInterval={100}
  exportData={true}
/>
```

### InteractiveWalkBuilder

Educational component for building custom random walk algorithms.

```tsx
import { InteractiveWalkBuilder } from '@monorepo/random-walk-components';

<InteractiveWalkBuilder
  onWalkCreate={(algorithm) => setCustomWalk(algorithm)}
  prebuiltAlgorithms={['simple', 'biased', 'levy-flight']}
  showCodePreview={true}
  enableTesting={true}
/>
```

### WalkPlayground

Comprehensive playground environment for experimenting with random walks.

```tsx
import { WalkPlayground } from '@monorepo/random-walk-components';

<WalkPlayground
  initialConfig={{
    walkType: 'simple',
    steps: 500,
    dimensions: 2
  }}
  showControls={true}
  showCode={true}
  exportFormats={['json', 'csv', 'png']}
/>
```

## Random Walk Algorithms

### Simple Random Walk
- **Description**: Basic random walk with equal probability steps
- **Parameters**: Step size, boundary conditions
- **Use Cases**: Educational demonstrations, baseline comparisons

```tsx
<RandomWalkChart walkType="simple" stepSize={1} />
```

### Biased Random Walk
- **Description**: Random walk with directional bias
- **Parameters**: Bias vector, bias strength
- **Use Cases**: Modeling directed motion with noise

```tsx
<RandomWalkChart
  walkType="biased"
  bias={{ x: 0.1, y: 0.05 }}
  biasStrength={0.3}
/>
```

### Levy Flight
- **Description**: Random walk with heavy-tailed step distribution
- **Parameters**: Alpha parameter, scale factor
- **Use Cases**: Modeling animal foraging, financial markets

```tsx
<RandomWalkChart
  walkType="levy-flight"
  alpha={1.5}
  scale={2.0}
/>
```

### Correlated Random Walk
- **Description**: Steps correlated with previous direction
- **Parameters**: Correlation coefficient, turning angle distribution
- **Use Cases**: Animal movement, particle physics

```tsx
<RandomWalkChart
  walkType="correlated"
  correlation={0.7}
  turningAngleDistribution="vonmises"
/>
```

### Self-Avoiding Walk
- **Description**: Random walk that cannot revisit previous positions
- **Parameters**: Memory length, avoidance strength
- **Use Cases**: Polymer modeling, path planning

```tsx
<RandomWalkChart
  walkType="self-avoiding"
  memoryLength={100}
  avoidanceStrength={1.0}
/>
```

## Hooks

### useRandomWalk

Core hook for generating and managing random walk state.

```tsx
import { useRandomWalk } from '@monorepo/random-walk-components';

function MyWalkComponent() {
  const {
    path,
    currentPosition,
    isWalking,
    statistics,
    start,
    pause,
    reset,
    step
  } = useRandomWalk({
    walkType: 'simple',
    steps: 1000,
    stepSize: 1,
    autoStart: false
  });

  return (
    <div>
      <button onClick={start}>Start Walk</button>
      <button onClick={pause}>Pause</button>
      <button onClick={step}>Single Step</button>
      <button onClick={reset}>Reset</button>
      <div>Current position: {currentPosition.x}, {currentPosition.y}</div>
      <div>Steps taken: {path.length}</div>
    </div>
  );
}
```

### useWalkAnimation

Hook for controlling walk animation playback.

```tsx
import { useWalkAnimation } from '@monorepo/random-walk-components';

function AnimatedWalk() {
  const {
    animatedPath,
    isPlaying,
    currentStep,
    speed,
    play,
    pause,
    setSpeed,
    jumpToStep
  } = useWalkAnimation(fullPath, {
    autoPlay: true,
    speed: 'normal',
    loop: false
  });

  return (
    <div>
      <RandomWalkChart path={animatedPath} />
      <div>
        <button onClick={isPlaying ? pause : play}>
          {isPlaying ? 'Pause' : 'Play'}
        </button>
        <input
          type="range"
          min={0}
          max={fullPath.length}
          value={currentStep}
          onChange={(e) => jumpToStep(parseInt(e.target.value))}
        />
        <select onChange={(e) => setSpeed(e.target.value)}>
          <option value="slow">Slow</option>
          <option value="normal">Normal</option>
          <option value="fast">Fast</option>
        </select>
      </div>
    </div>
  );
}
```

### useWalkStatistics

Hook for calculating real-time walk statistics.

```tsx
import { useWalkStatistics } from '@monorepo/random-walk-components';

function StatisticsDisplay({ path }) {
  const stats = useWalkStatistics(path, {
    metrics: ['displacement', 'variance', 'autocorrelation'],
    updateInterval: 500,
    smoothing: true
  });

  return (
    <div>
      <div>Displacement: {stats.displacement.toFixed(2)}</div>
      <div>Variance: {stats.variance.toFixed(2)}</div>
      <div>Autocorrelation: {stats.autocorrelation.toFixed(3)}</div>
    </div>
  );
}
```

## Advanced Features

### Custom Walk Algorithms

```tsx
import { createWalkAlgorithm } from '@monorepo/random-walk-components';

const quantumWalk = createWalkAlgorithm({
  name: 'quantum-walk',
  generator: function* (config) {
    let position = { x: 0, y: 0 };
    let phase = 0;

    for (let i = 0; i < config.steps; i++) {
      // Quantum walk logic
      const probability = Math.cos(phase) ** 2;
      const direction = Math.random() < probability ? 1 : -1;

      position.x += direction * config.stepSize;
      phase += config.phaseIncrement || Math.PI / 4;

      yield { ...position, step: i, phase };
    }
  },
  defaultConfig: {
    stepSize: 1,
    phaseIncrement: Math.PI / 4
  }
});

<RandomWalkChart walkType={quantumWalk} />
```

### Boundary Conditions

```tsx
import { createBoundary } from '@monorepo/random-walk-components';

const reflectiveBoundary = createBoundary({
  type: 'reflective',
  shape: 'circle',
  center: { x: 0, y: 0 },
  radius: 50,
  onBoundaryHit: (position, direction) => {
    // Custom reflection logic
    return reflectDirection(position, direction);
  }
});

<RandomWalkChart
  boundary={reflectiveBoundary}
  showBoundary={true}
/>
```

### Data Export and Analysis

```tsx
import {
  exportWalkData,
  analyzeWalkProperties,
  generateReport
} from '@monorepo/random-walk-components';

function WalkAnalyzer({ walks }) {
  const handleExport = () => {
    const data = exportWalkData(walks, {
      format: 'csv',
      includeStatistics: true,
      includeMetadata: true
    });
    downloadFile(data, 'walk-analysis.csv');
  };

  const analysis = analyzeWalkProperties(walks);
  const report = generateReport(analysis, {
    includeGraphs: true,
    format: 'html'
  });

  return (
    <div>
      <button onClick={handleExport}>Export Data</button>
      <div dangerouslySetInnerHTML={{ __html: report }} />
    </div>
  );
}
```

## Educational Features

### Step-by-Step Tutorial

```tsx
import { WalkTutorial } from '@monorepo/random-walk-components';

<WalkTutorial
  steps={[
    {
      title: "Introduction to Random Walks",
      content: "A random walk is a mathematical formalization...",
      interactive: true,
      demo: { walkType: 'simple', steps: 50 }
    },
    {
      title: "Understanding Bias",
      content: "When we introduce bias to a random walk...",
      demo: { walkType: 'biased', bias: { x: 0.1, y: 0 } }
    }
  ]}
  showProgress={true}
  allowSkip={true}
/>
```

### Interactive Exercises

```tsx
import { WalkExercise } from '@monorepo/random-walk-components';

<WalkExercise
  title="Predict the Final Position"
  description="Given the parameters below, predict where the walk will end"
  challenge={{
    walkType: 'biased',
    steps: 100,
    bias: { x: 0.05, y: -0.02 }
  }}
  onAnswer={(prediction, actual) => {
    const accuracy = calculateAccuracy(prediction, actual);
    showFeedback(accuracy);
  }}
/>
```

## Theming and Customization

### CSS Custom Properties

```css
:root {
  /* Walk visualization */
  --walk-path-color: #0066cc;
  --walk-path-width: 2px;
  --walk-point-size: 4px;
  --walk-current-position-color: #ff6b6b;

  /* Grid and axes */
  --walk-grid-color: #e9ecef;
  --walk-axes-color: #333333;
  --walk-grid-size: 10px;

  /* Animation */
  --walk-animation-duration: 2s;
  --walk-animation-easing: ease-in-out;

  /* Statistics */
  --walk-stats-background: #f8f9fa;
  --walk-stats-border: #dee2e6;
  --walk-stats-text: #495057;
}
```

### Theme Provider

```tsx
import { WalkThemeProvider } from '@monorepo/random-walk-components';

const darkTheme = {
  colors: {
    background: '#1a1a1a',
    path: '#00ff88',
    grid: '#333333',
    text: '#ffffff'
  },
  animation: {
    speed: 0.5,
    easing: 'cubic-bezier(0.4, 0, 0.2, 1)'
  }
};

function App() {
  return (
    <WalkThemeProvider theme={darkTheme}>
      <RandomWalkChart />
    </WalkThemeProvider>
  );
}
```

## Performance Optimization

### Large Dataset Handling

```tsx
import { RandomWalkChart } from '@monorepo/random-walk-components';

<RandomWalkChart
  steps={100000}                    // Large dataset
  virtualizeRendering={true}        // Render only visible portion
  downsampleThreshold={10000}       // Downsample when needed
  useWebWorker={true}              // Offload calculations
  memoryLimit="100MB"              // Memory management
/>
```

### Animation Performance

```tsx
<RandomWalkChart
  useCanvas={true}                 // Canvas rendering for performance
  animationBatchSize={10}          // Batch animation updates
  frameRateLimit={60}              // Limit frame rate
  reducedMotion={window.matchMedia('(prefers-reduced-motion: reduce)').matches}
/>
```

## API Reference

### Types

```typescript
interface WalkConfig {
  walkType: WalkType;
  steps: number;
  dimensions: 1 | 2 | 3;
  stepSize: number;
  seed?: number;
  boundary?: Boundary;
}

interface WalkPoint {
  x: number;
  y: number;
  z?: number;
  step: number;
  timestamp: number;
}

interface WalkStatistics {
  displacement: number;
  variance: number;
  meanSquareDisplacement: number;
  autocorrelation: number[];
  boundingBox: BoundingBox;
}

type WalkType =
  | 'simple'
  | 'biased'
  | 'levy-flight'
  | 'correlated'
  | 'self-avoiding'
  | 'quantum';
```

### Utility Functions

```typescript
// Walk generation
function generateRandomWalk(config: WalkConfig): WalkPoint[];
function generateMultipleWalks(configs: WalkConfig[]): WalkPoint[][];

// Statistical analysis
function calculateDisplacement(path: WalkPoint[]): number;
function calculateMSD(path: WalkPoint[]): number[];
function calculateAutocorrelation(path: WalkPoint[], maxLag: number): number[];

// Visualization helpers
function pathToSVG(path: WalkPoint[], options: SVGOptions): string;
function createWalkAnimation(path: WalkPoint[], duration: number): Animation;
```

## Testing

### Component Testing

```tsx
import { render, screen, waitFor } from '@testing-library/react';
import { RandomWalkChart } from '@monorepo/random-walk-components';

test('generates correct number of steps', async () => {
  render(<RandomWalkChart steps={100} animated={false} />);

  await waitFor(() => {
    const pathElement = screen.getByTestId('walk-path');
    expect(pathElement).toHaveAttribute('data-steps', '100');
  });
});
```

### Algorithm Testing

```tsx
import { generateRandomWalk } from '@monorepo/random-walk-components';

test('simple random walk returns to origin on average', () => {
  const walks = Array.from({ length: 1000 }, () =>
    generateRandomWalk({ walkType: 'simple', steps: 100, seed: Math.random() })
  );

  const avgDisplacement = walks.reduce((sum, walk) => {
    const finalPosition = walk[walk.length - 1];
    return sum + Math.sqrt(finalPosition.x ** 2 + finalPosition.y ** 2);
  }, 0) / walks.length;

  expect(avgDisplacement).toBeLessThan(10); // Should be close to origin
});
```

## Migration Guide

### From v1.x to v2.x

1. **Component Names**: Some components renamed for consistency
2. **Prop Changes**: Updated prop interfaces for better TypeScript support
3. **Hook APIs**: New hook signatures with improved error handling
4. **Performance**: Automatic virtualization for large datasets

### Breaking Changes

- `RandomWalk` component renamed to `RandomWalkChart`
- `onStepComplete` prop removed in favor of `onWalkUpdate`
- Removed deprecated `SimpleWalk` component
- Updated minimum React version to 19.0.0

## Contributing

1. Follow the [monorepo guidelines](../../CONTRIBUTING.md)
2. Add comprehensive tests for new algorithms
3. Include educational documentation
4. Test with various parameter ranges
5. Consider performance implications

## Roadmap

- **3D Visualization**: Enhanced three-dimensional walk rendering
- **Machine Learning**: Pattern recognition in walk behavior
- **Real-time Collaboration**: Multi-user walk exploration
- **VR/AR Support**: Immersive walk visualization
- **Educational Games**: Gamified learning experiences

## License

MIT License - see the [LICENSE](../../LICENSE) file for details.