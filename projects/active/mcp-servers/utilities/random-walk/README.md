# Random Walk MCP Server

A Model Context Protocol (MCP) server for generating and analyzing various types of random walks and stochastic processes. Based on the random walk visualization components from your TSX files.

## Features

### 🚶 Random Walk Types
- **Simple Random Walk**: Uniform step sizes in random directions
- **Biased Random Walk**: Directional preference with bias parameter
- **Levy Flight**: Power-law step size distribution with heavy tails
- **Correlated Random Walk**: Memory of previous direction with correlation parameter

### 📐 Dimensions
- **2D Walks**: Standard planar random walks
- **3D Walks**: Three-dimensional spatial random walks

### 📊 Analysis Capabilities
- End-to-end distance measurement
- Mean squared displacement calculation
- Total path length computation
- Walk efficiency metrics
- Bounding box analysis

## Available Tools

### 1. `generate_simple_walk`
Generate a simple random walk with uniform step sizes.

**Parameters:**
- `steps` (number): Number of steps in the walk (default: 1000)
- `stepSize` (number): Size of each step (default: 1.0)
- `dimensions` (2|3): Number of dimensions (default: 2)

### 2. `generate_biased_walk`
Generate a biased random walk with directional preference.

**Parameters:**
- `steps` (number): Number of steps in the walk (default: 1000)
- `bias` (number): Directional bias parameter (default: 0.1)
- `stepSize` (number): Size of each step (default: 1.0)
- `dimensions` (2|3): Number of dimensions (default: 2)

### 3. `generate_levy_walk`
Generate a Levy flight/walk with power-law step distribution.

**Parameters:**
- `steps` (number): Number of steps in the walk (default: 1000)
- `alpha` (number): Levy exponent, 1 < alpha <= 2 (default: 1.5)
- `stepSize` (number): Base step size scale (default: 1.0)
- `dimensions` (2|3): Number of dimensions (default: 2)

### 4. `generate_correlated_walk`
Generate a correlated random walk with memory of previous direction.

**Parameters:**
- `steps` (number): Number of steps in the walk (default: 1000)
- `correlation` (number): Correlation with previous direction, 0-1 (default: 0.7)
- `stepSize` (number): Size of each step (default: 1.0)
- `dimensions` (2|3): Number of dimensions (default: 2)

### 5. `analyze_walk`
Analyze statistical properties of a random walk path.

**Parameters:**
- `path` (array): Array of path points with x, y, z coordinates

## Installation & Setup

### Prerequisites
- Node.js 18+
- MCP-compatible client

### Quick Start

1. **Install dependencies:**
```bash
npm install
```

2. **Run the server:**
```bash
npm start
```

3. **Test functionality:**
```bash
npm test
```

## MCP Configuration

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "random-walk": {
      "command": "node",
      "args": ["src/index.js"],
      "cwd": "/path/to/random-walk-mcp"
    }
  }
}
```

## Usage Examples

### Simple Random Walk
```javascript
// Generate a basic 2D random walk
const result = await callTool('generate_simple_walk', {
  steps: 1000,
  stepSize: 1.0,
  dimensions: 2
});
```

### Biased Walk
```javascript
// Generate a walk with directional bias
const result = await callTool('generate_biased_walk', {
  steps: 1000,
  bias: 0.3,
  stepSize: 1.0,
  dimensions: 2
});
```

### Levy Flight
```javascript
// Generate a Levy flight with heavy-tailed steps
const result = await callTool('generate_levy_walk', {
  steps: 1000,
  alpha: 1.5,
  stepSize: 1.0,
  dimensions: 2
});
```

## Output Format

Each generation tool returns:
```json
{
  "walkType": "simple|biased|levy|correlated",
  "path": [
    {"x": 0, "y": 0, "z": 0, "step": 0},
    {"x": 1.2, "y": -0.8, "z": 0, "step": 1},
    ...
  ],
  "analysis": {
    "steps": 1000,
    "endDistance": 12.34,
    "meanSquaredDisplacement": 0.152,
    "totalPathLength": 1000.0,
    "efficiency": 0.012,
    "boundingBox": {
      "minX": -15.2, "maxX": 12.4,
      "minY": -10.8, "maxY": 18.6,
      "minZ": -5.2, "maxZ": 3.8
    }
  }
}
```

## Mathematical Background

### Simple Random Walk
Each step follows: `X_{n+1} = X_n + ε_n * stepSize`
where `ε_n` is a unit vector in random direction.

### Biased Random Walk
Direction includes bias: `θ = random() * 2π + bias`

### Levy Flight
Step sizes follow power law: `P(step > s) ~ s^{-α}`

### Correlated Walk
Direction correlates with previous: `θ_{n+1} = ρ * θ_n + (1-ρ) * random()`

## Applications

- **Physics**: Diffusion processes, particle tracking
- **Biology**: Animal movement patterns, cell migration
- **Finance**: Price movement modeling, volatility analysis
- **Computer Science**: Algorithm analysis, network topology
- **Research**: Statistical mechanics, complex systems

## License

MIT License - See LICENSE file for details.

---

Generated from TSX random walk visualization components for defensive research and analysis purposes only.