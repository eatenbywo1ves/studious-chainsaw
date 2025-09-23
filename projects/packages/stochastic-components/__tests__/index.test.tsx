import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import AdvancedMultidimensionalStochasticAnalyzer from '../src/index';

// Mock recharts components to avoid canvas issues in tests
jest.mock('recharts', () => ({
  ResponsiveContainer: ({ children }: any) => <div data-testid="responsive-container">{children}</div>,
  ScatterChart: ({ children }: any) => <div data-testid="scatter-chart">{children}</div>,
  BarChart: ({ children }: any) => <div data-testid="bar-chart">{children}</div>,
  CartesianGrid: () => <div data-testid="cartesian-grid" />,
  XAxis: ({ label }: any) => <div data-testid="x-axis">{label?.value}</div>,
  YAxis: ({ label }: any) => <div data-testid="y-axis">{label?.value}</div>,
  Tooltip: () => <div data-testid="tooltip" />,
  Legend: () => <div data-testid="legend" />,
  Scatter: () => <div data-testid="scatter" />,
  Bar: () => <div data-testid="bar" />,
}));

describe('AdvancedMultidimensionalStochasticAnalyzer', () => {
  beforeEach(() => {
    // Mock Math.random to get predictable test results
    jest.spyOn(Math, 'random').mockReturnValue(0.5);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('renders the main component', () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    expect(screen.getByText('Multidimensional Stochastic Process Analysis Framework')).toBeInTheDocument();
    expect(screen.getByText('Dimensional Configuration Matrix')).toBeInTheDocument();
  });

  test('displays control panel with default selections', () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    // Check default model selection
    const modelSelect = screen.getByDisplayValue('Multidimensional Geometric Brownian Motion');
    expect(modelSelect).toBeInTheDocument();

    // Check default dimension mode
    const dimensionSelect = screen.getByDisplayValue('3D System (XYZ-Space)');
    expect(dimensionSelect).toBeInTheDocument();

    // Check default projection view
    const projectionSelect = screen.getByDisplayValue('XY-Plane Projection');
    expect(projectionSelect).toBeInTheDocument();
  });

  test('allows changing stochastic process model', async () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    const modelSelect = screen.getByRole('combobox', { name: /stochastic process architecture/i });

    fireEvent.change(modelSelect, { target: { value: 'ou' } });

    await waitFor(() => {
      expect(screen.getByText('Multidimensional Ornstein-Uhlenbeck Process')).toBeInTheDocument();
    });
  });

  test('allows changing dimensional mode', async () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    const dimensionSelect = screen.getByRole('combobox', { name: /spatial dimensionality/i });

    fireEvent.change(dimensionSelect, { target: { value: '2D' } });

    await waitFor(() => {
      expect(dimensionSelect).toHaveValue('2D');
    });
  });

  test('allows changing projection view', async () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    const projectionSelect = screen.getByRole('combobox', { name: /visualization projection/i });

    fireEvent.change(projectionSelect, { target: { value: 'xz' } });

    await waitFor(() => {
      expect(projectionSelect).toHaveValue('xz');
      expect(screen.getByText('XZ-Plane Trajectory')).toBeInTheDocument();
    });
  });

  test('renders parameter sliders with correct initial values', () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    // Check for drift parameter slider
    const muSlider = screen.getByDisplayValue('0.05');
    expect(muSlider).toHaveAttribute('type', 'range');
    expect(muSlider).toHaveAttribute('min', '-0.1');
    expect(muSlider).toHaveAttribute('max', '0.3');

    // Check for volatility parameter slider
    const sigmaSlider = screen.getByDisplayValue('0.2');
    expect(sigmaSlider).toHaveAttribute('type', 'range');
    expect(sigmaSlider).toHaveAttribute('min', '0.05');
    expect(sigmaSlider).toHaveAttribute('max', '0.8');
  });

  test('updates parameters when sliders change', async () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    const muSlider = screen.getByDisplayValue('0.05');

    fireEvent.change(muSlider, { target: { value: '0.1' } });

    await waitFor(() => {
      expect(screen.getByText('X-Drift (μₓ): 0.100')).toBeInTheDocument();
    });
  });

  test('renders correlation structure controls', () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    // Check for correlation sliders
    expect(screen.getByText('ρ(X,Y): 0.300')).toBeInTheDocument();
    expect(screen.getByText('ρ(X,Z): 0.100')).toBeInTheDocument();
    expect(screen.getByText('ρ(Y,Z): -0.200')).toBeInTheDocument();
  });

  test('displays model analysis framework', () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    expect(screen.getByText(/Dimensional Analysis:/)).toBeInTheDocument();
    expect(screen.getByText('Mathematical Framework:')).toBeInTheDocument();
    expect(screen.getByText('Application Domain:')).toBeInTheDocument();
  });

  test('renders visualization charts', () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    // Check for chart containers
    expect(screen.getByTestId('responsive-container')).toBeInTheDocument();
    expect(screen.getByTestId('scatter-chart')).toBeInTheDocument();
    expect(screen.getByTestId('bar-chart')).toBeInTheDocument();
  });

  test('displays multidimensional metrics', () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    expect(screen.getByText('Multidimensional Metrics')).toBeInTheDocument();
    expect(screen.getByText(/Portfolio Return:/)).toBeInTheDocument();
    expect(screen.getByText(/Portfolio Vol:/)).toBeInTheDocument();
    expect(screen.getByText(/Portfolio Sharpe:/)).toBeInTheDocument();
  });

  test('renders statistical analysis table', () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    expect(screen.getByText('Multidimensional Statistical Analysis Framework')).toBeInTheDocument();
    expect(screen.getByText('X-Component')).toBeInTheDocument();
    expect(screen.getByText('Y-Component')).toBeInTheDocument();
    expect(screen.getByText('Z-Component')).toBeInTheDocument();
    expect(screen.getByText('Portfolio Aggregate')).toBeInTheDocument();
  });

  test('displays spatial properties analysis', () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    expect(screen.getByText('Dimensional Properties Analysis')).toBeInTheDocument();
    expect(screen.getByText('Correlation Structure Assessment')).toBeInTheDocument();
    expect(screen.getByText(/Max 3D Displacement:/)).toBeInTheDocument();
  });

  test('renders implementation framework insights', () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    expect(screen.getByText('Multidimensional Implementation Framework')).toBeInTheDocument();
    expect(screen.getByText('Computational Complexity Analysis:')).toBeInTheDocument();
    expect(screen.getByText('Statistical Framework:')).toBeInTheDocument();
    expect(screen.getByText('Application Domains:')).toBeInTheDocument();
  });

  test('changes analysis mode when dropdown changes', async () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    const analysisSelect = screen.getByRole('combobox', { name: /analytical framework/i });

    fireEvent.change(analysisSelect, { target: { value: 'correlation' } });

    await waitFor(() => {
      expect(analysisSelect).toHaveValue('correlation');
    });
  });

  test('validates correlation parameter bounds', async () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    const correlationSlider = screen.getByDisplayValue('0.3');

    // Test changing correlation within valid bounds
    fireEvent.change(correlationSlider, { target: { value: '0.8' } });

    await waitFor(() => {
      expect(screen.getByText('ρ(X,Y): 0.800')).toBeInTheDocument();
    });
  });

  test('handles different stochastic models correctly', async () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    const modelSelect = screen.getByRole('combobox', { name: /stochastic process architecture/i });

    // Test each model
    const models = ['gbm', 'ou', 'jump', 'fbm'];

    for (const model of models) {
      fireEvent.change(modelSelect, { target: { value: model } });

      await waitFor(() => {
        expect(modelSelect).toHaveValue(model);
      });
    }
  });

  test('component accessibility', () => {
    render(<AdvancedMultidimensionalStochasticAnalyzer />);

    // Check for proper labeling of form controls
    expect(screen.getByLabelText(/stochastic process architecture/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/spatial dimensionality/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/visualization projection/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/analytical framework/i)).toBeInTheDocument();
  });
});