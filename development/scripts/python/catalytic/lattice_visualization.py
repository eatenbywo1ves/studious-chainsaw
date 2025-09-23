#!/usr/bin/env python3
"""
High-Dimensional Lattice Visualization System
Provides multiple visualization techniques for N-dimensional lattice structures
"""

import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import time
from typing import Tuple, Optional, List, Dict, Any
from dataclasses import dataclass
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
import warnings
warnings.filterwarnings('ignore')

@dataclass
class LatticeConfig:
    """Configuration for lattice generation"""
    dimensions: int
    points_per_dim: int
    lattice_type: str = 'hypercubic'  # hypercubic, triangular, hexagonal
    spacing: float = 1.0
    noise: float = 0.0

class HighDimensionalLatticeVisualizer:
    """
    Visualizes high-dimensional lattices using various projection techniques
    """

    def __init__(self, use_gpu: bool = False):
        """
        Initialize visualizer

        Args:
            use_gpu: Whether to use GPU acceleration (requires CuPy)
        """
        self.use_gpu = use_gpu
        if use_gpu:
            try:
                import cupy as cp
                self.xp = cp
                print("[GPU] Using CuPy for accelerated computations")
            except ImportError:
                print("[CPU] CuPy not available, using NumPy")
                self.xp = np
        else:
            self.xp = np

    def generate_lattice(self, config: LatticeConfig) -> np.ndarray:
        """
        Generate N-dimensional lattice points

        Args:
            config: Lattice configuration

        Returns:
            Array of shape (n_points, dimensions)
        """
        if config.lattice_type == 'hypercubic':
            # Create regular grid
            coords = [np.arange(config.points_per_dim) * config.spacing
                     for _ in range(config.dimensions)]
            grid = np.meshgrid(*coords, indexing='ij')
            points = np.column_stack([g.ravel() for g in grid])

        elif config.lattice_type == 'random':
            # Random points in hypercube
            n_points = config.points_per_dim ** config.dimensions
            points = np.random.rand(min(n_points, 100000), config.dimensions) * \
                    (config.points_per_dim * config.spacing)

        elif config.lattice_type == 'fibonacci':
            # Fibonacci lattice (quasi-random)
            n_points = config.points_per_dim ** 2
            golden_ratio = (1 + np.sqrt(5)) / 2
            points = []
            for i in range(n_points):
                point = []
                for d in range(config.dimensions):
                    val = (i * golden_ratio ** (d+1)) % (config.points_per_dim * config.spacing)
                    point.append(val)
                points.append(point)
            points = np.array(points)

        else:
            raise ValueError(f"Unknown lattice type: {config.lattice_type}")

        # Add noise if specified
        if config.noise > 0:
            points += np.random.randn(*points.shape) * config.noise

        return points

    def reduce_dimensions(self, points: np.ndarray,
                         method: str = 'pca',
                         target_dim: int = 3) -> np.ndarray:
        """
        Reduce dimensionality for visualization

        Args:
            points: High-dimensional points
            method: Reduction method ('pca', 'tsne', 'random')
            target_dim: Target dimensions (2 or 3)

        Returns:
            Reduced points
        """
        n_points, n_dims = points.shape

        if n_dims <= target_dim:
            # Pad with zeros if needed
            if n_dims < target_dim:
                padding = np.zeros((n_points, target_dim - n_dims))
                return np.hstack([points, padding])
            return points

        if method == 'pca':
            pca = PCA(n_components=target_dim)
            reduced = pca.fit_transform(points)
            print(f"  PCA explained variance: {pca.explained_variance_ratio_.sum():.2%}")

        elif method == 'tsne':
            # t-SNE for up to 5000 points
            if n_points > 5000:
                indices = np.random.choice(n_points, 5000, replace=False)
                sample = points[indices]
            else:
                sample = points

            tsne = TSNE(n_components=target_dim, perplexity=30, max_iter=1000)
            reduced = tsne.fit_transform(sample)

            if n_points > 5000:
                # Interpolate remaining points
                print(f"  t-SNE: Sampled {len(sample)} of {n_points} points")
                return reduced[:len(indices)]

        elif method == 'random':
            # Random projection
            projection = np.random.randn(n_dims, target_dim)
            projection /= np.linalg.norm(projection, axis=0)
            reduced = points @ projection

        else:
            raise ValueError(f"Unknown reduction method: {method}")

        return reduced

    def create_3d_scatter(self, points: np.ndarray,
                         colors: Optional[np.ndarray] = None,
                         title: str = "3D Lattice Visualization") -> go.Figure:
        """
        Create interactive 3D scatter plot

        Args:
            points: 3D points
            colors: Color values for points
            title: Plot title

        Returns:
            Plotly figure
        """
        if points.shape[1] != 3:
            raise ValueError("Points must be 3D")

        # Default colors based on distance from origin
        if colors is None:
            colors = np.linalg.norm(points, axis=1)

        fig = go.Figure(data=[go.Scatter3d(
            x=points[:, 0],
            y=points[:, 1],
            z=points[:, 2],
            mode='markers',
            marker=dict(
                size=3,
                color=colors,
                colorscale='Viridis',
                showscale=True,
                colorbar=dict(title="Value"),
                opacity=0.8
            ),
            text=[f"Point {i}" for i in range(len(points))],
            hovertemplate='<b>Point %{text}</b><br>' +
                         'X: %{x:.2f}<br>' +
                         'Y: %{y:.2f}<br>' +
                         'Z: %{z:.2f}<br>' +
                         'Value: %{marker.color:.2f}'
        )])

        fig.update_layout(
            title=title,
            scene=dict(
                xaxis_title="Dimension 1",
                yaxis_title="Dimension 2",
                zaxis_title="Dimension 3",
                camera=dict(
                    eye=dict(x=1.5, y=1.5, z=1.5)
                )
            ),
            width=900,
            height=700
        )

        return fig

    def create_parallel_coordinates(self, points: np.ndarray,
                                   max_dims: int = 10) -> go.Figure:
        """
        Create parallel coordinates plot for high-dimensional data

        Args:
            points: N-dimensional points
            max_dims: Maximum dimensions to display

        Returns:
            Plotly figure
        """
        n_points, n_dims = points.shape

        # Limit dimensions and points for visibility
        dims_to_show = min(n_dims, max_dims)
        points_to_show = min(n_points, 1000)

        if points_to_show < n_points:
            indices = np.random.choice(n_points, points_to_show, replace=False)
            data = points[indices, :dims_to_show]
        else:
            data = points[:, :dims_to_show]

        # Normalize each dimension to [0, 1]
        data_norm = (data - data.min(axis=0)) / (data.max(axis=0) - data.min(axis=0) + 1e-10)

        # Create dimension dict for parallel coordinates
        dimensions = []
        for i in range(dims_to_show):
            dimensions.append(
                dict(
                    label=f'Dim {i+1}',
                    values=data_norm[:, i],
                    range=[0, 1]
                )
            )

        # Color by first dimension
        colors = data_norm[:, 0]

        fig = go.Figure(data=go.Parcoords(
            line=dict(
                color=colors,
                colorscale='Viridis',
                showscale=True
            ),
            dimensions=dimensions
        ))

        fig.update_layout(
            title=f"Parallel Coordinates ({points_to_show} points, {dims_to_show} dims)",
            width=1200,
            height=600
        )

        return fig

    def create_heatmap_projection(self, points: np.ndarray) -> go.Figure:
        """
        Create 2D heatmap projections of high-dimensional data

        Args:
            points: N-dimensional points

        Returns:
            Plotly figure with subplots
        """
        n_points, n_dims = points.shape

        # Create projections for first few dimension pairs
        max_projections = min(6, n_dims * (n_dims - 1) // 2)

        # Calculate subplot grid
        n_cols = 3
        n_rows = (max_projections + n_cols - 1) // n_cols

        fig = make_subplots(
            rows=n_rows,
            cols=n_cols,
            subplot_titles=[f"Dims {i+1} vs {j+1}"
                          for i in range(n_dims)
                          for j in range(i+1, min(i+2, n_dims))
                          if (i * n_dims + j) < max_projections]
        )

        plot_idx = 0
        for i in range(n_dims):
            for j in range(i+1, n_dims):
                if plot_idx >= max_projections:
                    break

                row = plot_idx // n_cols + 1
                col = plot_idx % n_cols + 1

                # Create 2D histogram
                hist, xedges, yedges = np.histogram2d(
                    points[:, i], points[:, j], bins=30
                )

                fig.add_trace(
                    go.Heatmap(
                        z=hist.T,
                        x=xedges,
                        y=yedges,
                        colorscale='Viridis',
                        showscale=plot_idx == 0
                    ),
                    row=row, col=col
                )

                plot_idx += 1

            if plot_idx >= max_projections:
                break

        fig.update_layout(
            title="2D Projections Heatmap",
            height=300 * n_rows,
            width=1200,
            showlegend=False
        )

        return fig

    def create_animated_rotation(self, points: np.ndarray,
                                duration: int = 50) -> go.Figure:
        """
        Create animated 3D rotation of lattice

        Args:
            points: 3D points
            duration: Number of frames

        Returns:
            Animated Plotly figure
        """
        if points.shape[1] != 3:
            points_3d = self.reduce_dimensions(points, method='pca', target_dim=3)
        else:
            points_3d = points

        # Create rotation frames
        frames = []
        for i in range(duration):
            angle = 2 * np.pi * i / duration

            # Rotation matrix around y-axis
            rotation = np.array([
                [np.cos(angle), 0, np.sin(angle)],
                [0, 1, 0],
                [-np.sin(angle), 0, np.cos(angle)]
            ])

            rotated = points_3d @ rotation.T

            frames.append(go.Frame(
                data=[go.Scatter3d(
                    x=rotated[:, 0],
                    y=rotated[:, 1],
                    z=rotated[:, 2],
                    mode='markers',
                    marker=dict(
                        size=3,
                        color=np.linalg.norm(rotated, axis=1),
                        colorscale='Viridis',
                        opacity=0.7
                    )
                )],
                name=str(i)
            ))

        # Initial frame
        fig = go.Figure(
            data=[go.Scatter3d(
                x=points_3d[:, 0],
                y=points_3d[:, 1],
                z=points_3d[:, 2],
                mode='markers',
                marker=dict(
                    size=3,
                    color=np.linalg.norm(points_3d, axis=1),
                    colorscale='Viridis',
                    opacity=0.7
                )
            )],
            frames=frames
        )

        # Add animation controls
        fig.update_layout(
            title="Rotating Lattice View",
            scene=dict(
                xaxis_title="X",
                yaxis_title="Y",
                zaxis_title="Z"
            ),
            updatemenus=[{
                'type': 'buttons',
                'showactive': False,
                'buttons': [
                    {
                        'label': 'Play',
                        'method': 'animate',
                        'args': [None, {
                            'frame': {'duration': 50, 'redraw': True},
                            'fromcurrent': True,
                            'mode': 'immediate'
                        }]
                    },
                    {
                        'label': 'Pause',
                        'method': 'animate',
                        'args': [[None], {
                            'frame': {'duration': 0, 'redraw': False},
                            'mode': 'immediate'
                        }]
                    }
                ]
            }],
            width=900,
            height=700
        )

        return fig

    def visualize_catalytic_transformation(self,
                                          initial_lattice: np.ndarray,
                                          catalyst: np.ndarray,
                                          steps: int = 10) -> go.Figure:
        """
        Visualize catalytic transformation process

        Args:
            initial_lattice: Initial lattice points
            catalyst: Catalyst configuration
            steps: Number of transformation steps

        Returns:
            Animated figure showing transformation
        """
        frames = []

        current = initial_lattice.copy()

        for step in range(steps):
            # Apply catalytic transformation (simplified XOR-like operation)
            if current.shape == catalyst.shape:
                # Direct XOR if same shape
                transformed = current * np.cos(catalyst * step / steps) + \
                            catalyst * np.sin(current * step / steps)
            else:
                # Broadcast transformation
                transformed = current * (1 + 0.1 * np.sin(step / steps * np.pi))

            # Reduce to 3D for visualization
            points_3d = self.reduce_dimensions(transformed, method='pca', target_dim=3)

            frames.append(go.Frame(
                data=[go.Scatter3d(
                    x=points_3d[:, 0],
                    y=points_3d[:, 1],
                    z=points_3d[:, 2],
                    mode='markers',
                    marker=dict(
                        size=4,
                        color=np.linalg.norm(points_3d, axis=1),
                        colorscale='Plasma',
                        opacity=0.8
                    )
                )],
                name=f"Step {step}"
            ))

            current = transformed

        # Create figure with first frame
        points_3d_init = self.reduce_dimensions(initial_lattice, method='pca', target_dim=3)

        fig = go.Figure(
            data=[go.Scatter3d(
                x=points_3d_init[:, 0],
                y=points_3d_init[:, 1],
                z=points_3d_init[:, 2],
                mode='markers',
                marker=dict(
                    size=4,
                    color=np.linalg.norm(points_3d_init, axis=1),
                    colorscale='Plasma',
                    opacity=0.8
                )
            )],
            frames=frames
        )

        # Add slider and buttons
        fig.update_layout(
            title="Catalytic Transformation Visualization",
            scene=dict(
                xaxis_title="PC1",
                yaxis_title="PC2",
                zaxis_title="PC3"
            ),
            updatemenus=[{
                'type': 'buttons',
                'showactive': False,
                'x': 0.1,
                'y': 1.1,
                'buttons': [
                    {
                        'label': 'Play',
                        'method': 'animate',
                        'args': [None, {
                            'frame': {'duration': 500, 'redraw': True},
                            'fromcurrent': True,
                            'transition': {'duration': 300, 'easing': 'cubic-in-out'}
                        }]
                    },
                    {
                        'label': 'Pause',
                        'method': 'animate',
                        'args': [[None], {
                            'frame': {'duration': 0, 'redraw': False},
                            'mode': 'immediate'
                        }]
                    }
                ]
            }],
            sliders=[{
                'steps': [{
                    'args': [[f'Step {i}'], {
                        'frame': {'duration': 300, 'redraw': True},
                        'mode': 'immediate'
                    }],
                    'label': f'{i}',
                    'method': 'animate'
                } for i in range(steps)],
                'active': 0,
                'y': 0,
                'len': 0.9,
                'x': 0.1,
                'xanchor': 'left',
                'y': 0,
                'yanchor': 'top'
            }],
            width=1000,
            height=800
        )

        return fig

def main():
    """Demo of lattice visualization capabilities"""
    print("=" * 70)
    print("HIGH-DIMENSIONAL LATTICE VISUALIZATION SYSTEM")
    print("=" * 70)

    # Initialize visualizer
    viz = HighDimensionalLatticeVisualizer(use_gpu=False)

    # Test 1: 5D Hypercubic Lattice
    print("\n[1] Generating 5D Hypercubic Lattice...")
    config = LatticeConfig(
        dimensions=5,
        points_per_dim=10,
        lattice_type='hypercubic',
        spacing=1.0,
        noise=0.1
    )

    lattice = viz.generate_lattice(config)
    print(f"  Generated {len(lattice)} points in {config.dimensions}D space")

    # Create visualizations
    print("\n[2] Creating Visualizations...")

    # 3D PCA projection
    print("  - PCA projection to 3D")
    points_3d = viz.reduce_dimensions(lattice, method='pca', target_dim=3)
    fig1 = viz.create_3d_scatter(points_3d, title="5D Lattice - PCA Projection")
    fig1.write_html("lattice_3d_pca.html")
    print("    Saved: lattice_3d_pca.html")

    # Parallel coordinates
    print("  - Parallel coordinates plot")
    fig2 = viz.create_parallel_coordinates(lattice)
    fig2.write_html("lattice_parallel.html")
    print("    Saved: lattice_parallel.html")

    # 2D projections heatmap
    print("  - 2D projection heatmaps")
    fig3 = viz.create_heatmap_projection(lattice)
    fig3.write_html("lattice_heatmaps.html")
    print("    Saved: lattice_heatmaps.html")

    # Animated rotation
    print("  - Animated rotation")
    fig4 = viz.create_animated_rotation(points_3d, duration=30)
    fig4.write_html("lattice_rotation.html")
    print("    Saved: lattice_rotation.html")

    # Test 2: Higher dimensional lattice
    print("\n[3] Testing 10D Lattice with t-SNE...")
    config_10d = LatticeConfig(
        dimensions=10,
        points_per_dim=3,  # Reduced from 5 to avoid too many points
        lattice_type='hypercubic'
    )

    lattice_10d = viz.generate_lattice(config_10d)
    print(f"  Generated {len(lattice_10d)} points in 10D")

    # t-SNE visualization
    print("  - Computing t-SNE embedding...")
    points_tsne = viz.reduce_dimensions(lattice_10d, method='tsne', target_dim=3)
    fig5 = viz.create_3d_scatter(points_tsne, title="10D Lattice - t-SNE Projection")
    fig5.write_html("lattice_tsne.html")
    print("    Saved: lattice_tsne.html")

    # Test 3: Catalytic transformation
    print("\n[4] Visualizing Catalytic Transformation...")
    catalyst = np.random.randn(*lattice.shape) * 0.5
    fig6 = viz.visualize_catalytic_transformation(lattice, catalyst, steps=10)
    fig6.write_html("lattice_catalytic.html")
    print("    Saved: lattice_catalytic.html")

    print("\n" + "=" * 70)
    print("VISUALIZATION COMPLETE")
    print("=" * 70)
    print("\nGenerated 6 interactive visualizations:")
    print("  1. lattice_3d_pca.html      - 3D PCA projection")
    print("  2. lattice_parallel.html    - Parallel coordinates")
    print("  3. lattice_heatmaps.html    - 2D projection heatmaps")
    print("  4. lattice_rotation.html    - Animated rotation")
    print("  5. lattice_tsne.html        - t-SNE embedding")
    print("  6. lattice_catalytic.html   - Catalytic transformation")
    print("\nOpen these files in a web browser to interact with the visualizations!")

if __name__ == "__main__":
    main()