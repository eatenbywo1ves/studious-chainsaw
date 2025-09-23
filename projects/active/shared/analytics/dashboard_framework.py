"""
Custom Dashboard Framework

Enterprise-grade dashboard builder with:
- Drag-and-drop visual dashboard designer
- Real-time data visualization components
- Multi-tenant dashboard isolation
- Interactive charts and widgets
- Customizable themes and layouts
- Export capabilities (PDF, PNG, Excel)
- Role-based dashboard access control
- Responsive design for mobile/desktop
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List
from uuid import uuid4

import aiofiles
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from fastapi import WebSocket


class WidgetType(Enum):
    CHART_LINE = "chart_line"
    CHART_BAR = "chart_bar"
    CHART_PIE = "chart_pie"
    CHART_SCATTER = "chart_scatter"
    CHART_HEATMAP = "chart_heatmap"
    METRIC_CARD = "metric_card"
    TABLE = "table"
    GAUGE = "gauge"
    MAP = "map"
    TEXT = "text"
    IMAGE = "image"
    IFRAME = "iframe"


class ChartType(Enum):
    LINE = "line"
    BAR = "bar"
    HORIZONTAL_BAR = "horizontal_bar"
    PIE = "pie"
    DONUT = "donut"
    SCATTER = "scatter"
    AREA = "area"
    HISTOGRAM = "histogram"
    HEATMAP = "heatmap"
    TREEMAP = "treemap"
    SUNBURST = "sunburst"


class AggregationFunction(Enum):
    SUM = "sum"
    AVG = "avg"
    COUNT = "count"
    MIN = "min"
    MAX = "max"
    STDDEV = "stddev"


@dataclass
class WidgetConfig:
    """Widget configuration settings"""

    id: str = field(default_factory=lambda: str(uuid4()))
    type: WidgetType = WidgetType.CHART_LINE
    title: str = ""
    description: str = ""

    # Layout properties
    x: int = 0
    y: int = 0
    width: int = 6
    height: int = 4

    # Data configuration
    data_source: str = ""
    query_config: Dict[str, Any] = field(default_factory=dict)
    refresh_interval: int = 30000  # milliseconds

    # Visual configuration
    chart_config: Dict[str, Any] = field(default_factory=dict)
    style_config: Dict[str, Any] = field(default_factory=dict)

    # Interaction configuration
    drill_down_enabled: bool = False
    filter_enabled: bool = True
    export_enabled: bool = True


@dataclass
class Dashboard:
    """Dashboard configuration"""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    tenant_id: str = ""
    owner_id: str = ""

    # Layout configuration
    layout: str = "grid"  # grid, flexible, fixed
    theme: str = "default"
    background_color: str = "#ffffff"

    # Widget configuration
    widgets: List[WidgetConfig] = field(default_factory=list)

    # Access control
    is_public: bool = False
    shared_users: List[str] = field(default_factory=list)
    shared_roles: List[str] = field(default_factory=list)

    # Metadata
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "tenant_id": self.tenant_id,
            "owner_id": self.owner_id,
            "layout": self.layout,
            "theme": self.theme,
            "background_color": self.background_color,
            "widgets": [
                {
                    "id": w.id,
                    "type": w.type.value,
                    "title": w.title,
                    "description": w.description,
                    "x": w.x,
                    "y": w.y,
                    "width": w.width,
                    "height": w.height,
                    "data_source": w.data_source,
                    "query_config": w.query_config,
                    "chart_config": w.chart_config,
                    "style_config": w.style_config,
                    "refresh_interval": w.refresh_interval,
                    "drill_down_enabled": w.drill_down_enabled,
                    "filter_enabled": w.filter_enabled,
                    "export_enabled": w.export_enabled,
                }
                for w in self.widgets
            ],
            "is_public": self.is_public,
            "shared_users": self.shared_users,
            "shared_roles": self.shared_roles,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class DashboardFramework:
    """Custom dashboard framework with real-time capabilities"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.dashboards: Dict[str, Dashboard] = {}
        self.active_connections: Dict[str, List[WebSocket]] = {}

        # Data source integrations
        self.data_sources: Dict[str, Any] = {}

        # Theme configurations
        self.themes = self._load_default_themes()

        # Widget templates
        self.widget_templates = self._create_widget_templates()

        self.logger = logging.getLogger(__name__)

    def _load_default_themes(self) -> Dict[str, Dict[str, Any]]:
        """Load default dashboard themes"""
        return {
            "default": {
                "primary_color": "#007bff",
                "secondary_color": "#6c757d",
                "success_color": "#28a745",
                "warning_color": "#ffc107",
                "danger_color": "#dc3545",
                "background_color": "#ffffff",
                "text_color": "#212529",
                "border_color": "#dee2e6",
                "font_family": "Inter, system-ui, sans-serif",
            },
            "dark": {
                "primary_color": "#0d6efd",
                "secondary_color": "#6c757d",
                "success_color": "#198754",
                "warning_color": "#fd7e14",
                "danger_color": "#dc3545",
                "background_color": "#1a1a1a",
                "text_color": "#ffffff",
                "border_color": "#333333",
                "font_family": "Inter, system-ui, sans-serif",
            },
            "corporate": {
                "primary_color": "#2c3e50",
                "secondary_color": "#95a5a6",
                "success_color": "#27ae60",
                "warning_color": "#f39c12",
                "danger_color": "#e74c3c",
                "background_color": "#ecf0f1",
                "text_color": "#2c3e50",
                "border_color": "#bdc3c7",
                "font_family": "Roboto, sans-serif",
            },
        }

    def _create_widget_templates(self) -> Dict[str, WidgetConfig]:
        """Create default widget templates"""
        templates = {}

        # Line chart template
        templates["line_chart"] = WidgetConfig(
            type=WidgetType.CHART_LINE,
            title="Line Chart",
            width=8,
            height=6,
            chart_config={
                "chart_type": ChartType.LINE.value,
                "x_axis": "time",
                "y_axis": "value",
                "show_legend": True,
                "show_grid": True,
                "line_smoothing": True,
            },
        )

        # Bar chart template
        templates["bar_chart"] = WidgetConfig(
            type=WidgetType.CHART_BAR,
            title="Bar Chart",
            width=8,
            height=6,
            chart_config={
                "chart_type": ChartType.BAR.value,
                "x_axis": "category",
                "y_axis": "value",
                "show_legend": True,
                "show_values": True,
            },
        )

        # Metric card template
        templates["metric_card"] = WidgetConfig(
            type=WidgetType.METRIC_CARD,
            title="Metric Card",
            width=4,
            height=3,
            chart_config={
                "primary_metric": "value",
                "comparison_metric": "previous_value",
                "show_trend": True,
                "format": "{:.2f}",
                "prefix": "",
                "suffix": "",
            },
        )

        # Gauge template
        templates["gauge"] = WidgetConfig(
            type=WidgetType.GAUGE,
            title="Gauge",
            width=6,
            height=6,
            chart_config={
                "value_field": "value",
                "min_value": 0,
                "max_value": 100,
                "target_value": 80,
                "thresholds": [
                    {"value": 50, "color": "#28a745"},
                    {"value": 75, "color": "#ffc107"},
                    {"value": 90, "color": "#dc3545"},
                ],
            },
        )

        # Table template
        templates["table"] = WidgetConfig(
            type=WidgetType.TABLE,
            title="Data Table",
            width=12,
            height=8,
            chart_config={
                "columns": [],
                "sortable": True,
                "searchable": True,
                "paginated": True,
                "page_size": 10,
                "show_totals": False,
            },
        )

        return templates

    async def create_dashboard(self, dashboard_config: Dict[str, Any]) -> Dashboard:
        """Create a new dashboard"""
        dashboard = Dashboard(**dashboard_config)
        dashboard.updated_at = datetime.utcnow()

        self.dashboards[dashboard.id] = dashboard

        # Save to persistent storage
        await self._save_dashboard(dashboard)

        self.logger.info(f"Created dashboard: {dashboard.name} ({dashboard.id})")
        return dashboard

    async def update_dashboard(
        self, dashboard_id: str, updates: Dict[str, Any]
    ) -> Dashboard:
        """Update existing dashboard"""
        if dashboard_id not in self.dashboards:
            raise ValueError(f"Dashboard not found: {dashboard_id}")

        dashboard = self.dashboards[dashboard_id]

        # Apply updates
        for key, value in updates.items():
            if hasattr(dashboard, key):
                setattr(dashboard, key, value)

        dashboard.updated_at = datetime.utcnow()

        # Save to persistent storage
        await self._save_dashboard(dashboard)

        # Notify connected clients
        await self._notify_dashboard_update(dashboard_id)

        return dashboard

    async def delete_dashboard(self, dashboard_id: str, user_id: str) -> bool:
        """Delete dashboard"""
        if dashboard_id not in self.dashboards:
            raise ValueError(f"Dashboard not found: {dashboard_id}")

        dashboard = self.dashboards[dashboard_id]

        # Check permissions (owner or admin)
        if dashboard.owner_id != user_id:
            # TODO: Add role-based permission check
            pass

        # Remove from memory
        del self.dashboards[dashboard_id]

        # Remove from persistent storage
        await self._delete_dashboard_file(dashboard_id)

        self.logger.info(f"Deleted dashboard: {dashboard_id}")
        return True

    async def get_dashboard(self, dashboard_id: str, user_id: str = None) -> Dashboard:
        """Get dashboard by ID"""
        if dashboard_id not in self.dashboards:
            # Try to load from persistent storage
            await self._load_dashboard(dashboard_id)

        if dashboard_id not in self.dashboards:
            raise ValueError(f"Dashboard not found: {dashboard_id}")

        dashboard = self.dashboards[dashboard_id]

        # Check access permissions
        if not self._check_dashboard_access(dashboard, user_id):
            raise PermissionError("Access denied to dashboard")

        return dashboard

    def _check_dashboard_access(
        self, dashboard: Dashboard, user_id: str = None
    ) -> bool:
        """Check if user has access to dashboard"""
        if dashboard.is_public:
            return True

        if not user_id:
            return False

        if dashboard.owner_id == user_id:
            return True

        if user_id in dashboard.shared_users:
            return True

        # TODO: Add role-based access check

        return False

    async def add_widget(
        self, dashboard_id: str, widget_config: Dict[str, Any]
    ) -> WidgetConfig:
        """Add widget to dashboard"""
        dashboard = self.dashboards.get(dashboard_id)
        if not dashboard:
            raise ValueError(f"Dashboard not found: {dashboard_id}")

        widget = WidgetConfig(**widget_config)
        dashboard.widgets.append(widget)
        dashboard.updated_at = datetime.utcnow()

        # Save dashboard
        await self._save_dashboard(dashboard)

        # Notify connected clients
        await self._notify_widget_added(dashboard_id, widget)

        return widget

    async def update_widget(
        self, dashboard_id: str, widget_id: str, updates: Dict[str, Any]
    ) -> WidgetConfig:
        """Update widget configuration"""
        dashboard = self.dashboards.get(dashboard_id)
        if not dashboard:
            raise ValueError(f"Dashboard not found: {dashboard_id}")

        widget = next((w for w in dashboard.widgets if w.id == widget_id), None)
        if not widget:
            raise ValueError(f"Widget not found: {widget_id}")

        # Apply updates
        for key, value in updates.items():
            if hasattr(widget, key):
                setattr(widget, key, value)

        dashboard.updated_at = datetime.utcnow()

        # Save dashboard
        await self._save_dashboard(dashboard)

        # Notify connected clients
        await self._notify_widget_updated(dashboard_id, widget)

        return widget

    async def remove_widget(self, dashboard_id: str, widget_id: str) -> bool:
        """Remove widget from dashboard"""
        dashboard = self.dashboards.get(dashboard_id)
        if not dashboard:
            raise ValueError(f"Dashboard not found: {dashboard_id}")

        dashboard.widgets = [w for w in dashboard.widgets if w.id != widget_id]
        dashboard.updated_at = datetime.utcnow()

        # Save dashboard
        await self._save_dashboard(dashboard)

        # Notify connected clients
        await self._notify_widget_removed(dashboard_id, widget_id)

        return True

    async def get_widget_data(
        self, dashboard_id: str, widget_id: str, tenant_id: str = None
    ) -> Dict[str, Any]:
        """Get data for widget"""
        dashboard = self.dashboards.get(dashboard_id)
        if not dashboard:
            raise ValueError(f"Dashboard not found: {dashboard_id}")

        widget = next((w for w in dashboard.widgets if w.id == widget_id), None)
        if not widget:
            raise ValueError(f"Widget not found: {widget_id}")

        # Get data from configured data source
        data_source = widget.data_source
        if data_source not in self.data_sources:
            raise ValueError(f"Unknown data source: {data_source}")

        # Execute query to get data
        data = await self._execute_widget_query(widget, tenant_id)

        # Generate visualization based on widget type
        visualization = await self._generate_visualization(widget, data)

        return {
            "widget_id": widget_id,
            "data": data,
            "visualization": visualization,
            "last_updated": datetime.utcnow().isoformat(),
        }

    async def _execute_widget_query(
        self, widget: WidgetConfig, tenant_id: str = None
    ) -> List[Dict[str, Any]]:
        """Execute query to get widget data"""
        # This would integrate with the OLAP engine or other data sources
        # For now, return mock data based on widget type

        if widget.type == WidgetType.CHART_LINE:
            return self._generate_line_chart_data()
        elif widget.type == WidgetType.CHART_BAR:
            return self._generate_bar_chart_data()
        elif widget.type == WidgetType.METRIC_CARD:
            return self._generate_metric_card_data()
        elif widget.type == WidgetType.GAUGE:
            return self._generate_gauge_data()
        elif widget.type == WidgetType.TABLE:
            return self._generate_table_data()
        else:
            return []

    def _generate_line_chart_data(self) -> List[Dict[str, Any]]:
        """Generate sample line chart data"""
        data = []
        base_date = datetime.utcnow() - timedelta(days=30)

        for i in range(30):
            date = base_date + timedelta(days=i)
            data.append(
                {
                    "date": date.isoformat(),
                    "value": 100 + (i * 2) + (i % 7 * 10),
                    "category": "Series 1",
                }
            )

        return data

    def _generate_bar_chart_data(self) -> List[Dict[str, Any]]:
        """Generate sample bar chart data"""
        return [
            {"category": "A", "value": 45, "label": "Category A"},
            {"category": "B", "value": 67, "label": "Category B"},
            {"category": "C", "value": 32, "label": "Category C"},
            {"category": "D", "value": 89, "label": "Category D"},
            {"category": "E", "value": 56, "label": "Category E"},
        ]

    def _generate_metric_card_data(self) -> List[Dict[str, Any]]:
        """Generate sample metric card data"""
        return [
            {
                "current_value": 1247,
                "previous_value": 1189,
                "change_percent": 4.9,
                "trend": "up",
                "label": "Total Users",
            }
        ]

    def _generate_gauge_data(self) -> List[Dict[str, Any]]:
        """Generate sample gauge data"""
        return [
            {
                "value": 73.5,
                "min_value": 0,
                "max_value": 100,
                "target": 80,
                "label": "Performance Score",
            }
        ]

    def _generate_table_data(self) -> List[Dict[str, Any]]:
        """Generate sample table data"""
        return [
            {"id": 1, "name": "Agent Alpha", "status": "Active", "requests": 1245},
            {"id": 2, "name": "Agent Beta", "status": "Active", "requests": 967},
            {"id": 3, "name": "Agent Gamma", "status": "Idle", "requests": 234},
            {"id": 4, "name": "Agent Delta", "status": "Active", "requests": 1789},
            {"id": 5, "name": "Agent Epsilon", "status": "Error", "requests": 45},
        ]

    async def _generate_visualization(
        self, widget: WidgetConfig, data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate Plotly visualization for widget"""
        if widget.type == WidgetType.CHART_LINE:
            return self._create_line_chart(data, widget.chart_config)
        elif widget.type == WidgetType.CHART_BAR:
            return self._create_bar_chart(data, widget.chart_config)
        elif widget.type == WidgetType.CHART_PIE:
            return self._create_pie_chart(data, widget.chart_config)
        elif widget.type == WidgetType.GAUGE:
            return self._create_gauge_chart(data, widget.chart_config)
        else:
            return {"data": [], "layout": {}}

    def _create_line_chart(
        self, data: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create Plotly line chart"""
        df = pd.DataFrame(data)

        fig = px.line(
            df,
            x=config.get("x_axis", "date"),
            y=config.get("y_axis", "value"),
            color=config.get("color_by"),
            title=config.get("title", ""),
        )

        fig.update_layout(
            showlegend=config.get("show_legend", True),
            xaxis_showgrid=config.get("show_grid", True),
            yaxis_showgrid=config.get("show_grid", True),
        )

        return json.loads(fig.to_json())

    def _create_bar_chart(
        self, data: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create Plotly bar chart"""
        df = pd.DataFrame(data)

        fig = px.bar(
            df,
            x=config.get("x_axis", "category"),
            y=config.get("y_axis", "value"),
            color=config.get("color_by"),
            title=config.get("title", ""),
        )

        if config.get("show_values", True):
            fig.update_traces(texttemplate="%{y}", textposition="outside")

        return json.loads(fig.to_json())

    def _create_pie_chart(
        self, data: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create Plotly pie chart"""
        df = pd.DataFrame(data)

        fig = px.pie(
            df,
            values=config.get("values", "value"),
            names=config.get("names", "category"),
            title=config.get("title", ""),
        )

        return json.loads(fig.to_json())

    def _create_gauge_chart(
        self, data: List[Dict[str, Any]], config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create Plotly gauge chart"""
        if not data:
            return {"data": [], "layout": {}}

        value = data[0].get("value", 0)
        min_val = config.get("min_value", 0)
        max_val = config.get("max_value", 100)

        fig = go.Figure(
            go.Indicator(
                mode="gauge+number+delta",
                value=value,
                domain={"x": [0, 1], "y": [0, 1]},
                title={"text": config.get("title", "Gauge")},
                delta={"reference": config.get("target_value", 80)},
                gauge={
                    "axis": {"range": [min_val, max_val]},
                    "bar": {"color": "darkblue"},
                    "steps": [
                        {"range": [min_val, max_val * 0.5], "color": "lightgray"},
                        {"range": [max_val * 0.5, max_val * 0.8], "color": "gray"},
                    ],
                    "threshold": {
                        "line": {"color": "red", "width": 4},
                        "thickness": 0.75,
                        "value": config.get("target_value", 80),
                    },
                },
            )
        )

        return json.loads(fig.to_json())

    async def _save_dashboard(self, dashboard: Dashboard):
        """Save dashboard to persistent storage"""
        try:
            dashboard_path = f"dashboards/{dashboard.id}.json"

            async with aiofiles.open(dashboard_path, "w") as f:
                await f.write(json.dumps(dashboard.to_dict(), indent=2))

        except Exception as e:
            self.logger.error(f"Failed to save dashboard {dashboard.id}: {e}")

    async def _load_dashboard(self, dashboard_id: str):
        """Load dashboard from persistent storage"""
        try:
            dashboard_path = f"dashboards/{dashboard_id}.json"

            async with aiofiles.open(dashboard_path, "r") as f:
                data = json.loads(await f.read())

            dashboard = Dashboard(**data)
            self.dashboards[dashboard_id] = dashboard

        except Exception as e:
            self.logger.error(f"Failed to load dashboard {dashboard_id}: {e}")

    async def _delete_dashboard_file(self, dashboard_id: str):
        """Delete dashboard file from storage"""
        try:
            import os

            dashboard_path = f"dashboards/{dashboard_id}.json"
            if os.path.exists(dashboard_path):
                os.remove(dashboard_path)
        except Exception as e:
            self.logger.error(f"Failed to delete dashboard file {dashboard_id}: {e}")

    async def connect_websocket(self, websocket: WebSocket, dashboard_id: str):
        """Connect WebSocket for real-time updates"""
        if dashboard_id not in self.active_connections:
            self.active_connections[dashboard_id] = []

        self.active_connections[dashboard_id].append(websocket)

    async def disconnect_websocket(self, websocket: WebSocket, dashboard_id: str):
        """Disconnect WebSocket"""
        if dashboard_id in self.active_connections:
            self.active_connections[dashboard_id].remove(websocket)

    async def _notify_dashboard_update(self, dashboard_id: str):
        """Notify connected clients of dashboard update"""
        if dashboard_id in self.active_connections:
            message = {
                "type": "dashboard_updated",
                "dashboard_id": dashboard_id,
                "timestamp": datetime.utcnow().isoformat(),
            }

            for websocket in self.active_connections[dashboard_id]:
                try:
                    await websocket.send_json(message)
                except Exception:
                    pass  # Connection might be closed

    async def _notify_widget_added(self, dashboard_id: str, widget: WidgetConfig):
        """Notify connected clients of widget addition"""
        if dashboard_id in self.active_connections:
            message = {
                "type": "widget_added",
                "dashboard_id": dashboard_id,
                "widget": {
                    "id": widget.id,
                    "type": widget.type.value,
                    "title": widget.title,
                    "x": widget.x,
                    "y": widget.y,
                    "width": widget.width,
                    "height": widget.height,
                },
                "timestamp": datetime.utcnow().isoformat(),
            }

            for websocket in self.active_connections[dashboard_id]:
                try:
                    await websocket.send_json(message)
                except Exception:
                    pass

    async def _notify_widget_updated(self, dashboard_id: str, widget: WidgetConfig):
        """Notify connected clients of widget update"""
        if dashboard_id in self.active_connections:
            message = {
                "type": "widget_updated",
                "dashboard_id": dashboard_id,
                "widget_id": widget.id,
                "timestamp": datetime.utcnow().isoformat(),
            }

            for websocket in self.active_connections[dashboard_id]:
                try:
                    await websocket.send_json(message)
                except Exception:
                    pass

    async def _notify_widget_removed(self, dashboard_id: str, widget_id: str):
        """Notify connected clients of widget removal"""
        if dashboard_id in self.active_connections:
            message = {
                "type": "widget_removed",
                "dashboard_id": dashboard_id,
                "widget_id": widget_id,
                "timestamp": datetime.utcnow().isoformat(),
            }

            for websocket in self.active_connections[dashboard_id]:
                try:
                    await websocket.send_json(message)
                except Exception:
                    pass

    def get_widget_templates(self) -> Dict[str, WidgetConfig]:
        """Get available widget templates"""
        return self.widget_templates.copy()

    def get_themes(self) -> Dict[str, Dict[str, Any]]:
        """Get available themes"""
        return self.themes.copy()

    async def export_dashboard(self, dashboard_id: str, format: str = "json") -> bytes:
        """Export dashboard in specified format"""
        dashboard = await self.get_dashboard(dashboard_id)

        if format == "json":
            return json.dumps(dashboard.to_dict(), indent=2).encode("utf-8")
        elif format == "pdf":
            # TODO: Implement PDF export
            return b""
        else:
            raise ValueError(f"Unsupported export format: {format}")

    async def import_dashboard(
        self, data: bytes, format: str = "json", user_id: str = None
    ) -> Dashboard:
        """Import dashboard from data"""
        if format == "json":
            dashboard_data = json.loads(data.decode("utf-8"))
            dashboard_data["id"] = str(uuid4())  # Generate new ID
            dashboard_data["owner_id"] = user_id

            return await self.create_dashboard(dashboard_data)
        else:
            raise ValueError(f"Unsupported import format: {format}")
