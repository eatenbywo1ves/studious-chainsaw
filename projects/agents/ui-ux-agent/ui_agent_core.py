"""
UI/UX Agent Core Orchestrator
==============================
Central coordinator for all UI/UX operations in a multi-agent system
"""

import asyncio
import json
import uuid
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import redis
import aioredis
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class UIEventType(Enum):
    """Types of UI events that can be processed"""
    CLICK = "click"
    HOVER = "hover"
    FOCUS = "focus"
    BLUR = "blur"
    INPUT = "input"
    SUBMIT = "submit"
    SCROLL = "scroll"
    RESIZE = "resize"
    DRAG = "drag"
    DROP = "drop"
    KEYPRESS = "keypress"
    GESTURE = "gesture"
    VOICE_COMMAND = "voice_command"


class UIComponentType(Enum):
    """Types of UI components that can be generated"""
    BUTTON = "button"
    FORM = "form"
    CARD = "card"
    MODAL = "modal"
    CHART = "chart"
    TABLE = "table"
    NAVIGATION = "navigation"
    DASHBOARD = "dashboard"
    NOTIFICATION = "notification"
    WIDGET = "widget"


class SubAgentType(Enum):
    """Types of sub-agents in the UI system"""
    # Presentation Layer
    VISUAL_RENDERING = "visual_rendering"
    LAYOUT = "layout"
    ANIMATION = "animation"
    THEME = "theme"

    # Interaction Layer
    INPUT_HANDLER = "input_handler"
    FEEDBACK = "feedback"
    ACCESSIBILITY = "accessibility"
    GESTURE = "gesture"

    # Data Layer
    CHART = "chart"
    OBSERVATORY = "observatory"
    METRICS = "metrics"

    # State Management
    FORM = "form"
    SESSION = "session"
    CACHE = "cache"


@dataclass
class UIRequest:
    """Represents a UI generation or modification request"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: UIComponentType = UIComponentType.CARD
    prompt: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    style: Dict[str, Any] = field(default_factory=dict)
    interactions: List[str] = field(default_factory=list)
    accessibility: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class UIEvent:
    """Represents a UI event that needs processing"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: UIEventType = UIEventType.CLICK
    target: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UIResponse:
    """Response from UI agent processing"""
    request_id: str
    success: bool
    component: Optional[Dict[str, Any]] = None
    updates: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    sub_agent_results: Dict[str, Any] = field(default_factory=dict)
    rendering_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)


class SubAgentRegistry:
    """Registry for managing UI sub-agents"""

    def __init__(self):
        self.agents: Dict[SubAgentType, Dict[str, Any]] = {}
        self.agent_status: Dict[str, str] = {}
        self.agent_metrics: Dict[str, Dict[str, Any]] = {}

    def register_agent(self, agent_type: SubAgentType, agent_instance: Any,
                      capabilities: Dict[str, Any] = None):
        """Register a new sub-agent"""
        agent_id = f"{agent_type.value}_{uuid.uuid4().hex[:8]}"
        self.agents[agent_type] = {
            'id': agent_id,
            'instance': agent_instance,
            'capabilities': capabilities or {},
            'registered_at': datetime.now()
        }
        self.agent_status[agent_id] = 'active'
        self.agent_metrics[agent_id] = {
            'requests_processed': 0,
            'avg_response_time': 0,
            'errors': 0
        }
        logger.info(f"Registered sub-agent: {agent_id}")
        return agent_id

    def get_agent(self, agent_type: SubAgentType) -> Optional[Any]:
        """Get a sub-agent instance by type"""
        if agent_type in self.agents:
            agent_info = self.agents[agent_type]
            if self.agent_status[agent_info['id']] == 'active':
                return agent_info['instance']
        return None

    def update_metrics(self, agent_type: SubAgentType, response_time: float,
                      success: bool):
        """Update agent performance metrics"""
        if agent_type in self.agents:
            agent_id = self.agents[agent_type]['id']
            metrics = self.agent_metrics[agent_id]

            metrics['requests_processed'] += 1
            if not success:
                metrics['errors'] += 1

            # Update rolling average response time
            n = metrics['requests_processed']
            avg = metrics['avg_response_time']
            metrics['avg_response_time'] = (avg * (n-1) + response_time) / n


class UIAgentOrchestrator:
    """
    Core UI Agent that orchestrates all UI/UX operations
    Coordinates sub-agents for rendering, interaction, and state management
    """

    def __init__(self, redis_url: str = "redis://localhost:6379",
                 websocket_port: int = 8765):
        self.agent_id = str(uuid.uuid4())
        self.redis_url = redis_url
        self.websocket_port = websocket_port

        # Sub-agent registry
        self.registry = SubAgentRegistry()

        # Component cache
        self.component_cache: Dict[str, Dict[str, Any]] = {}

        # Event queue
        self.event_queue = asyncio.Queue()

        # Active sessions
        self.sessions: Dict[str, Dict[str, Any]] = {}

        # WebSocket connections
        self.websocket_clients: List[Any] = []

        # Component templates
        self.templates = self._load_templates()

        logger.info(f"UI Agent Orchestrator initialized: {self.agent_id}")

    async def initialize(self):
        """Initialize the UI agent and connect to services"""
        try:
            # Connect to Redis for inter-agent communication
            self.redis = await aioredis.create_redis_pool(self.redis_url)

            # Start event processing loop
            asyncio.create_task(self._process_events())

            # Initialize sub-agents
            await self._initialize_sub_agents()

            logger.info("UI Agent Orchestrator fully initialized")
            return True

        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            return False

    async def _initialize_sub_agents(self):
        """Initialize and register all sub-agents"""
        # Import sub-agents (these will be created next)
        from .presentation_agents import VisualRenderingAgent, LayoutAgent, AnimationAgent
        from .interaction_agents import InputHandlerAgent, FeedbackAgent, AccessibilityAgent
        from .visualization_agents import ChartAgent, ObservatoryAgent
        from .state_agents import FormAgent, SessionAgent

        # Initialize presentation layer agents
        visual_agent = VisualRenderingAgent()
        await visual_agent.initialize()
        self.registry.register_agent(SubAgentType.VISUAL_RENDERING, visual_agent)

        layout_agent = LayoutAgent()
        await layout_agent.initialize()
        self.registry.register_agent(SubAgentType.LAYOUT, layout_agent)

        animation_agent = AnimationAgent()
        await animation_agent.initialize()
        self.registry.register_agent(SubAgentType.ANIMATION, animation_agent)

        # Initialize interaction agents
        input_agent = InputHandlerAgent()
        await input_agent.initialize()
        self.registry.register_agent(SubAgentType.INPUT_HANDLER, input_agent)

        feedback_agent = FeedbackAgent()
        await feedback_agent.initialize()
        self.registry.register_agent(SubAgentType.FEEDBACK, feedback_agent)

        accessibility_agent = AccessibilityAgent()
        await accessibility_agent.initialize()
        self.registry.register_agent(SubAgentType.ACCESSIBILITY, accessibility_agent)

        # Initialize data visualization agents
        chart_agent = ChartAgent()
        await chart_agent.initialize()
        self.registry.register_agent(SubAgentType.CHART, chart_agent)

        observatory_agent = ObservatoryAgent()
        await observatory_agent.initialize()
        self.registry.register_agent(SubAgentType.OBSERVATORY, observatory_agent)

        # Initialize state management agents
        form_agent = FormAgent()
        await form_agent.initialize()
        self.registry.register_agent(SubAgentType.FORM, form_agent)

        session_agent = SessionAgent()
        await session_agent.initialize()
        self.registry.register_agent(SubAgentType.SESSION, session_agent)

        logger.info(f"Registered {len(self.registry.agents)} sub-agents")

    async def process_ui_request(self, request: UIRequest) -> UIResponse:
        """
        Process a UI generation/modification request
        Orchestrates multiple sub-agents to create the final UI
        """
        start_time = datetime.now()
        response = UIResponse(request_id=request.id, success=False)

        try:
            # Step 1: Layout calculation
            layout_agent = self.registry.get_agent(SubAgentType.LAYOUT)
            if layout_agent:
                layout = await layout_agent.calculate_layout(request)
                response.sub_agent_results['layout'] = layout

            # Step 2: Visual rendering
            visual_agent = self.registry.get_agent(SubAgentType.VISUAL_RENDERING)
            if visual_agent:
                visual = await visual_agent.render_component(request, layout)
                response.sub_agent_results['visual'] = visual

            # Step 3: Add interactions
            if request.interactions:
                input_agent = self.registry.get_agent(SubAgentType.INPUT_HANDLER)
                if input_agent:
                    interactions = await input_agent.setup_interactions(
                        request.interactions, visual
                    )
                    response.sub_agent_results['interactions'] = interactions

            # Step 4: Apply animations
            animation_agent = self.registry.get_agent(SubAgentType.ANIMATION)
            if animation_agent:
                animations = await animation_agent.add_animations(visual, request.style)
                response.sub_agent_results['animations'] = animations

            # Step 5: Ensure accessibility
            if request.accessibility:
                accessibility_agent = self.registry.get_agent(SubAgentType.ACCESSIBILITY)
                if accessibility_agent:
                    accessibility = await accessibility_agent.apply_accessibility(
                        visual, request.accessibility
                    )
                    response.sub_agent_results['accessibility'] = accessibility

            # Step 6: Add data visualizations if needed
            if request.type in [UIComponentType.CHART, UIComponentType.DASHBOARD]:
                chart_agent = self.registry.get_agent(SubAgentType.CHART)
                if chart_agent:
                    charts = await chart_agent.generate_visualizations(request.data)
                    response.sub_agent_results['charts'] = charts

            # Combine all results into final component
            response.component = self._combine_agent_results(response.sub_agent_results)
            response.success = True

            # Cache the component
            self.component_cache[request.id] = response.component

            # Broadcast update to WebSocket clients
            await self._broadcast_update({
                'type': 'component_created',
                'request_id': request.id,
                'component': response.component
            })

        except Exception as e:
            logger.error(f"Error processing UI request: {e}")
            response.errors.append(str(e))

        # Calculate rendering time
        response.rendering_time = (datetime.now() - start_time).total_seconds()

        # Update metrics for each agent
        for agent_type in SubAgentType:
            if agent_type.value in response.sub_agent_results:
                self.registry.update_metrics(
                    agent_type,
                    response.rendering_time,
                    response.success
                )

        return response

    async def handle_ui_event(self, event: UIEvent) -> Dict[str, Any]:
        """
        Handle a UI event (click, input, etc.)
        Routes to appropriate sub-agents for processing
        """
        result = {
            'event_id': event.id,
            'processed': False,
            'updates': []
        }

        try:
            # Get the appropriate handler based on event type
            input_agent = self.registry.get_agent(SubAgentType.INPUT_HANDLER)
            if not input_agent:
                raise ValueError("Input handler agent not available")

            # Process the event
            event_result = await input_agent.process_event(event)

            # Apply feedback if needed
            feedback_agent = self.registry.get_agent(SubAgentType.FEEDBACK)
            if feedback_agent and event_result.get('requires_feedback'):
                feedback = await feedback_agent.generate_feedback(event, event_result)
                result['feedback'] = feedback

            # Update session state
            session_agent = self.registry.get_agent(SubAgentType.SESSION)
            if session_agent and event.session_id:
                await session_agent.update_session(event.session_id, event, event_result)

            # Check if component needs re-rendering
            if event_result.get('requires_rerender'):
                component = self.component_cache.get(event.target)
                if component:
                    # Re-render with updated state
                    updated_component = await self._rerender_component(
                        component, event_result
                    )
                    result['updates'].append(updated_component)

            result['processed'] = True
            result['event_result'] = event_result

            # Broadcast event result
            await self._broadcast_update({
                'type': 'event_processed',
                'event': event.type.value,
                'result': result
            })

        except Exception as e:
            logger.error(f"Error handling UI event: {e}")
            result['error'] = str(e)

        return result

    async def _process_events(self):
        """Background task to process queued events"""
        while True:
            try:
                event = await self.event_queue.get()
                await self.handle_ui_event(event)
            except Exception as e:
                logger.error(f"Event processing error: {e}")
            await asyncio.sleep(0.01)

    async def _broadcast_update(self, update: Dict[str, Any]):
        """Broadcast updates to all connected WebSocket clients"""
        if self.websocket_clients:
            message = json.dumps(update)
            disconnected = []

            for client in self.websocket_clients:
                try:
                    await client.send(message)
                except:
                    disconnected.append(client)

            # Remove disconnected clients
            for client in disconnected:
                self.websocket_clients.remove(client)

    def _combine_agent_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Combine results from multiple sub-agents into a final component"""
        component = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'layers': {}
        }

        # Merge results from each agent
        for agent_type, result in results.items():
            if result:
                component['layers'][agent_type] = result

        return component

    async def _rerender_component(self, component: Dict[str, Any],
                                  updates: Dict[str, Any]) -> Dict[str, Any]:
        """Re-render a component with updates"""
        # Apply updates to component
        updated_component = {**component, **updates}

        # Re-run through rendering pipeline
        visual_agent = self.registry.get_agent(SubAgentType.VISUAL_RENDERING)
        if visual_agent:
            updated_component = await visual_agent.update_component(updated_component)

        return updated_component

    def _load_templates(self) -> Dict[str, Any]:
        """Load UI component templates"""
        return {
            'button': {
                'tag': 'button',
                'classes': ['btn'],
                'attributes': {}
            },
            'card': {
                'tag': 'div',
                'classes': ['card'],
                'children': ['header', 'body', 'footer']
            },
            'form': {
                'tag': 'form',
                'classes': ['form'],
                'children': []
            },
            'dashboard': {
                'tag': 'div',
                'classes': ['dashboard'],
                'layout': 'grid',
                'children': []
            }
        }

    async def get_agent_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for all sub-agents"""
        return {
            'orchestrator_id': self.agent_id,
            'sub_agents': self.registry.agent_metrics,
            'cache_size': len(self.component_cache),
            'active_sessions': len(self.sessions),
            'websocket_clients': len(self.websocket_clients)
        }

    async def shutdown(self):
        """Clean shutdown of the UI agent"""
        logger.info("Shutting down UI Agent Orchestrator...")

        # Close Redis connection
        if hasattr(self, 'redis'):
            self.redis.close()
            await self.redis.wait_closed()

        # Notify all sub-agents
        for agent_type in SubAgentType:
            agent = self.registry.get_agent(agent_type)
            if agent and hasattr(agent, 'shutdown'):
                await agent.shutdown()

        logger.info("UI Agent Orchestrator shutdown complete")


# Example usage
async def main():
    """Demonstrate the UI Agent Orchestrator"""

    # Initialize the orchestrator
    ui_agent = UIAgentOrchestrator()
    await ui_agent.initialize()

    # Create a dashboard request
    dashboard_request = UIRequest(
        type=UIComponentType.DASHBOARD,
        prompt="Create a modern analytics dashboard with real-time metrics",
        data={
            'metrics': ['users', 'revenue', 'performance'],
            'timeframe': '24h'
        },
        style={
            'theme': 'dark',
            'animations': True
        },
        interactions=['click', 'hover', 'resize'],
        accessibility={
            'aria_labels': True,
            'keyboard_nav': True
        }
    )

    # Process the request
    response = await ui_agent.process_ui_request(dashboard_request)

    if response.success:
        print(f"Dashboard created successfully!")
        print(f"Rendering time: {response.rendering_time:.2f}s")
        print(f"Sub-agents used: {list(response.sub_agent_results.keys())}")
    else:
        print(f"Failed to create dashboard: {response.errors}")

    # Simulate a click event
    click_event = UIEvent(
        type=UIEventType.CLICK,
        target="metric_card_users",
        data={'metric': 'users', 'action': 'expand'}
    )

    event_result = await ui_agent.handle_ui_event(click_event)
    print(f"Event processed: {event_result['processed']}")

    # Get metrics
    metrics = await ui_agent.get_agent_metrics()
    print(f"Agent metrics: {json.dumps(metrics, indent=2)}")

    # Shutdown
    await ui_agent.shutdown()


if __name__ == "__main__":
    asyncio.run(main())