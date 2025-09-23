"""
Integrated UI/UX Agent Demo Application
========================================
Demonstrates all UI agents working together in a cohesive system
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, Any

# Import all agents
from ui_agent_core import UIAgentOrchestrator, UIRequest, UIEvent, UIComponentType, UIEventType
from presentation_agents import VisualRenderingAgent, LayoutAgent, AnimationAgent, ThemeAgent
from interaction_agents import InputHandlerAgent, FeedbackAgent, AccessibilityAgent
from visualization_agents import ChartAgent, ObservatoryAgent
from state_agents import FormAgent, SessionAgent, CacheAgent
from websocket_router import WebSocketRouter, Channel


class UIAgentDemoApp:
    """
    Complete demo application showcasing UI/UX agent system
    Creates a dashboard with real-time updates, forms, and visualizations
    """

    def __init__(self):
        self.orchestrator = None
        self.websocket_router = None
        self.session_agent = None
        self.current_session = None

    async def initialize(self):
        """Initialize all components"""
        print("🚀 Initializing UI/UX Agent Demo Application...")

        # Initialize orchestrator
        self.orchestrator = UIAgentOrchestrator()
        await self.orchestrator.initialize()

        # Initialize WebSocket router
        self.websocket_router = WebSocketRouter()
        asyncio.create_task(self.websocket_router.start())

        # Get session agent from orchestrator
        from ui_agent_core import SubAgentType
        self.session_agent = self.orchestrator.registry.get_agent(SubAgentType.SESSION)

        print("✅ All systems initialized")

    async def create_dashboard(self):
        """Create a comprehensive dashboard demonstrating all agents"""
        print("\n📊 Creating Analytics Dashboard...")

        # Create dashboard request
        dashboard_request = UIRequest(
            type=UIComponentType.DASHBOARD,
            prompt="Create a modern real-time analytics dashboard",
            data={
                'title': 'UI Agent System Monitor',
                'sections': ['metrics', 'charts', 'agents', 'events'],
                'metrics': {
                    'Active Users': 1247,
                    'Requests/sec': 342,
                    'Error Rate': '0.3%',
                    'Uptime': '99.98%'
                },
                'timeseries': {
                    'timestamps': ['10:00', '10:05', '10:10', '10:15', '10:20'],
                    'values': [120, 145, 132, 168, 155],
                    'label': 'System Load'
                },
                'categories': {
                    'Success': 892,
                    'Warning': 45,
                    'Error': 12
                },
                'realtime': True
            },
            style={
                'theme': 'dark',
                'animations': True,
                'responsive': True
            },
            interactions=['click', 'hover', 'resize'],
            accessibility={
                'aria_labels': True,
                'keyboard_nav': True,
                'screen_reader': True
            }
        )

        # Process through orchestrator
        response = await self.orchestrator.process_ui_request(dashboard_request)

        if response.success:
            print(f"✅ Dashboard created in {response.rendering_time:.2f}s")
            print(f"   Sub-agents used: {', '.join(response.sub_agent_results.keys())}")

            # Broadcast dashboard creation
            await self.websocket_router.broadcast_to_channel(
                Channel.COMPONENTS.value,
                {
                    'event': 'dashboard_created',
                    'dashboard_id': response.component['id'],
                    'timestamp': datetime.now().isoformat()
                }
            )

            return response.component
        else:
            print(f"❌ Dashboard creation failed: {response.errors}")
            return None

    async def create_login_form(self):
        """Create a login form demonstrating form agents"""
        print("\n📝 Creating Login Form...")

        # Get form agent
        from ui_agent_core import SubAgentType
        form_agent = self.orchestrator.registry.get_agent(SubAgentType.FORM)

        # Create form
        form_config = {
            'fields': [
                {
                    'name': 'username',
                    'type': 'text',
                    'label': 'Username',
                    'placeholder': 'Enter your username',
                    'required': True,
                    'validation': [
                        {'type': 'min_length', 'value': 3, 'message': 'Username must be at least 3 characters'}
                    ]
                },
                {
                    'name': 'password',
                    'type': 'password',
                    'label': 'Password',
                    'placeholder': 'Enter your password',
                    'required': True,
                    'validation': [
                        {'type': 'min_length', 'value': 8, 'message': 'Password must be at least 8 characters'}
                    ]
                },
                {
                    'name': 'remember',
                    'type': 'checkbox',
                    'label': 'Remember me for 30 days'
                }
            ]
        }

        form = await form_agent.create_form(form_config)
        print(f"✅ Form created: {form.id}")

        # Create form UI component
        form_request = UIRequest(
            type=UIComponentType.FORM,
            data={'form_id': form.id, 'form_config': form_config},
            style={'theme': 'light', 'width': '400px'},
            interactions=['input', 'focus', 'submit'],
            accessibility={'aria_labels': True}
        )

        response = await self.orchestrator.process_ui_request(form_request)

        if response.success:
            print("✅ Form UI created")
            return form, response.component
        else:
            print(f"❌ Form UI creation failed: {response.errors}")
            return form, None

    async def simulate_user_interaction(self):
        """Simulate user interactions to demonstrate event handling"""
        print("\n👆 Simulating User Interactions...")

        # Create a session
        self.current_session = await self.session_agent.create_session(
            user_id='demo_user',
            data={'demo': True}
        )
        print(f"✅ Session created: {self.current_session.id}")

        # Simulate button click
        click_event = UIEvent(
            type=UIEventType.CLICK,
            target='dashboard_refresh_btn',
            session_id=self.current_session.id,
            data={'action': 'refresh'}
        )

        result = await self.orchestrator.handle_ui_event(click_event)
        print(f"   Click event processed: {result['processed']}")

        # Simulate form input
        input_event = UIEvent(
            type=UIEventType.INPUT,
            target='username_field',
            session_id=self.current_session.id,
            data={'value': 'demo_user'}
        )

        result = await self.orchestrator.handle_ui_event(input_event)
        print(f"   Input event processed: {result['processed']}")

        # Broadcast events
        await self.websocket_router.broadcast_to_channel(
            Channel.EVENTS.value,
            {
                'events': ['click', 'input'],
                'session': self.current_session.id,
                'timestamp': datetime.now().isoformat()
            }
        )

    async def demonstrate_real_time_updates(self):
        """Demonstrate real-time chart updates via WebSocket"""
        print("\n📈 Demonstrating Real-Time Updates...")

        # Simulate real-time data updates
        for i in range(5):
            # Generate new data point
            import random
            new_data = {
                'timestamp': datetime.now().isoformat(),
                'value': random.randint(100, 200),
                'metric': 'requests_per_second'
            }

            # Broadcast to charts channel
            await self.websocket_router.broadcast_to_channel(
                Channel.CHARTS.value,
                {
                    'update': 'new_data',
                    'data': new_data
                }
            )

            print(f"   📊 Sent update {i+1}/5: {new_data['value']} req/s")
            await asyncio.sleep(1)

    async def demonstrate_agent_collaboration(self):
        """Demonstrate multiple agents working together"""
        print("\n🤝 Demonstrating Agent Collaboration...")

        # Create a complex component requiring multiple agents
        complex_request = UIRequest(
            type=UIComponentType.CARD,
            prompt="Create an interactive metric card with animations",
            data={
                'title': 'System Performance',
                'metric': 'CPU Usage',
                'value': 67.5,
                'trend': 'up',
                'history': [60, 62, 65, 63, 67.5]
            },
            style={
                'theme': 'dark',
                'animations': True,
                'hover_effects': True
            },
            interactions=['click', 'hover'],
            accessibility={'keyboard_nav': True}
        )

        print("   Agents working together:")
        response = await self.orchestrator.process_ui_request(complex_request)

        if response.success:
            agents_used = list(response.sub_agent_results.keys())
            for agent in agents_used:
                print(f"   ✅ {agent}: Completed task")

            print(f"\n   Total rendering time: {response.rendering_time:.2f}s")
            print(f"   Component layers: {len(response.component.get('layers', {}))}")

    async def get_system_metrics(self):
        """Get metrics from all agents"""
        print("\n📊 System Metrics:")

        # Get orchestrator metrics
        metrics = await self.orchestrator.get_agent_metrics()

        print(f"   Active sub-agents: {len(metrics['sub_agents'])}")
        print(f"   Cached components: {metrics['cache_size']}")
        print(f"   Active sessions: {metrics['active_sessions']}")
        print(f"   WebSocket clients: {metrics['websocket_clients']}")

        # Get WebSocket stats
        ws_stats = await self.websocket_router.get_stats()
        print(f"   Total connections: {ws_stats['total_clients']}")
        print(f"   Message queue size: {ws_stats['message_queue_size']}")

        # Get cache stats
        from ui_agent_core import SubAgentType
        cache_agent = self.orchestrator.registry.get_agent(SubAgentType.CACHE)
        if cache_agent:
            cache_stats = cache_agent.get_cache_stats()
            print(f"   Cache hit ratio: {cache_stats.get('total_hits', 0)} hits")

    async def run_complete_demo(self):
        """Run the complete demonstration"""
        print("\n" + "="*60)
        print("   UI/UX AGENT SYSTEM - COMPLETE DEMONSTRATION")
        print("="*60)

        # Initialize system
        await self.initialize()
        await asyncio.sleep(2)  # Let WebSocket server start

        # Create dashboard
        dashboard = await self.create_dashboard()

        # Create login form
        form, form_ui = await self.create_login_form()

        # Simulate user interactions
        await self.simulate_user_interaction()

        # Demonstrate real-time updates
        await self.demonstrate_real_time_updates()

        # Show agent collaboration
        await self.demonstrate_agent_collaboration()

        # Display metrics
        await self.get_system_metrics()

        print("\n" + "="*60)
        print("   DEMONSTRATION COMPLETE")
        print("="*60)

        # Summary
        print("\n📋 Summary:")
        print("   ✅ UI Agent Orchestrator: Coordinated all sub-agents")
        print("   ✅ Presentation Agents: Rendered UI components with themes")
        print("   ✅ Interaction Agents: Handled user events and feedback")
        print("   ✅ Visualization Agents: Created charts and dashboards")
        print("   ✅ State Agents: Managed forms and sessions")
        print("   ✅ WebSocket Router: Enabled real-time updates")

        print("\n💡 Key Features Demonstrated:")
        print("   • Multi-agent collaboration")
        print("   • Real-time data updates")
        print("   • Accessibility compliance")
        print("   • Form validation")
        print("   • Session management")
        print("   • Component caching")
        print("   • Event processing")
        print("   • Responsive layouts")
        print("   • Theme support")
        print("   • Performance optimization")


async def main():
    """Main entry point"""
    demo_app = UIAgentDemoApp()
    await demo_app.run_complete_demo()

    # Keep running for WebSocket connections
    print("\n⚡ System running... Press Ctrl+C to stop")
    try:
        await asyncio.Future()  # Run forever
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")


if __name__ == "__main__":
    asyncio.run(main())