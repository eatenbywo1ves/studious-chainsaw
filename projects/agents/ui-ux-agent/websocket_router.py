"""
WebSocket Event Routing System
===============================
Real-time bi-directional communication between UI agents and clients
"""

import asyncio
import json
import uuid
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import logging
from datetime import datetime
import websockets
from websockets.server import WebSocketServerProtocol

logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Types of WebSocket messages"""
    # Client to server
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    EVENT = "event"
    REQUEST = "request"

    # Server to client
    RESPONSE = "response"
    BROADCAST = "broadcast"
    UPDATE = "update"
    NOTIFICATION = "notification"
    ERROR = "error"
    HEARTBEAT = "heartbeat"


class Channel(Enum):
    """WebSocket channels for different data streams"""
    COMPONENTS = "components"
    EVENTS = "events"
    METRICS = "metrics"
    ALERTS = "alerts"
    CHARTS = "charts"
    FORMS = "forms"
    SESSIONS = "sessions"


@dataclass
class WebSocketMessage:
    """Represents a WebSocket message"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: MessageType = MessageType.EVENT
    channel: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    client_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WebSocketClient:
    """Represents a connected WebSocket client"""
    id: str
    websocket: WebSocketServerProtocol
    subscriptions: Set[str] = field(default_factory=set)
    session_id: Optional[str] = None
    connected_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class WebSocketRouter:
    """
    Central WebSocket router for real-time UI updates
    Manages connections, subscriptions, and message routing
    """

    def __init__(self, host: str = "localhost", port: int = 8765):
        self.host = host
        self.port = port
        self.clients: Dict[str, WebSocketClient] = {}
        self.channels: Dict[str, Set[str]] = {channel.value: set() for channel in Channel}
        self.message_queue = asyncio.Queue()
        self.agent_connections: Dict[str, Any] = {}

    async def start(self):
        """Start the WebSocket server"""
        # Start message processor
        asyncio.create_task(self._process_messages())

        # Start heartbeat sender
        asyncio.create_task(self._send_heartbeats())

        # Start WebSocket server
        async with websockets.serve(self.handle_client, self.host, self.port):
            logger.info(f"WebSocket server started on ws://{self.host}:{self.port}")
            await asyncio.Future()  # Run forever

    async def handle_client(self, websocket: WebSocketServerProtocol, path: str):
        """Handle a WebSocket client connection"""
        client_id = str(uuid.uuid4())
        client = WebSocketClient(
            id=client_id,
            websocket=websocket
        )

        # Register client
        self.clients[client_id] = client
        logger.info(f"Client {client_id} connected from {websocket.remote_address}")

        # Send welcome message
        await self._send_to_client(client, WebSocketMessage(
            type=MessageType.CONNECT,
            data={'client_id': client_id, 'channels': list(self.channels.keys())}
        ))

        try:
            # Handle messages from client
            async for message in websocket:
                await self._handle_client_message(client, message)

        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Client {client_id} disconnected")
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            # Clean up client
            await self._disconnect_client(client)

    async def _handle_client_message(self, client: WebSocketClient, raw_message: str):
        """Handle a message from a client"""
        try:
            # Parse message
            data = json.loads(raw_message)
            message = WebSocketMessage(
                type=MessageType(data.get('type', 'event')),
                channel=data.get('channel'),
                data=data.get('data', {}),
                client_id=client.id
            )

            # Update client activity
            client.last_activity = datetime.now()

            # Route message based on type
            if message.type == MessageType.SUBSCRIBE:
                await self._handle_subscribe(client, message)
            elif message.type == MessageType.UNSUBSCRIBE:
                await self._handle_unsubscribe(client, message)
            elif message.type == MessageType.EVENT:
                await self._handle_event(client, message)
            elif message.type == MessageType.REQUEST:
                await self._handle_request(client, message)
            else:
                logger.warning(f"Unknown message type: {message.type}")

        except json.JSONDecodeError:
            await self._send_error(client, "Invalid JSON message")
        except Exception as e:
            logger.error(f"Error handling message: {e}")
            await self._send_error(client, str(e))

    async def _handle_subscribe(self, client: WebSocketClient, message: WebSocketMessage):
        """Handle channel subscription"""
        channel = message.data.get('channel')

        if channel and channel in self.channels:
            client.subscriptions.add(channel)
            self.channels[channel].add(client.id)

            await self._send_to_client(client, WebSocketMessage(
                type=MessageType.RESPONSE,
                data={'subscribed': channel}
            ))

            logger.info(f"Client {client.id} subscribed to {channel}")
        else:
            await self._send_error(client, f"Invalid channel: {channel}")

    async def _handle_unsubscribe(self, client: WebSocketClient, message: WebSocketMessage):
        """Handle channel unsubscription"""
        channel = message.data.get('channel')

        if channel in client.subscriptions:
            client.subscriptions.remove(channel)
            self.channels[channel].discard(client.id)

            await self._send_to_client(client, WebSocketMessage(
                type=MessageType.RESPONSE,
                data={'unsubscribed': channel}
            ))

            logger.info(f"Client {client.id} unsubscribed from {channel}")

    async def _handle_event(self, client: WebSocketClient, message: WebSocketMessage):
        """Handle UI event from client"""
        # Add to message queue for processing
        await self.message_queue.put(message)

        # Route to appropriate agent
        event_type = message.data.get('event_type')
        if event_type:
            await self._route_to_agent(event_type, message)

    async def _handle_request(self, client: WebSocketClient, message: WebSocketMessage):
        """Handle data request from client"""
        request_type = message.data.get('request_type')

        # Handle different request types
        if request_type == 'component':
            await self._handle_component_request(client, message)
        elif request_type == 'metrics':
            await self._handle_metrics_request(client, message)
        elif request_type == 'chart_data':
            await self._handle_chart_data_request(client, message)
        else:
            await self._send_error(client, f"Unknown request type: {request_type}")

    async def _handle_component_request(self, client: WebSocketClient, message: WebSocketMessage):
        """Handle component data request"""
        component_id = message.data.get('component_id')

        # Get component from UI agent (mock for demonstration)
        component_data = {
            'id': component_id,
            'type': 'card',
            'content': 'Requested component data',
            'timestamp': datetime.now().isoformat()
        }

        await self._send_to_client(client, WebSocketMessage(
            type=MessageType.RESPONSE,
            channel=Channel.COMPONENTS.value,
            data=component_data
        ))

    async def _handle_metrics_request(self, client: WebSocketClient, message: WebSocketMessage):
        """Handle metrics data request"""
        metrics = {
            'cpu': 45.2,
            'memory': 62.8,
            'requests': 1250,
            'timestamp': datetime.now().isoformat()
        }

        await self._send_to_client(client, WebSocketMessage(
            type=MessageType.RESPONSE,
            channel=Channel.METRICS.value,
            data=metrics
        ))

    async def _handle_chart_data_request(self, client: WebSocketClient, message: WebSocketMessage):
        """Handle chart data request"""
        chart_id = message.data.get('chart_id')

        # Generate sample chart data
        import random
        chart_data = {
            'id': chart_id,
            'labels': ['Jan', 'Feb', 'Mar', 'Apr', 'May'],
            'values': [random.randint(50, 200) for _ in range(5)],
            'timestamp': datetime.now().isoformat()
        }

        await self._send_to_client(client, WebSocketMessage(
            type=MessageType.RESPONSE,
            channel=Channel.CHARTS.value,
            data=chart_data
        ))

    async def broadcast_to_channel(self, channel: str, data: Dict[str, Any]):
        """Broadcast message to all clients subscribed to a channel"""
        if channel not in self.channels:
            logger.warning(f"Invalid channel: {channel}")
            return

        message = WebSocketMessage(
            type=MessageType.BROADCAST,
            channel=channel,
            data=data
        )

        # Send to all subscribed clients
        for client_id in self.channels[channel]:
            if client_id in self.clients:
                await self._send_to_client(self.clients[client_id], message)

        logger.info(f"Broadcast to {len(self.channels[channel])} clients on {channel}")

    async def send_update(self, client_id: str, update_type: str, data: Dict[str, Any]):
        """Send update to specific client"""
        if client_id in self.clients:
            message = WebSocketMessage(
                type=MessageType.UPDATE,
                data={'update_type': update_type, **data}
            )
            await self._send_to_client(self.clients[client_id], message)

    async def _send_to_client(self, client: WebSocketClient, message: WebSocketMessage):
        """Send message to a specific client"""
        try:
            await client.websocket.send(json.dumps({
                'id': message.id,
                'type': message.type.value,
                'channel': message.channel,
                'data': message.data,
                'timestamp': message.timestamp.isoformat()
            }))
        except Exception as e:
            logger.error(f"Error sending to client {client.id}: {e}")
            await self._disconnect_client(client)

    async def _send_error(self, client: WebSocketClient, error_message: str):
        """Send error message to client"""
        await self._send_to_client(client, WebSocketMessage(
            type=MessageType.ERROR,
            data={'error': error_message}
        ))

    async def _disconnect_client(self, client: WebSocketClient):
        """Disconnect and clean up client"""
        # Remove from channels
        for channel in client.subscriptions:
            self.channels[channel].discard(client.id)

        # Remove from clients
        if client.id in self.clients:
            del self.clients[client.id]

        logger.info(f"Client {client.id} disconnected and cleaned up")

    async def _route_to_agent(self, event_type: str, message: WebSocketMessage):
        """Route message to appropriate agent"""
        # This would connect to actual agents in production
        agent_map = {
            'click': 'input_agent',
            'form_submit': 'form_agent',
            'chart_update': 'chart_agent',
            'session_update': 'session_agent'
        }

        agent = agent_map.get(event_type)
        if agent and agent in self.agent_connections:
            # Forward to agent
            await self.agent_connections[agent].process_message(message)

    async def _process_messages(self):
        """Process queued messages"""
        while True:
            try:
                message = await self.message_queue.get()

                # Process message based on type
                if message.channel:
                    # Broadcast to channel subscribers
                    await self.broadcast_to_channel(message.channel, message.data)

            except Exception as e:
                logger.error(f"Message processing error: {e}")

            await asyncio.sleep(0.01)

    async def _send_heartbeats(self):
        """Send periodic heartbeats to all clients"""
        while True:
            try:
                heartbeat = WebSocketMessage(
                    type=MessageType.HEARTBEAT,
                    data={'timestamp': datetime.now().isoformat()}
                )

                disconnected = []
                for client_id, client in self.clients.items():
                    try:
                        await self._send_to_client(client, heartbeat)
                    except:
                        disconnected.append(client_id)

                # Clean up disconnected clients
                for client_id in disconnected:
                    if client_id in self.clients:
                        await self._disconnect_client(self.clients[client_id])

            except Exception as e:
                logger.error(f"Heartbeat error: {e}")

            await asyncio.sleep(30)  # Send heartbeat every 30 seconds

    def register_agent(self, agent_name: str, agent_connection: Any):
        """Register an agent connection for message routing"""
        self.agent_connections[agent_name] = agent_connection
        logger.info(f"Registered agent: {agent_name}")

    async def get_stats(self) -> Dict[str, Any]:
        """Get WebSocket server statistics"""
        return {
            'total_clients': len(self.clients),
            'channels': {
                channel: len(clients)
                for channel, clients in self.channels.items()
            },
            'message_queue_size': self.message_queue.qsize(),
            'registered_agents': list(self.agent_connections.keys())
        }


class WebSocketClientManager:
    """
    Client-side WebSocket manager for UI components
    Handles connection, reconnection, and message handling
    """

    def __init__(self, url: str):
        self.url = url
        self.websocket = None
        self.client_id = None
        self.subscriptions = set()
        self.message_handlers = {}
        self.reconnect_interval = 5  # seconds

    async def connect(self):
        """Connect to WebSocket server"""
        try:
            self.websocket = await websockets.connect(self.url)
            logger.info(f"Connected to WebSocket server at {self.url}")

            # Start message handler
            asyncio.create_task(self._handle_messages())

            # Start reconnection monitor
            asyncio.create_task(self._monitor_connection())

            return True

        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    async def subscribe(self, channel: str):
        """Subscribe to a channel"""
        if self.websocket:
            message = {
                'type': MessageType.SUBSCRIBE.value,
                'data': {'channel': channel}
            }
            await self.websocket.send(json.dumps(message))
            self.subscriptions.add(channel)
            logger.info(f"Subscribed to channel: {channel}")

    async def unsubscribe(self, channel: str):
        """Unsubscribe from a channel"""
        if self.websocket and channel in self.subscriptions:
            message = {
                'type': MessageType.UNSUBSCRIBE.value,
                'data': {'channel': channel}
            }
            await self.websocket.send(json.dumps(message))
            self.subscriptions.remove(channel)
            logger.info(f"Unsubscribed from channel: {channel}")

    async def send_event(self, event_type: str, data: Dict[str, Any]):
        """Send UI event to server"""
        if self.websocket:
            message = {
                'type': MessageType.EVENT.value,
                'data': {'event_type': event_type, **data}
            }
            await self.websocket.send(json.dumps(message))

    async def request_data(self, request_type: str, params: Dict[str, Any]):
        """Request data from server"""
        if self.websocket:
            message = {
                'type': MessageType.REQUEST.value,
                'data': {'request_type': request_type, **params}
            }
            await self.websocket.send(json.dumps(message))

    def on_message(self, message_type: str, handler: callable):
        """Register message handler"""
        self.message_handlers[message_type] = handler

    async def _handle_messages(self):
        """Handle incoming messages"""
        try:
            async for message in self.websocket:
                data = json.loads(message)
                message_type = data.get('type')

                # Store client ID
                if message_type == 'connect':
                    self.client_id = data['data'].get('client_id')

                # Call registered handler
                if message_type in self.message_handlers:
                    await self.message_handlers[message_type](data)

                logger.debug(f"Received message: {message_type}")

        except websockets.exceptions.ConnectionClosed:
            logger.warning("WebSocket connection closed")
            await self._reconnect()
        except Exception as e:
            logger.error(f"Message handling error: {e}")

    async def _monitor_connection(self):
        """Monitor connection and reconnect if needed"""
        while True:
            if not self.websocket or self.websocket.closed:
                await self._reconnect()
            await asyncio.sleep(self.reconnect_interval)

    async def _reconnect(self):
        """Attempt to reconnect to server"""
        logger.info("Attempting to reconnect...")
        if await self.connect():
            # Re-subscribe to channels
            for channel in self.subscriptions:
                await self.subscribe(channel)
            logger.info("Reconnection successful")

    async def disconnect(self):
        """Disconnect from server"""
        if self.websocket:
            await self.websocket.close()
            logger.info("Disconnected from WebSocket server")


# Example usage
async def test_websocket_router():
    """Test the WebSocket router"""

    # Start server
    router = WebSocketRouter()

    # Start in background
    asyncio.create_task(router.start())

    # Wait a bit for server to start
    await asyncio.sleep(2)

    # Create client
    client_manager = WebSocketClientManager("ws://localhost:8765")

    # Connect client
    if await client_manager.connect():
        # Subscribe to channels
        await client_manager.subscribe(Channel.COMPONENTS.value)
        await client_manager.subscribe(Channel.METRICS.value)

        # Send an event
        await client_manager.send_event("click", {"target": "button_1"})

        # Request data
        await client_manager.request_data("metrics", {})

        # Wait for messages
        await asyncio.sleep(5)

        # Get server stats
        stats = await router.get_stats()
        print(f"Server stats: {stats}")

        # Disconnect
        await client_manager.disconnect()


if __name__ == "__main__":
    asyncio.run(test_websocket_router())