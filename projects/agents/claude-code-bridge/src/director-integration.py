#!/usr/bin/env python3
"""
Director Agent Integration for Claude Code Bridge
Provides Python-side coordination between Claude Code and Director Agents
"""

import asyncio
import json
import redis
import sys
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ClaudeCodeDirectorIntegration:
    """Integration layer between Claude Code Bridge and Director Agent system"""

    def __init__(self):
        """Initialize the integration system"""
        self.redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
        self.pubsub = None
        self.running = False
        self.tasks_processed = 0

        # Track registered agents and active tasks
        self.registered_agents = {}
        self.active_tasks = {}
        self.task_routing_map = {}

        # Enhanced capability registry with metadata
        self.capability_registry = {}

        # Agent capability mappings for intelligent routing (legacy support)
        self.capability_agents = {
            'code_generation': [],
            'code_analysis': [],
            'documentation': [],
            'debugging': [],
            'testing': [],
            'project_orchestration': []
        }

        # Performance metrics tracking
        self.agent_performance = {}

        # Capability discovery cache
        self.discovery_cache = {
            'last_updated': datetime.now(),
            'cache_ttl': 300  # 5 minutes
        }

        # Real-time progress monitoring
        self.progress_tracking = {}
        self.monitoring_sessions = {}
        self.progress_analytics = {
            'total_tasks_monitored': 0,
            'average_completion_time': 0,
            'task_completion_trends': [],
            'bottleneck_analysis': {},
            'resource_utilization': {}
        }

    async def start(self):
        """Start the integration system"""
        logger.info("Starting Claude Code Director Integration...")

        try:
            # Test Redis connection
            self.redis_client.ping()
            logger.info("Connected to Redis successfully")

            # Set up pub/sub
            self.pubsub = self.redis_client.pubsub()

            # Subscribe to Claude Code channels
            self.pubsub.subscribe('agent:broadcast')
            self.pubsub.subscribe('agent:director')
            self.pubsub.subscribe('agent:registry')
            self.pubsub.subscribe('tasks:claude-code')

            # Subscribe to task response channels
            self.pubsub.subscribe('tasks:responses')
            self.pubsub.subscribe('agent:task_complete')
            self.pubsub.subscribe('agent:task_failed')

            # Subscribe to capability discovery channels
            self.pubsub.subscribe('capability:query')
            self.pubsub.subscribe('capability:announce')

            # Subscribe to progress monitoring channels
            self.pubsub.subscribe('progress:update')
            self.pubsub.subscribe('progress:milestone')
            self.pubsub.subscribe('progress:subscribe')
            self.pubsub.subscribe('progress:analytics')

            logger.info("Subscribed to Redis channels")

            # Register this integration as a director agent
            await self.register_director_agent()

            # Start main loop
            self.running = True
            logger.info("Claude Code Director Integration started successfully")

            return True

        except Exception as e:
            logger.error(f"Failed to start integration: {e}")
            return False

    async def register_director_agent(self):
        """Register this integration as a director agent in the system"""
        agent_info = {
            'id': 'director-integration',
            'type': 'director',
            'status': 'online',
            'capabilities': ['task_coordination', 'agent_management', 'message_routing'],
            'registered_at': datetime.now().isoformat(),
            'last_heartbeat': datetime.now().isoformat()
        }

        # Store in Redis (convert all values to strings)
        redis_data = {k: str(v) if not isinstance(v, str) else v for k, v in agent_info.items()}
        redis_data['capabilities'] = json.dumps(agent_info['capabilities'])

        self.redis_client.hset('agent:director-integration', mapping=redis_data)
        self.redis_client.sadd('active_agents', 'director-integration')
        self.redis_client.sadd('active_agents:director', 'director-integration')

        # Publish registration message
        registration_message = {
            'id': f'reg-{datetime.now().timestamp()}',
            'type': 'agent_register',
            'sender': 'director-integration',
            'recipient': 'registry',
            'payload': {
                'agent_id': 'director-integration',
                'agent_type': 'director',
                'capabilities': agent_info['capabilities'],
                'metadata': {
                    'version': '1.0.0',
                    'language': 'python',
                    'framework': 'claude-code-bridge-integration'
                }
            },
            'timestamp': datetime.now().isoformat()
        }

        self.redis_client.publish('agent:registry', json.dumps(registration_message))
        logger.info("Director agent registered with system")

    async def message_loop(self):
        """Main message processing loop"""
        logger.info("Starting message processing loop...")

        while self.running:
            try:
                # Get message from pub/sub
                message = self.pubsub.get_message(timeout=1.0)

                if message and message['type'] == 'message':
                    await self.handle_message(message)

                # Send heartbeat every 30 seconds
                if int(datetime.now().timestamp()) % 30 == 0:
                    await self.send_heartbeat()

                await asyncio.sleep(0.1)

            except Exception as e:
                logger.error(f"Error in message loop: {e}")
                await asyncio.sleep(1)

    async def handle_message(self, message):
        """Handle incoming Redis messages"""
        try:
            channel = message['channel']
            data = json.loads(message['data'])

            logger.info(f"Received message on {channel}: {data.get('type', 'unknown')}")

            message_type = data.get('type', '')

            if message_type == 'agent_register':
                await self.handle_agent_registration(data)
            elif message_type == 'task_assignment':
                await self.handle_task_assignment(data)
            elif message_type == 'agent_heartbeat':
                await self.handle_agent_heartbeat(data)
            elif message_type == 'task_complete':
                await self.handle_task_completion(data)
            elif message_type == 'task_failed':
                await self.handle_task_failure(data)
            elif message_type == 'task_progress':
                await self.handle_task_progress(data)
            elif message_type == 'capability_query':
                await self.handle_capability_query(data)
            elif message_type == 'capability_announce':
                await self.handle_capability_announcement(data)
            elif message_type == 'progress_update':
                await self.handle_progress_update(data)
            elif message_type == 'task_metrics':
                await self.handle_task_metrics(data)
            elif message_type == 'bottleneck_report':
                await self.handle_bottleneck_report(data)
            elif message_type == 'progress_subscribe':
                await self.handle_progress_subscription(data)
            elif message_type == 'get_task_analytics':
                await self.handle_task_analytics_request(data)
            else:
                logger.debug(f"Unhandled message type: {message_type}")

        except Exception as e:
            logger.error(f"Error handling message: {e}")

    async def handle_agent_registration(self, data):
        """Handle agent registration messages with enhanced capability metadata"""
        agent_id = data.get('payload', {}).get('agent_id')
        agent_type = data.get('payload', {}).get('agent_type')
        capabilities = data.get('payload', {}).get('capabilities', [])
        metadata = data.get('payload', {}).get('metadata', {})

        if agent_id and agent_type:
            # Enhanced agent registration with metadata
            registration_time = datetime.now()

            self.registered_agents[agent_id] = {
                'type': agent_type,
                'capabilities': capabilities,
                'registered_at': registration_time,
                'last_seen': registration_time,
                'status': 'online',
                'current_tasks': [],
                'metadata': metadata
            }

            # Build enhanced capability registry
            await self.register_agent_capabilities(agent_id, agent_type, capabilities, metadata)

            # Update legacy capability mappings for backward compatibility
            for capability in capabilities:
                if capability in self.capability_agents:
                    if agent_id not in self.capability_agents[capability]:
                        self.capability_agents[capability].append(agent_id)

            # Initialize performance tracking
            if agent_id not in self.agent_performance:
                self.agent_performance[agent_id] = {
                    'total_tasks': 0,
                    'completed_tasks': 0,
                    'failed_tasks': 0,
                    'avg_response_time': 0,
                    'success_rate': 1.0,
                    'last_performance_update': registration_time
                }

            logger.info(f"Enhanced registration: {agent_id} (type: {agent_type}) with capabilities: {capabilities}")
            logger.info(f"Agent metadata: {metadata}")

            # Send welcome message with enhanced system info
            await self.send_agent_welcome(agent_id)

            # Broadcast capability announcement
            await self.broadcast_capability_update(agent_id, 'registered')

    async def handle_task_assignment(self, data):
        """Handle task assignment messages"""
        task_id = data.get('payload', {}).get('task', {}).get('id', 'unknown')
        task_type = data.get('payload', {}).get('task', {}).get('type', 'unknown')

        logger.info(f"Processing task assignment: {task_id} (type: {task_type})")

        # Route task to appropriate agents
        await self.route_task(data)
        self.tasks_processed += 1

    async def handle_agent_heartbeat(self, data):
        """Handle agent heartbeat messages"""
        agent_id = data.get('payload', {}).get('agent_id')

        if agent_id in self.registered_agents:
            self.registered_agents[agent_id]['last_seen'] = datetime.now()

    async def route_task(self, task_data):
        """Route tasks to appropriate agents with intelligent routing"""
        task = task_data.get('payload', {}).get('task', {})
        task_type = task.get('type', '')
        task_id = task.get('id', 'unknown')
        required_capabilities = task_data.get('payload', {}).get('required_capabilities', [])
        sender = task_data.get('sender')

        logger.info(f"Routing task {task_id} of type {task_type} with required capabilities: {required_capabilities}")

        # Store task for tracking with enhanced progress monitoring
        task_start_time = datetime.now()
        self.active_tasks[task_id] = {
            'task': task,
            'sender': sender,
            'created_at': task_start_time,
            'status': 'routing',
            'assigned_agent': None
        }

        # Initialize progress tracking
        await self.initialize_progress_tracking(task_id, task_type, required_capabilities, sender)

        # Find best agent for the task
        target_agent = await self.find_best_agent(task_type, required_capabilities)

        if target_agent:
            # Assign task to specific agent
            await self.assign_task_to_agent(task_data, target_agent)
        else:
            # No suitable agent found, simulate task processing
            await self.simulate_task_processing(task_data)

        # Always acknowledge task receipt
        await self.send_task_acknowledgment(task_id, sender)

    async def send_heartbeat(self):
        """Send heartbeat to maintain agent status"""
        heartbeat = {
            'id': f'hb-{datetime.now().timestamp()}',
            'type': 'agent_heartbeat',
            'sender': 'director-integration',
            'recipient': 'registry',
            'payload': {
                'agent_id': 'director-integration',
                'status': 'online',
                'tasks_processed': self.tasks_processed,
                'registered_agents': len(self.registered_agents)
            },
            'timestamp': datetime.now().isoformat()
        }

        self.redis_client.publish('agent:registry', json.dumps(heartbeat))
        self.redis_client.hset('agent:director-integration', 'last_heartbeat', datetime.now().isoformat())

    async def find_best_agent(self, task_type: str, required_capabilities: list) -> Optional[str]:
        """Find the best agent for a given task based on capabilities and availability"""
        if not required_capabilities:
            # If no specific capabilities required, try to match task type to capability
            capability_mapping = {
                'code_analysis': 'code_analysis',
                'code_generation': 'code_generation',
                'documentation': 'documentation',
                'debug': 'debugging',
                'test': 'testing'
            }
            required_capabilities = [capability_mapping.get(task_type, 'code_analysis')]

        # Find agents with required capabilities
        candidate_agents = []
        for capability in required_capabilities:
            if capability in self.capability_agents:
                candidate_agents.extend(self.capability_agents[capability])

        # Filter to active agents with lowest task load
        available_agents = []
        for agent_id in set(candidate_agents):
            if agent_id in self.registered_agents:
                agent = self.registered_agents[agent_id]
                if agent['status'] == 'online':
                    available_agents.append((agent_id, len(agent['current_tasks'])))

        # Sort by task load (ascending) and return agent with least load
        if available_agents:
            available_agents.sort(key=lambda x: x[1])
            return available_agents[0][0]

        return None

    async def assign_task_to_agent(self, task_data: Dict[str, Any], target_agent: str):
        """Assign a task to a specific agent"""
        task = task_data.get('payload', {}).get('task', {})
        task_id = task.get('id', 'unknown')

        # Update task tracking
        if task_id in self.active_tasks:
            self.active_tasks[task_id]['assigned_agent'] = target_agent
            self.active_tasks[task_id]['status'] = 'assigned'

        # Add task to agent's current tasks
        if target_agent in self.registered_agents:
            self.registered_agents[target_agent]['current_tasks'].append(task_id)

        # Send task to the target agent
        assignment_message = {
            'id': f'assign-{datetime.now().timestamp()}',
            'type': 'task_assignment',
            'sender': 'director-integration',
            'recipient': target_agent,
            'payload': task_data.get('payload', {}),
            'timestamp': datetime.now().isoformat()
        }

        self.redis_client.publish(f'agent:{target_agent}', json.dumps(assignment_message))
        logger.info(f"Assigned task {task_id} to agent {target_agent}")

    async def simulate_task_processing(self, task_data: Dict[str, Any]):
        """Simulate task processing when no specific agent is available"""
        task = task_data.get('payload', {}).get('task', {})
        task_id = task.get('id', 'unknown')
        task_type = task.get('type', 'unknown')

        logger.info(f"Simulating processing for task {task_id} of type {task_type}")

        # Update task status
        if task_id in self.active_tasks:
            self.active_tasks[task_id]['status'] = 'processing'
            self.active_tasks[task_id]['assigned_agent'] = 'director-integration'

        # Simulate some processing time (in real implementation, this would be actual work)
        await asyncio.sleep(1)

        # Generate simulated result based on task type
        result = await self.generate_simulated_result(task_type, task.get('data', {}))

        # Send completion message
        await self.send_task_completion(task_id, task_data.get('sender'), result)

    async def generate_simulated_result(self, task_type: str, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate simulated results for different task types"""
        if task_type == 'code_analysis':
            return {
                'analysis': 'Code analysis completed by Director Integration',
                'issues_found': 0,
                'suggestions': ['Code looks good!'],
                'processed_by': 'director-integration'
            }
        elif task_type == 'code_generation':
            return {
                'generated_code': '// Code generated by Director Integration\nconsole.log("Hello from Director!");',
                'language': 'javascript',
                'processed_by': 'director-integration'
            }
        elif task_type == 'documentation':
            return {
                'documentation': 'Documentation generated by Director Integration',
                'format': 'markdown',
                'processed_by': 'director-integration'
            }
        else:
            return {
                'message': f'Task of type {task_type} processed by Director Integration',
                'processed_by': 'director-integration',
                'task_data': task_data
            }

    async def send_task_acknowledgment(self, task_id: str, sender: str):
        """Send task acknowledgment to the requesting agent"""
        response = {
            'id': f'ack-{datetime.now().timestamp()}',
            'type': 'task_acknowledged',
            'sender': 'director-integration',
            'recipient': sender,
            'payload': {
                'task_id': task_id,
                'status': 'acknowledged',
                'message': 'Task received and being processed by Director Integration'
            },
            'timestamp': datetime.now().isoformat()
        }

        if sender:
            self.redis_client.publish(f'agent:{sender}', json.dumps(response))
            logger.info(f"Sent acknowledgment for task {task_id} to {sender}")

    async def send_task_completion(self, task_id: str, sender: str, result: Dict[str, Any]):
        """Send task completion message back to the requesting agent"""
        completion_message = {
            'id': f'complete-{datetime.now().timestamp()}',
            'type': 'task_complete',
            'sender': 'director-integration',
            'recipient': sender,
            'payload': {
                'task_id': task_id,
                'status': 'completed',
                'result': result,
                'completed_at': datetime.now().isoformat()
            },
            'timestamp': datetime.now().isoformat()
        }

        if sender:
            self.redis_client.publish(f'agent:{sender}', json.dumps(completion_message))
            logger.info(f"Sent completion for task {task_id} to {sender}")

        # Update task tracking
        if task_id in self.active_tasks:
            self.active_tasks[task_id]['status'] = 'completed'
            self.active_tasks[task_id]['completed_at'] = datetime.now()

    async def send_agent_welcome(self, agent_id: str):
        """Send welcome message to newly registered agent"""
        welcome_message = {
            'id': f'welcome-{datetime.now().timestamp()}',
            'type': 'agent_welcome',
            'sender': 'director-integration',
            'recipient': agent_id,
            'payload': {
                'message': 'Welcome to the Director Agent system!',
                'system_status': {
                    'total_agents': len(self.registered_agents),
                    'active_tasks': len(self.active_tasks)
                }
            },
            'timestamp': datetime.now().isoformat()
        }

        self.redis_client.publish(f'agent:{agent_id}', json.dumps(welcome_message))
        logger.info(f"Sent welcome message to agent {agent_id}")

    async def handle_task_completion(self, data: Dict[str, Any]):
        """Handle task completion messages from other agents"""
        task_id = data.get('payload', {}).get('task_id')
        agent_id = data.get('sender')
        result = data.get('payload', {}).get('result', {})
        completed_at = datetime.now()

        logger.info(f"Task {task_id} completed by agent {agent_id}")

        # Update performance metrics
        await self.update_agent_performance(agent_id, task_id, 'completed', completed_at)

        # Update task tracking
        if task_id in self.active_tasks:
            original_sender = self.active_tasks[task_id]['sender']
            task_start_time = self.active_tasks[task_id]['created_at']
            execution_time = (completed_at - task_start_time).total_seconds()

            self.active_tasks[task_id]['status'] = 'completed'
            self.active_tasks[task_id]['completed_at'] = completed_at
            self.active_tasks[task_id]['execution_time'] = execution_time

            # Forward completion to original requester
            if original_sender:
                await self.send_task_completion(task_id, original_sender, result)

        # Remove task from agent's current tasks
        if agent_id in self.registered_agents:
            if task_id in self.registered_agents[agent_id]['current_tasks']:
                self.registered_agents[agent_id]['current_tasks'].remove(task_id)

    async def handle_task_failure(self, data: Dict[str, Any]):
        """Handle task failure messages from other agents"""
        task_id = data.get('payload', {}).get('task_id')
        agent_id = data.get('sender')
        error = data.get('payload', {}).get('error', 'Unknown error')
        failed_at = datetime.now()

        logger.error(f"Task {task_id} failed on agent {agent_id}: {error}")

        # Update performance metrics
        await self.update_agent_performance(agent_id, task_id, 'failed', failed_at)

        # Update task tracking
        if task_id in self.active_tasks:
            original_sender = self.active_tasks[task_id]['sender']
            self.active_tasks[task_id]['status'] = 'failed'
            self.active_tasks[task_id]['error'] = error
            self.active_tasks[task_id]['failed_at'] = failed_at

            # Send failure notification to original requester
            if original_sender:
                failure_message = {
                    'id': f'failed-{datetime.now().timestamp()}',
                    'type': 'task_failed',
                    'sender': 'director-integration',
                    'recipient': original_sender,
                    'payload': {
                        'task_id': task_id,
                        'status': 'failed',
                        'error': error,
                        'failed_at': failed_at.isoformat()
                    },
                    'timestamp': datetime.now().isoformat()
                }
                self.redis_client.publish(f'agent:{original_sender}', json.dumps(failure_message))

        # Remove task from agent's current tasks
        if agent_id in self.registered_agents:
            if task_id in self.registered_agents[agent_id]['current_tasks']:
                self.registered_agents[agent_id]['current_tasks'].remove(task_id)

    async def handle_task_progress(self, data: Dict[str, Any]):
        """Handle task progress updates from other agents"""
        task_id = data.get('payload', {}).get('task_id')
        agent_id = data.get('sender')
        progress = data.get('payload', {}).get('progress', 0)

        logger.info(f"Task {task_id} progress from agent {agent_id}: {progress}%")

        # Forward progress to original requester
        if task_id in self.active_tasks:
            original_sender = self.active_tasks[task_id]['sender']
            if original_sender:
                progress_message = {
                    'id': f'progress-{datetime.now().timestamp()}',
                    'type': 'task_progress',
                    'sender': 'director-integration',
                    'recipient': original_sender,
                    'payload': {
                        'task_id': task_id,
                        'progress': progress,
                        'agent_id': agent_id
                    },
                    'timestamp': datetime.now().isoformat()
                }
                self.redis_client.publish(f'agent:{original_sender}', json.dumps(progress_message))

    async def register_agent_capabilities(self, agent_id: str, agent_type: str, capabilities: list, metadata: dict):
        """Register agent capabilities with enhanced metadata"""
        capability_entry = {
            'agent_id': agent_id,
            'agent_type': agent_type,
            'capabilities_detail': {},
            'discovery_metadata': {
                'last_updated': datetime.now().isoformat(),
                'agent_version': metadata.get('version', '1.0.0'),
                'language': metadata.get('language', 'unknown'),
                'framework': metadata.get('framework', 'unknown'),
                'supported_protocols': ['redis', 'websocket'],
                'max_concurrent_tasks': metadata.get('max_concurrent_tasks', 5)
            }
        }

        # Build detailed capability information
        for capability in capabilities:
            capability_entry['capabilities_detail'][capability] = {
                'version': '1.0.0',
                'supported_languages': self._infer_supported_languages(capability, metadata),
                'complexity_level': 'advanced',
                'estimated_time': self._estimate_capability_time(capability),
                'reliability_score': 1.0  # Will be updated based on performance
            }

        self.capability_registry[agent_id] = capability_entry

        # Store in Redis for persistence
        redis_key = f'capability_registry:{agent_id}'
        self.redis_client.hset(redis_key, mapping={
            'data': json.dumps(capability_entry, default=str),
            'last_updated': datetime.now().isoformat()
        })

        logger.info(f"Registered enhanced capabilities for {agent_id}: {list(capability_entry['capabilities_detail'].keys())}")

    def _infer_supported_languages(self, capability: str, metadata: dict) -> list:
        """Infer supported programming languages based on capability and metadata"""
        base_languages = ['javascript', 'python', 'typescript']

        if capability == 'code_generation':
            return base_languages + ['java', 'go', 'rust']
        elif capability == 'code_analysis':
            return base_languages + ['c++', 'java', 'go']
        elif capability == 'documentation':
            return ['markdown', 'html', 'latex']
        else:
            return base_languages

    def _estimate_capability_time(self, capability: str) -> dict:
        """Estimate typical execution time for capabilities"""
        time_estimates = {
            'code_generation': {'min': 2, 'avg': 5, 'max': 15},
            'code_analysis': {'min': 1, 'avg': 3, 'max': 10},
            'documentation': {'min': 3, 'avg': 8, 'max': 20},
            'debugging': {'min': 5, 'avg': 12, 'max': 30},
            'testing': {'min': 2, 'avg': 6, 'max': 15},
            'project_orchestration': {'min': 10, 'avg': 25, 'max': 60}
        }
        return time_estimates.get(capability, {'min': 1, 'avg': 5, 'max': 15})

    async def broadcast_capability_update(self, agent_id: str, update_type: str):
        """Broadcast capability updates to the ecosystem"""
        if agent_id in self.capability_registry:
            capability_info = self.capability_registry[agent_id]

            broadcast_message = {
                'id': f'capability-{datetime.now().timestamp()}',
                'type': 'capability_update',
                'sender': 'director-integration',
                'recipient': 'all',
                'payload': {
                    'update_type': update_type,  # 'registered', 'updated', 'removed'
                    'agent_id': agent_id,
                    'capabilities': list(capability_info['capabilities_detail'].keys()),
                    'capability_details': capability_info['capabilities_detail'],
                    'discovery_metadata': capability_info['discovery_metadata']
                },
                'timestamp': datetime.now().isoformat()
            }

            # Broadcast to all agents
            self.redis_client.publish('agent:broadcast', json.dumps(broadcast_message))
            logger.info(f"Broadcasted capability update for {agent_id}: {update_type}")

    async def discover_agents_by_capability(self, required_capability: str, filters: dict = None) -> list:
        """Discover agents that have a specific capability with optional filters"""
        matching_agents = []

        for agent_id, capability_info in self.capability_registry.items():
            if required_capability in capability_info['capabilities_detail']:
                agent_data = {
                    'agent_id': agent_id,
                    'agent_type': capability_info['agent_type'],
                    'capability_detail': capability_info['capabilities_detail'][required_capability],
                    'discovery_metadata': capability_info['discovery_metadata'],
                    'performance': self.agent_performance.get(agent_id, {}),
                    'current_load': len(self.registered_agents.get(agent_id, {}).get('current_tasks', []))
                }

                # Apply filters if provided
                if filters:
                    if self._apply_discovery_filters(agent_data, filters):
                        matching_agents.append(agent_data)
                else:
                    matching_agents.append(agent_data)

        # Sort by performance and load
        matching_agents.sort(key=lambda x: (
            -x['performance'].get('success_rate', 1.0),  # Higher success rate first
            x['current_load'],  # Lower load first
            x['performance'].get('avg_response_time', 0)  # Faster response first
        ))

        return matching_agents

    def _apply_discovery_filters(self, agent_data: dict, filters: dict) -> bool:
        """Apply discovery filters to agent data"""
        # Language filter
        if 'language' in filters:
            supported_langs = agent_data['capability_detail'].get('supported_languages', [])
            if filters['language'] not in supported_langs:
                return False

        # Performance filter
        if 'min_success_rate' in filters:
            success_rate = agent_data['performance'].get('success_rate', 1.0)
            if success_rate < filters['min_success_rate']:
                return False

        # Load filter
        if 'max_load' in filters:
            if agent_data['current_load'] > filters['max_load']:
                return False

        return True

    async def get_capability_network_map(self) -> dict:
        """Generate a network map of all agents and their capabilities"""
        network_map = {
            'agents': {},
            'capabilities': {},
            'connections': [],
            'statistics': {
                'total_agents': len(self.capability_registry),
                'total_capabilities': len(set(
                    cap for agent in self.capability_registry.values()
                    for cap in agent['capabilities_detail'].keys()
                )),
                'avg_capabilities_per_agent': 0,
                'system_load': sum(
                    len(agent.get('current_tasks', []))
                    for agent in self.registered_agents.values()
                )
            }
        }

        # Build agent nodes
        for agent_id, capability_info in self.capability_registry.items():
            agent_status = self.registered_agents.get(agent_id, {})
            performance = self.agent_performance.get(agent_id, {})

            network_map['agents'][agent_id] = {
                'type': capability_info['agent_type'],
                'capabilities': list(capability_info['capabilities_detail'].keys()),
                'status': agent_status.get('status', 'unknown'),
                'current_load': len(agent_status.get('current_tasks', [])),
                'performance': performance,
                'metadata': capability_info['discovery_metadata']
            }

        # Build capability nodes
        capability_counts = {}
        for agent_info in self.capability_registry.values():
            for capability in agent_info['capabilities_detail'].keys():
                capability_counts[capability] = capability_counts.get(capability, 0) + 1

        network_map['capabilities'] = {
            cap: {'agent_count': count, 'utilization': 0}  # TODO: Calculate utilization
            for cap, count in capability_counts.items()
        }

        # Calculate statistics
        if network_map['statistics']['total_agents'] > 0:
            total_caps = sum(len(agent['capabilities']) for agent in network_map['agents'].values())
            network_map['statistics']['avg_capabilities_per_agent'] = total_caps / network_map['statistics']['total_agents']

        return network_map

    async def update_agent_performance(self, agent_id: str, task_id: str, status: str, completion_time: datetime):
        """Update agent performance metrics based on task completion"""
        if agent_id not in self.agent_performance:
            self.agent_performance[agent_id] = {
                'total_tasks': 0,
                'completed_tasks': 0,
                'failed_tasks': 0,
                'avg_response_time': 0,
                'success_rate': 1.0,
                'last_performance_update': completion_time
            }

        performance = self.agent_performance[agent_id]
        performance['total_tasks'] += 1
        performance['last_performance_update'] = completion_time

        if status == 'completed':
            performance['completed_tasks'] += 1

            # Update response time if task exists in active_tasks
            if task_id in self.active_tasks:
                task_start = self.active_tasks[task_id]['created_at']
                response_time = (completion_time - task_start).total_seconds()

                # Calculate rolling average response time
                current_avg = performance['avg_response_time']
                total_completed = performance['completed_tasks']
                performance['avg_response_time'] = (
                    (current_avg * (total_completed - 1) + response_time) / total_completed
                )
        elif status == 'failed':
            performance['failed_tasks'] += 1

        # Update success rate
        if performance['total_tasks'] > 0:
            performance['success_rate'] = performance['completed_tasks'] / performance['total_tasks']

        # Update capability reliability scores
        if agent_id in self.capability_registry:
            for capability in self.capability_registry[agent_id]['capabilities_detail']:
                cap_detail = self.capability_registry[agent_id]['capabilities_detail'][capability]
                cap_detail['reliability_score'] = performance['success_rate']

        logger.info(f"Updated performance for {agent_id}: {performance['completed_tasks']}/{performance['total_tasks']} success rate: {performance['success_rate']:.2f}")

    async def handle_capability_query(self, data: Dict[str, Any]):
        """Handle capability discovery queries from agents"""
        query_id = data.get('id')
        sender = data.get('sender')
        query_params = data.get('payload', {})
        required_capability = query_params.get('capability')
        filters = query_params.get('filters', {})

        logger.info(f"Capability query from {sender} for '{required_capability}' with filters: {filters}")

        # Discover matching agents
        matching_agents = await self.discover_agents_by_capability(required_capability, filters)

        # Send response back to requester
        response_message = {
            'id': f'query-resp-{datetime.now().timestamp()}',
            'type': 'capability_query_response',
            'sender': 'director-integration',
            'recipient': sender,
            'payload': {
                'query_id': query_id,
                'capability': required_capability,
                'matching_agents': matching_agents,
                'total_found': len(matching_agents),
                'query_processed_at': datetime.now().isoformat()
            },
            'timestamp': datetime.now().isoformat()
        }

        if sender:
            self.redis_client.publish(f'agent:{sender}', json.dumps(response_message))
            logger.info(f"Sent capability query response to {sender}: {len(matching_agents)} agents found")

    async def handle_capability_announcement(self, data: Dict[str, Any]):
        """Handle capability announcements from agents"""
        sender = data.get('sender')
        announcement = data.get('payload', {})
        update_type = announcement.get('update_type', 'update')  # 'update', 'add', 'remove'
        capabilities = announcement.get('capabilities', [])
        metadata = announcement.get('metadata', {})

        logger.info(f"Capability announcement from {sender}: {update_type} - {capabilities}")

        if update_type == 'update' and sender in self.capability_registry:
            # Update existing capability registry
            await self.register_agent_capabilities(
                sender,
                self.registered_agents.get(sender, {}).get('type', 'unknown'),
                capabilities,
                metadata
            )

            # Update discovery cache timestamp
            self.discovery_cache['last_updated'] = datetime.now()

            # Broadcast the update to other agents
            await self.broadcast_capability_update(sender, 'updated')

        elif update_type == 'remove':
            # Handle capability removal
            if sender in self.capability_registry:
                for capability in capabilities:
                    if capability in self.capability_registry[sender]['capabilities_detail']:
                        del self.capability_registry[sender]['capabilities_detail'][capability]

                        # Remove from legacy mapping
                        if capability in self.capability_agents and sender in self.capability_agents[capability]:
                            self.capability_agents[capability].remove(sender)

                logger.info(f"Removed capabilities {capabilities} from {sender}")
                await self.broadcast_capability_update(sender, 'capabilities_removed')

    async def handle_capability_discovery_request(self, capability: str, filters: dict = None) -> dict:
        """Handle external capability discovery requests (for API)"""
        matching_agents = await self.discover_agents_by_capability(capability, filters)

        return {
            'capability': capability,
            'filters_applied': filters or {},
            'matching_agents': matching_agents,
            'total_found': len(matching_agents),
            'discovery_timestamp': datetime.now().isoformat(),
            'cache_age': (datetime.now() - self.discovery_cache['last_updated']).total_seconds()
        }

    async def get_all_capabilities_info(self) -> dict:
        """Get comprehensive information about all registered capabilities"""
        capabilities_info = {}

        for agent_id, capability_info in self.capability_registry.items():
            for capability, details in capability_info['capabilities_detail'].items():
                if capability not in capabilities_info:
                    capabilities_info[capability] = {
                        'total_agents': 0,
                        'agents': [],
                        'avg_reliability': 0,
                        'supported_languages': set(),
                        'avg_response_time': 0
                    }

                agent_performance = self.agent_performance.get(agent_id, {})
                agent_status = self.registered_agents.get(agent_id, {})

                capabilities_info[capability]['total_agents'] += 1
                capabilities_info[capability]['agents'].append({
                    'agent_id': agent_id,
                    'agent_type': capability_info['agent_type'],
                    'reliability': details.get('reliability_score', 1.0),
                    'current_load': len(agent_status.get('current_tasks', [])),
                    'status': agent_status.get('status', 'unknown')
                })

                # Aggregate supported languages
                capabilities_info[capability]['supported_languages'].update(
                    details.get('supported_languages', [])
                )

        # Calculate averages and convert sets to lists
        for capability, info in capabilities_info.items():
            if info['total_agents'] > 0:
                info['avg_reliability'] = sum(
                    agent['reliability'] for agent in info['agents']
                ) / info['total_agents']

                info['avg_response_time'] = sum(
                    self.agent_performance.get(agent['agent_id'], {}).get('avg_response_time', 0)
                    for agent in info['agents']
                ) / info['total_agents']

            info['supported_languages'] = list(info['supported_languages'])

        return capabilities_info

    async def initialize_progress_tracking(self, task_id: str, task_type: str, required_capabilities: list, sender: str):
        """Initialize comprehensive progress tracking for a task"""
        self.progress_tracking[task_id] = {
            'task_id': task_id,
            'task_type': task_type,
            'required_capabilities': required_capabilities,
            'sender': sender,
            'started_at': datetime.now(),
            'estimated_completion': None,
            'overall_progress': 0,
            'current_phase': 'initialization',
            'sub_tasks': {},
            'milestones': [],
            'performance_metrics': {
                'cpu_usage': 0,
                'memory_usage': 0,
                'network_io': 0,
                'response_times': []
            },
            'bottlenecks': [],
            'subscribers': [],  # Agents subscribed to progress updates
            'last_update': datetime.now()
        }

        # Estimate completion time based on task type and capability
        await self.estimate_task_completion_time(task_id, task_type)

        # Initialize sub-tasks based on task type
        await self.initialize_sub_tasks(task_id, task_type)

        logger.info(f"Initialized progress tracking for task {task_id} (type: {task_type})")

    async def estimate_task_completion_time(self, task_id: str, task_type: str):
        """Estimate task completion time based on historical data and complexity"""
        base_estimates = {
            'code_generation': 300,  # 5 minutes
            'code_analysis': 120,    # 2 minutes
            'documentation': 480,    # 8 minutes
            'debugging': 720,        # 12 minutes
            'testing': 360,          # 6 minutes
            'project_orchestration': 1500  # 25 minutes
        }

        base_time = base_estimates.get(task_type, 300)

        # Adjust based on system load
        system_load = len(self.active_tasks)
        load_multiplier = 1 + (system_load * 0.1)  # 10% increase per active task

        estimated_seconds = base_time * load_multiplier
        estimated_completion = datetime.now() + timedelta(seconds=estimated_seconds)

        if task_id in self.progress_tracking:
            self.progress_tracking[task_id]['estimated_completion'] = estimated_completion

        logger.info(f"Estimated completion for task {task_id}: {estimated_completion.isoformat()}")

    async def initialize_sub_tasks(self, task_id: str, task_type: str):
        """Initialize sub-tasks based on task type"""
        sub_task_templates = {
            'code_generation': ['analysis', 'generation', 'validation', 'optimization'],
            'code_analysis': ['parsing', 'static_analysis', 'complexity_analysis', 'reporting'],
            'documentation': ['content_analysis', 'structure_generation', 'writing', 'formatting'],
            'debugging': ['issue_identification', 'root_cause_analysis', 'solution_development', 'testing'],
            'testing': ['test_planning', 'test_execution', 'result_analysis', 'reporting']
        }

        sub_tasks = sub_task_templates.get(task_type, ['initialization', 'processing', 'finalization'])

        if task_id in self.progress_tracking:
            for i, sub_task in enumerate(sub_tasks):
                self.progress_tracking[task_id]['sub_tasks'][sub_task] = {
                    'name': sub_task,
                    'progress': 0,
                    'status': 'pending' if i > 0 else 'in_progress',
                    'started_at': None,
                    'completed_at': None,
                    'estimated_duration': 60  # Default 1 minute per sub-task
                }

    async def handle_progress_update(self, data: Dict[str, Any]):
        """Handle progress update messages from agents"""
        task_id = data.get('payload', {}).get('task_id')
        progress_data = data.get('payload', {})
        sender = data.get('sender')

        if task_id not in self.progress_tracking:
            logger.warning(f"Received progress update for unknown task: {task_id}")
            return

        # Update progress tracking
        tracking = self.progress_tracking[task_id]
        tracking['last_update'] = datetime.now()

        # Update overall progress
        if 'overall_progress' in progress_data:
            tracking['overall_progress'] = progress_data['overall_progress']

        # Update current phase
        if 'current_phase' in progress_data:
            tracking['current_phase'] = progress_data['current_phase']

        # Update sub-task progress
        if 'sub_task_progress' in progress_data:
            for sub_task, progress in progress_data['sub_task_progress'].items():
                if sub_task in tracking['sub_tasks']:
                    tracking['sub_tasks'][sub_task]['progress'] = progress
                    if progress >= 100:
                        tracking['sub_tasks'][sub_task]['status'] = 'completed'
                        tracking['sub_tasks'][sub_task]['completed_at'] = datetime.now()

        # Update performance metrics
        if 'performance' in progress_data:
            perf = progress_data['performance']
            tracking['performance_metrics'].update(perf)

        # Check for bottlenecks
        await self.analyze_bottlenecks(task_id, progress_data)

        # Broadcast progress update to subscribers
        await self.broadcast_progress_update(task_id, progress_data)

        logger.info(f"Updated progress for task {task_id}: {tracking['overall_progress']}% (phase: {tracking['current_phase']})")

    async def handle_progress_milestone(self, data: Dict[str, Any]):
        """Handle milestone completion messages"""
        task_id = data.get('payload', {}).get('task_id')
        milestone = data.get('payload', {}).get('milestone', {})

        if task_id in self.progress_tracking:
            milestone['timestamp'] = datetime.now().isoformat()
            self.progress_tracking[task_id]['milestones'].append(milestone)

            # Broadcast milestone to subscribers
            await self.broadcast_milestone(task_id, milestone)

            logger.info(f"Milestone reached for task {task_id}: {milestone.get('name', 'unnamed')}")

    async def handle_progress_subscription(self, data: Dict[str, Any]):
        """Handle requests to subscribe to task progress updates"""
        task_id = data.get('payload', {}).get('task_id')
        subscriber = data.get('sender')
        action = data.get('payload', {}).get('action', 'subscribe')  # 'subscribe' or 'unsubscribe'

        if task_id in self.progress_tracking:
            subscribers = self.progress_tracking[task_id]['subscribers']

            if action == 'subscribe' and subscriber not in subscribers:
                subscribers.append(subscriber)
                logger.info(f"Agent {subscriber} subscribed to progress updates for task {task_id}")

                # Send current progress state to new subscriber
                await self.send_progress_snapshot(task_id, subscriber)

            elif action == 'unsubscribe' and subscriber in subscribers:
                subscribers.remove(subscriber)
                logger.info(f"Agent {subscriber} unsubscribed from progress updates for task {task_id}")

    async def handle_progress_analytics_request(self, data: Dict[str, Any]):
        """Handle requests for progress analytics"""
        requester = data.get('sender')
        analytics_type = data.get('payload', {}).get('type', 'summary')

        analytics_data = await self.generate_progress_analytics(analytics_type)

        # Send analytics response
        response_message = {
            'id': f'analytics-{datetime.now().timestamp()}',
            'type': 'progress_analytics_response',
            'sender': 'director-integration',
            'recipient': requester,
            'payload': {
                'analytics_type': analytics_type,
                'data': analytics_data,
                'generated_at': datetime.now().isoformat()
            },
            'timestamp': datetime.now().isoformat()
        }

        if requester:
            self.redis_client.publish(f'agent:{requester}', json.dumps(response_message))

    async def analyze_bottlenecks(self, task_id: str, progress_data: Dict[str, Any]):
        """Analyze potential bottlenecks in task execution"""
        if task_id not in self.progress_tracking:
            return

        tracking = self.progress_tracking[task_id]
        current_time = datetime.now()

        # Check if task is taking longer than estimated
        if tracking['estimated_completion'] and current_time > tracking['estimated_completion']:
            bottleneck = {
                'type': 'deadline_exceeded',
                'description': 'Task execution exceeded estimated completion time',
                'detected_at': current_time.isoformat(),
                'severity': 'high'
            }
            tracking['bottlenecks'].append(bottleneck)

        # Check for stuck sub-tasks
        for sub_task_name, sub_task in tracking['sub_tasks'].items():
            if sub_task['status'] == 'in_progress' and sub_task['started_at']:
                duration = (current_time - sub_task['started_at']).total_seconds()
                if duration > sub_task['estimated_duration'] * 2:  # 2x estimated time
                    bottleneck = {
                        'type': 'stuck_subtask',
                        'description': f'Sub-task {sub_task_name} taking longer than expected',
                        'detected_at': current_time.isoformat(),
                        'severity': 'medium',
                        'sub_task': sub_task_name
                    }
                    tracking['bottlenecks'].append(bottleneck)

    async def broadcast_progress_update(self, task_id: str, progress_data: Dict[str, Any]):
        """Broadcast progress updates to all subscribers"""
        if task_id not in self.progress_tracking:
            return

        subscribers = self.progress_tracking[task_id]['subscribers']
        tracking = self.progress_tracking[task_id]

        broadcast_message = {
            'id': f'progress-{datetime.now().timestamp()}',
            'type': 'progress_update_broadcast',
            'sender': 'director-integration',
            'payload': {
                'task_id': task_id,
                'overall_progress': tracking['overall_progress'],
                'current_phase': tracking['current_phase'],
                'sub_tasks': tracking['sub_tasks'],
                'performance_metrics': tracking['performance_metrics'],
                'estimated_completion': tracking['estimated_completion'].isoformat() if tracking['estimated_completion'] else None,
                'update_timestamp': datetime.now().isoformat()
            },
            'timestamp': datetime.now().isoformat()
        }

        # Send to all subscribers
        for subscriber in subscribers:
            self.redis_client.publish(f'agent:{subscriber}', json.dumps(broadcast_message))

        # Also broadcast to general progress channel
        self.redis_client.publish('progress:update', json.dumps(broadcast_message))

    async def broadcast_milestone(self, task_id: str, milestone: Dict[str, Any]):
        """Broadcast milestone completion to subscribers"""
        if task_id not in self.progress_tracking:
            return

        subscribers = self.progress_tracking[task_id]['subscribers']

        milestone_message = {
            'id': f'milestone-{datetime.now().timestamp()}',
            'type': 'milestone_reached',
            'sender': 'director-integration',
            'payload': {
                'task_id': task_id,
                'milestone': milestone,
                'timestamp': datetime.now().isoformat()
            },
            'timestamp': datetime.now().isoformat()
        }

        # Send to all subscribers
        for subscriber in subscribers:
            self.redis_client.publish(f'agent:{subscriber}', json.dumps(milestone_message))

        # Also broadcast to general milestone channel
        self.redis_client.publish('progress:milestone', json.dumps(milestone_message))

    async def send_progress_snapshot(self, task_id: str, subscriber: str):
        """Send current progress snapshot to a new subscriber"""
        if task_id not in self.progress_tracking:
            return

        tracking = self.progress_tracking[task_id]

        snapshot_message = {
            'id': f'snapshot-{datetime.now().timestamp()}',
            'type': 'progress_snapshot',
            'sender': 'director-integration',
            'recipient': subscriber,
            'payload': {
                'task_id': task_id,
                'task_type': tracking['task_type'],
                'started_at': tracking['started_at'].isoformat(),
                'overall_progress': tracking['overall_progress'],
                'current_phase': tracking['current_phase'],
                'sub_tasks': tracking['sub_tasks'],
                'milestones': tracking['milestones'],
                'performance_metrics': tracking['performance_metrics'],
                'bottlenecks': tracking['bottlenecks'],
                'estimated_completion': tracking['estimated_completion'].isoformat() if tracking['estimated_completion'] else None
            },
            'timestamp': datetime.now().isoformat()
        }

        self.redis_client.publish(f'agent:{subscriber}', json.dumps(snapshot_message))

    async def generate_progress_analytics(self, analytics_type: str = 'summary') -> Dict[str, Any]:
        """Generate comprehensive progress analytics"""
        if analytics_type == 'summary':
            return {
                'active_tasks': len(self.progress_tracking),
                'completed_tasks': len([t for t in self.progress_tracking.values() if t['overall_progress'] >= 100]),
                'average_progress': sum(t['overall_progress'] for t in self.progress_tracking.values()) / max(1, len(self.progress_tracking)),
                'total_bottlenecks': sum(len(t['bottlenecks']) for t in self.progress_tracking.values()),
                'system_load': len(self.active_tasks)
            }
        elif analytics_type == 'detailed':
            return {
                'task_breakdown': {
                    task_id: {
                        'progress': tracking['overall_progress'],
                        'phase': tracking['current_phase'],
                        'duration': (datetime.now() - tracking['started_at']).total_seconds(),
                        'bottlenecks': len(tracking['bottlenecks'])
                    } for task_id, tracking in self.progress_tracking.items()
                },
                'performance_trends': self.progress_analytics,
                'resource_utilization': self.calculate_resource_utilization()
            }
        else:
            return {'error': f'Unknown analytics type: {analytics_type}'}

    def calculate_resource_utilization(self) -> Dict[str, Any]:
        """Calculate current system resource utilization"""
        total_tasks = len(self.active_tasks)
        active_agents = len([agent for agent in self.registered_agents.values() if agent['status'] == 'online'])

        return {
            'task_load': total_tasks,
            'agent_utilization': total_tasks / max(1, active_agents),
            'average_tasks_per_agent': total_tasks / max(1, active_agents),
            'system_capacity': active_agents * 5,  # Assume 5 tasks per agent capacity
            'utilization_percentage': (total_tasks / max(1, active_agents * 5)) * 100
        }

    async def get_status(self):
        """Get enhanced integration status with capability discovery information"""
        return {
            'running': self.running,
            'tasks_processed': self.tasks_processed,
            'registered_agents': len(self.registered_agents),
            'active_tasks': len(self.active_tasks),
            'agent_types': list(set(agent['type'] for agent in self.registered_agents.values())),
            'capability_distribution': {cap: len(agents) for cap, agents in self.capability_agents.items()},
            'enhanced_capabilities': {
                'total_capability_entries': len(self.capability_registry),
                'unique_capabilities': len(set(
                    cap for agent in self.capability_registry.values()
                    for cap in agent['capabilities_detail'].keys()
                )),
                'discovery_cache_age': (datetime.now() - self.discovery_cache['last_updated']).total_seconds()
            },
            'performance_overview': {
                'avg_success_rate': sum(
                    perf.get('success_rate', 1.0) for perf in self.agent_performance.values()
                ) / max(1, len(self.agent_performance)),
                'total_tasks_processed': sum(
                    perf.get('total_tasks', 0) for perf in self.agent_performance.values()
                )
            },
            'agents_detail': {
                agent_id: {
                    'type': agent['type'],
                    'capabilities': agent['capabilities'],
                    'status': agent['status'],
                    'current_tasks': len(agent['current_tasks']),
                    'has_enhanced_capabilities': agent_id in self.capability_registry,
                    'performance': self.agent_performance.get(agent_id, {})
                } for agent_id, agent in self.registered_agents.items()
            }
        }

    async def handle_task_metrics(self, data: Dict[str, Any]):
        """Handle task performance metrics from agents"""
        payload = data.get('payload', {})
        task_id = payload.get('task_id')
        agent_id = payload.get('agent_id')
        metrics = payload.get('metrics', {})

        logger.info(f"Received task metrics from {agent_id} for task {task_id}")

        if task_id in self.progress_tracking:
            # Update performance metrics
            current_metrics = self.progress_tracking[task_id]['performance_metrics']
            current_metrics.update(metrics)
            current_metrics['last_updated'] = datetime.now().isoformat()

            # Update agent performance history
            if agent_id not in self.agent_performance:
                self.agent_performance[agent_id] = {
                    'total_tasks': 0,
                    'avg_execution_time': 0,
                    'success_rate': 100,
                    'metrics_history': []
                }

            agent_perf = self.agent_performance[agent_id]
            agent_perf['metrics_history'].append({
                'task_id': task_id,
                'metrics': metrics,
                'timestamp': datetime.now().isoformat()
            })

            # Keep only last 10 metrics
            agent_perf['metrics_history'] = agent_perf['metrics_history'][-10:]

            logger.info(f"Updated metrics for task {task_id}: execution_time={metrics.get('execution_time', 0)}s")

    async def handle_bottleneck_report(self, data: Dict[str, Any]):
        """Handle bottleneck reports from agents"""
        payload = data.get('payload', {})
        task_id = payload.get('task_id')
        agent_id = payload.get('agent_id')
        bottleneck_type = payload.get('bottleneck_type')
        severity = payload.get('severity')
        description = payload.get('description')
        suggested_actions = payload.get('suggested_actions', [])

        logger.warning(f"Bottleneck reported by {agent_id} for task {task_id}: {severity} {bottleneck_type} - {description}")

        if task_id in self.progress_tracking:
            bottleneck_record = {
                'type': bottleneck_type,
                'severity': severity,
                'description': description,
                'agent': agent_id,
                'suggested_actions': suggested_actions,
                'reported_at': datetime.now().isoformat()
            }

            self.progress_tracking[task_id]['bottlenecks'].append(bottleneck_record)

            # For critical bottlenecks, take immediate action
            if severity in ['high', 'critical']:
                await self.handle_critical_bottleneck(task_id, bottleneck_record)

            # Broadcast bottleneck to subscribers
            await self.broadcast_progress_update(task_id, {
                'type': 'bottleneck',
                'bottleneck': bottleneck_record
            })

    async def handle_critical_bottleneck(self, task_id: str, bottleneck: Dict[str, Any]):
        """Handle critical bottlenecks that require immediate attention"""
        logger.critical(f"Critical bottleneck detected for task {task_id}: {bottleneck['description']}")

        # Consider reassigning task if it's a capacity issue
        if bottleneck['type'] == 'capacity' and bottleneck['severity'] == 'critical':
            await self.consider_task_reassignment(task_id, bottleneck['agent'])

    async def consider_task_reassignment(self, task_id: str, overloaded_agent: str):
        """Consider reassigning a task due to capacity issues"""
        if task_id in self.active_tasks:
            task_info = self.active_tasks[task_id]
            required_capabilities = task_info.get('required_capabilities', [])

            # Try to find alternative agent
            alternative_agent = await self.find_best_agent(task_info['type'], required_capabilities)

            if alternative_agent and alternative_agent != overloaded_agent:
                logger.info(f"Considering reassignment of task {task_id} from {overloaded_agent} to {alternative_agent}")

    async def handle_progress_subscription(self, data: Dict[str, Any]):
        """Handle progress subscription requests"""
        payload = data.get('payload', {})
        task_id = payload.get('task_id')
        subscriber = payload.get('subscriber')

        logger.info(f"Progress subscription request from {subscriber} for task {task_id}")

        if task_id in self.progress_tracking:
            if subscriber not in self.progress_tracking[task_id]['subscribers']:
                self.progress_tracking[task_id]['subscribers'].append(subscriber)
                logger.info(f"Added {subscriber} to progress updates for task {task_id}")

                # Send current progress to new subscriber
                current_progress = self.progress_tracking[task_id]
                await self.send_progress_to_subscriber(subscriber, task_id, {
                    'type': 'current_status',
                    'progress': current_progress['overall_progress'],
                    'phase': current_progress['current_phase'],
                    'sub_tasks': current_progress['sub_tasks']
                })

    async def send_progress_to_subscriber(self, subscriber: str, task_id: str, update: Dict[str, Any]):
        """Send progress update to a specific subscriber"""
        message = {
            'id': f'progress-{datetime.now().timestamp()}',
            'type': 'progress_notification',
            'sender': 'director-integration',
            'recipient': subscriber,
            'payload': {
                'task_id': task_id,
                'update': update,
                'timestamp': datetime.now().isoformat()
            },
            'timestamp': datetime.now().isoformat()
        }

        self.redis_client.publish(f'agent:{subscriber}', json.dumps(message))

    async def handle_task_analytics_request(self, data: Dict[str, Any]):
        """Handle analytics request for a task"""
        payload = data.get('payload', {})
        task_id = payload.get('task_id')
        requester = data.get('sender')
        include_metrics = payload.get('include_metrics', True)
        include_bottlenecks = payload.get('include_bottlenecks', True)
        include_sub_tasks = payload.get('include_sub_tasks', True)

        logger.info(f"Analytics request from {requester} for task {task_id}")

        if task_id in self.progress_tracking:
            analytics = await self.generate_progress_analytics(task_id)

            # Filter analytics based on request
            filtered_analytics = {}
            if include_metrics:
                filtered_analytics['performance_metrics'] = analytics.get('performance_metrics', {})
            if include_bottlenecks:
                filtered_analytics['bottlenecks'] = analytics.get('bottlenecks', [])
            if include_sub_tasks:
                filtered_analytics['sub_tasks'] = analytics.get('sub_tasks', {})

            # Always include basic info
            filtered_analytics.update({
                'task_id': task_id,
                'overall_progress': analytics.get('overall_progress', 0),
                'current_phase': analytics.get('current_phase', 'unknown'),
                'estimated_completion': analytics.get('estimated_completion'),
                'generated_at': datetime.now().isoformat()
            })

            # Send analytics response
            response_message = {
                'id': f'analytics-resp-{datetime.now().timestamp()}',
                'type': 'task_analytics_response',
                'sender': 'director-integration',
                'recipient': requester,
                'payload': {
                    'task_id': task_id,
                    'analytics': filtered_analytics
                },
                'timestamp': datetime.now().isoformat()
            }

            self.redis_client.publish(f'agent:{requester}', json.dumps(response_message))
            logger.info(f"Sent analytics response to {requester} for task {task_id}")
        else:
            # Send error response
            error_message = {
                'id': f'analytics-error-{datetime.now().timestamp()}',
                'type': 'error',
                'sender': 'director-integration',
                'recipient': requester,
                'payload': {
                    'error': f'Task {task_id} not found or not being tracked',
                    'task_id': task_id
                },
                'timestamp': datetime.now().isoformat()
            }
            self.redis_client.publish(f'agent:{requester}', json.dumps(error_message))

    async def stop(self):
        """Stop the integration system"""
        logger.info("Stopping Claude Code Director Integration...")
        self.running = False

        if self.pubsub:
            self.pubsub.close()

        # Remove from active agents
        self.redis_client.srem('active_agents', 'director-integration')
        self.redis_client.srem('active_agents:director', 'director-integration')

        logger.info("Claude Code Director Integration stopped")

async def main():
    """Main function to run the integration"""
    integration = ClaudeCodeDirectorIntegration()

    # Start the integration
    started = await integration.start()

    if started:
        try:
            # Run the message loop
            await integration.message_loop()
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        finally:
            await integration.stop()
    else:
        logger.error("Failed to start integration")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())