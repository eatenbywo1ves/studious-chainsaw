"""
Real-time Streaming Data Processor

High-performance streaming infrastructure for real-time analytics with:
- Apache Kafka integration for data streams
- Apache Pulsar support for multi-tenant messaging
- Event-driven data pipeline processing
- Stream aggregations and windowing
- Multi-tenant data isolation
- Real-time metrics and monitoring
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

import aioredis
import pulsar
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer


class StreamType(Enum):
    AGENT_EVENTS = "agent_events"
    USER_ACTIONS = "user_actions"
    SYSTEM_METRICS = "system_metrics"
    SECURITY_EVENTS = "security_events"
    BUSINESS_EVENTS = "business_events"


class MessageFormat(Enum):
    JSON = "json"
    AVRO = "avro"
    PROTOBUF = "protobuf"


@dataclass
class StreamMessage:
    """Standardized stream message format"""

    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    tenant_id: str = ""
    stream_type: StreamType = StreamType.AGENT_EVENTS
    event_type: str = ""
    source: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "tenant_id": self.tenant_id,
            "stream_type": self.stream_type.value,
            "event_type": self.event_type,
            "source": self.source,
            "data": self.data,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StreamMessage":
        return cls(
            id=data["id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            tenant_id=data["tenant_id"],
            stream_type=StreamType(data["stream_type"]),
            event_type=data["event_type"],
            source=data["source"],
            data=data["data"],
            metadata=data["metadata"],
        )


@dataclass
class StreamConfig:
    """Stream configuration settings"""

    name: str
    stream_type: StreamType
    partition_key: str = "tenant_id"
    retention_hours: int = 168  # 7 days
    compression: str = "gzip"
    message_format: MessageFormat = MessageFormat.JSON
    max_batch_size: int = 100
    flush_interval_ms: int = 1000
    enable_deduplication: bool = True


class StreamProcessor:
    """High-performance real-time stream processor"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.kafka_producer: Optional[AIOKafkaProducer] = None
        self.kafka_consumers: Dict[str, AIOKafkaConsumer] = {}
        self.pulsar_client: Optional[pulsar.Client] = None
        self.redis_client: Optional[aioredis.Redis] = None

        self.stream_configs: Dict[str, StreamConfig] = {}
        self.message_handlers: Dict[str, List[Callable]] = {}
        self.aggregators: Dict[str, "StreamAggregator"] = {}

        self.metrics = {
            "messages_processed": 0,
            "messages_failed": 0,
            "processing_time_ms": 0,
            "active_streams": 0,
        }

        self.logger = logging.getLogger(__name__)

    async def initialize(self):
        """Initialize streaming infrastructure"""
        try:
            # Initialize Kafka
            if self.config.get("kafka_enabled", True):
                await self._init_kafka()

            # Initialize Pulsar
            if self.config.get("pulsar_enabled", False):
                await self._init_pulsar()

            # Initialize Redis for state management
            if self.config.get("redis_enabled", True):
                await self._init_redis()

            self.logger.info("Stream processor initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize stream processor: {e}")
            raise

    async def _init_kafka(self):
        """Initialize Kafka producer and consumers"""
        kafka_config = {
            "bootstrap_servers": self.config.get("kafka_brokers", ["localhost:9092"]),
            "client_id": f"stream_processor_{uuid4()}",
            "compression_type": "gzip",
            "batch_size": 16384,
            "linger_ms": 10,
            "max_request_size": 1048576,
        }

        self.kafka_producer = AIOKafkaProducer(**kafka_config)
        await self.kafka_producer.start()

        self.logger.info("Kafka producer initialized")

    async def _init_pulsar(self):
        """Initialize Pulsar client"""
        pulsar_url = self.config.get("pulsar_url", "pulsar://localhost:6650")
        self.pulsar_client = pulsar.Client(pulsar_url)

        self.logger.info("Pulsar client initialized")

    async def _init_redis(self):
        """Initialize Redis for state management"""
        redis_url = self.config.get("redis_url", "redis://localhost:6379")
        self.redis_client = aioredis.from_url(redis_url)

        self.logger.info("Redis client initialized")

    def register_stream(self, stream_config: StreamConfig):
        """Register a new stream configuration"""
        self.stream_configs[stream_config.name] = stream_config
        self.message_handlers[stream_config.name] = []

        self.logger.info(f"Registered stream: {stream_config.name}")

    def add_message_handler(self, stream_name: str, handler: Callable):
        """Add message handler for a stream"""
        if stream_name not in self.message_handlers:
            self.message_handlers[stream_name] = []

        self.message_handlers[stream_name].append(handler)
        self.logger.info(f"Added handler for stream: {stream_name}")

    async def publish_message(self, stream_name: str, message: StreamMessage):
        """Publish message to stream"""
        try:
            if stream_name not in self.stream_configs:
                raise ValueError(f"Unknown stream: {stream_name}")

            config = self.stream_configs[stream_name]

            # Add tenant isolation
            topic_name = self._get_tenant_topic(stream_name, message.tenant_id)

            if self.kafka_producer:
                await self._publish_to_kafka(topic_name, message, config)

            if self.pulsar_client:
                await self._publish_to_pulsar(topic_name, message, config)

            self.metrics["messages_processed"] += 1

        except Exception as e:
            self.metrics["messages_failed"] += 1
            self.logger.error(f"Failed to publish message: {e}")
            raise

    async def _publish_to_kafka(
        self, topic: str, message: StreamMessage, config: StreamConfig
    ):
        """Publish message to Kafka"""
        partition_key = getattr(message, config.partition_key, message.tenant_id)
        message_data = json.dumps(message.to_dict()).encode("utf-8")

        await self.kafka_producer.send_and_wait(
            topic,
            value=message_data,
            key=partition_key.encode("utf-8") if partition_key else None,
        )

    async def _publish_to_pulsar(
        self, topic: str, message: StreamMessage, config: StreamConfig
    ):
        """Publish message to Pulsar"""
        producer = self.pulsar_client.create_producer(
            topic,
            compression_type=pulsar.CompressionType.LZ4,
            batching_enabled=True,
            batch_size=config.max_batch_size,
        )

        message_data = json.dumps(message.to_dict()).encode("utf-8")
        producer.send(message_data)
        producer.close()

    async def start_consumer(self, stream_name: str, consumer_group: str = "default"):
        """Start consuming messages from stream"""
        if stream_name not in self.stream_configs:
            raise ValueError(f"Unknown stream: {stream_name}")

        config = self.stream_configs[stream_name]
        topic_pattern = f"{stream_name}_tenant_*"

        consumer = AIOKafkaConsumer(
            topic_pattern,
            bootstrap_servers=self.config.get("kafka_brokers", ["localhost:9092"]),
            group_id=consumer_group,
            auto_offset_reset="latest",
            enable_auto_commit=True,
            max_poll_records=config.max_batch_size,
        )

        await consumer.start()
        self.kafka_consumers[stream_name] = consumer

        # Start consumer task
        asyncio.create_task(self._consume_messages(stream_name, consumer))

        self.logger.info(f"Started consumer for stream: {stream_name}")

    async def _consume_messages(self, stream_name: str, consumer: AIOKafkaConsumer):
        """Consume and process messages"""
        try:
            async for message in consumer:
                start_time = datetime.utcnow()

                try:
                    # Parse message
                    message_data = json.loads(message.value.decode("utf-8"))
                    stream_message = StreamMessage.from_dict(message_data)

                    # Process with handlers
                    handlers = self.message_handlers.get(stream_name, [])
                    for handler in handlers:
                        try:
                            await handler(stream_message)
                        except Exception as e:
                            self.logger.error(f"Handler error: {e}")

                    # Update aggregators
                    if stream_name in self.aggregators:
                        await self.aggregators[stream_name].process_message(
                            stream_message
                        )

                    # Update metrics
                    processing_time = (
                        datetime.utcnow() - start_time
                    ).total_seconds() * 1000
                    self.metrics["processing_time_ms"] = (
                        self.metrics["processing_time_ms"] + processing_time
                    ) / 2

                except Exception as e:
                    self.logger.error(f"Message processing error: {e}")
                    self.metrics["messages_failed"] += 1

        except Exception as e:
            self.logger.error(f"Consumer error: {e}")

    def _get_tenant_topic(self, stream_name: str, tenant_id: str) -> str:
        """Generate tenant-specific topic name"""
        return f"{stream_name}_tenant_{tenant_id}"

    async def create_aggregator(
        self,
        name: str,
        stream_name: str,
        window_size: timedelta,
        aggregation_func: Callable,
    ) -> "StreamAggregator":
        """Create stream aggregator for windowed operations"""
        aggregator = StreamAggregator(
            name=name,
            stream_name=stream_name,
            window_size=window_size,
            aggregation_func=aggregation_func,
            redis_client=self.redis_client,
        )

        self.aggregators[stream_name] = aggregator
        return aggregator

    async def get_metrics(self) -> Dict[str, Any]:
        """Get processor metrics"""
        self.metrics["active_streams"] = len(self.kafka_consumers)
        return self.metrics.copy()

    async def shutdown(self):
        """Gracefully shutdown processor"""
        try:
            # Stop Kafka consumers
            for consumer in self.kafka_consumers.values():
                await consumer.stop()

            # Stop Kafka producer
            if self.kafka_producer:
                await self.kafka_producer.stop()

            # Close Pulsar client
            if self.pulsar_client:
                self.pulsar_client.close()

            # Close Redis connection
            if self.redis_client:
                await self.redis_client.close()

            self.logger.info("Stream processor shutdown complete")

        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")


class StreamAggregator:
    """Real-time stream aggregations with windowing"""

    def __init__(
        self,
        name: str,
        stream_name: str,
        window_size: timedelta,
        aggregation_func: Callable,
        redis_client: aioredis.Redis,
    ):
        self.name = name
        self.stream_name = stream_name
        self.window_size = window_size
        self.aggregation_func = aggregation_func
        self.redis_client = redis_client

        self.current_window: Dict[str, List[StreamMessage]] = {}
        self.window_start_time = datetime.utcnow()

    async def process_message(self, message: StreamMessage):
        """Process message for aggregation"""
        current_time = datetime.utcnow()

        # Check if we need to start a new window
        if current_time - self.window_start_time > self.window_size:
            await self._flush_window()
            self.window_start_time = current_time
            self.current_window.clear()

        # Add message to current window
        tenant_key = message.tenant_id or "global"
        if tenant_key not in self.current_window:
            self.current_window[tenant_key] = []

        self.current_window[tenant_key].append(message)

    async def _flush_window(self):
        """Process and store aggregated window data"""
        for tenant_id, messages in self.current_window.items():
            if not messages:
                continue

            try:
                # Apply aggregation function
                aggregated_data = await self.aggregation_func(messages)

                # Store in Redis with TTL
                key = f"aggregation:{self.name}:{tenant_id}:{self.window_start_time.isoformat()}"

                await self.redis_client.setex(
                    key,
                    int(self.window_size.total_seconds() * 24),  # Keep for 24 windows
                    json.dumps(aggregated_data, default=str),
                )

            except Exception as e:
                logging.error(f"Aggregation error for {self.name}: {e}")

    async def get_aggregated_data(
        self, tenant_id: str, start_time: datetime, end_time: datetime
    ) -> List[Dict[str, Any]]:
        """Retrieve aggregated data for time range"""
        results = []

        current_time = start_time
        while current_time < end_time:
            key = f"aggregation:{self.name}:{tenant_id}:{current_time.isoformat()}"

            data = await self.redis_client.get(key)
            if data:
                results.append(json.loads(data))

            current_time += self.window_size

        return results


# Example aggregation functions
async def count_aggregator(messages: List[StreamMessage]) -> Dict[str, Any]:
    """Count messages by event type"""
    counts = {}
    for message in messages:
        event_type = message.event_type
        counts[event_type] = counts.get(event_type, 0) + 1

    return {
        "total_messages": len(messages),
        "event_counts": counts,
        "window_start": messages[0].timestamp.isoformat() if messages else None,
        "window_end": messages[-1].timestamp.isoformat() if messages else None,
    }


async def performance_aggregator(messages: List[StreamMessage]) -> Dict[str, Any]:
    """Aggregate performance metrics"""
    response_times = []
    error_count = 0

    for message in messages:
        if "response_time_ms" in message.data:
            response_times.append(message.data["response_time_ms"])

        if message.data.get("status") == "error":
            error_count += 1

    return {
        "total_requests": len(messages),
        "avg_response_time": (
            sum(response_times) / len(response_times) if response_times else 0
        ),
        "max_response_time": max(response_times) if response_times else 0,
        "min_response_time": min(response_times) if response_times else 0,
        "error_count": error_count,
        "error_rate": error_count / len(messages) if messages else 0,
    }
