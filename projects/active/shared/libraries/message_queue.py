"""
Message Queue System for Async Communication
Provides event-driven architecture with pub/sub and task queuing
"""

import asyncio
import uuid
import logging
from typing import Dict, Any, Optional, List, Callable, Union
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, deque
import threading
from concurrent.futures import ThreadPoolExecutor


class MessagePriority(Enum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


class MessageStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


class ExchangeType(Enum):
    DIRECT = "direct"  # Direct routing to specific queue
    FANOUT = "fanout"  # Broadcast to all bound queues
    TOPIC = "topic"  # Pattern-based routing
    HEADERS = "headers"  # Header-based routing


@dataclass
class Message:
    """Represents a message in the queue"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    body: Any = None
    headers: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    reply_to: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    expiration: Optional[datetime] = None
    priority: MessagePriority = MessagePriority.NORMAL
    status: MessageStatus = MessageStatus.PENDING
    retry_count: int = 0
    max_retries: int = 3
    routing_key: Optional[str] = None
    exchange: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert message to dictionary"""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        if self.expiration:
            data["expiration"] = self.expiration.isoformat()
        data["priority"] = self.priority.value
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: Dict) -> "Message":
        """Create message from dictionary"""
        data = data.copy()
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        if data.get("expiration"):
            data["expiration"] = datetime.fromisoformat(data["expiration"])
        data["priority"] = MessagePriority(data.get("priority", 1))
        data["status"] = MessageStatus(data.get("status", "pending"))
        return cls(**data)

    def is_expired(self) -> bool:
        """Check if message has expired"""
        if self.expiration:
            return datetime.now() > self.expiration
        return False


@dataclass
class Queue:
    """Represents a message queue"""

    name: str
    max_size: int = 1000
    durable: bool = True
    auto_delete: bool = False
    exclusive: bool = False
    messages: deque = field(default_factory=deque)
    consumers: List[Callable] = field(default_factory=list)
    dead_letter_queue: Optional[str] = None

    def size(self) -> int:
        """Get current queue size"""
        return len(self.messages)

    def is_full(self) -> bool:
        """Check if queue is full"""
        return self.size() >= self.max_size

    def enqueue(self, message: Message) -> bool:
        """Add message to queue"""
        if self.is_full():
            return False

        # Insert based on priority
        if message.priority == MessagePriority.NORMAL:
            self.messages.append(message)
        else:
            # Find correct position for priority message
            inserted = False
            for i, msg in enumerate(self.messages):
                if msg.priority.value < message.priority.value:
                    self.messages.insert(i, message)
                    inserted = True
                    break

            if not inserted:
                self.messages.append(message)

        return True

    def dequeue(self) -> Optional[Message]:
        """Remove and return message from queue"""
        if self.messages:
            return self.messages.popleft()
        return None

    def peek(self) -> Optional[Message]:
        """View next message without removing"""
        if self.messages:
            return self.messages[0]
        return None


@dataclass
class Exchange:
    """Represents a message exchange for routing"""

    name: str
    type: ExchangeType
    durable: bool = True
    auto_delete: bool = False
    bindings: Dict[str, List[str]] = field(
        default_factory=dict
    )  # routing_key -> queue_names

    def bind_queue(self, queue_name: str, routing_key: str = "#"):
        """Bind a queue to this exchange"""
        if routing_key not in self.bindings:
            self.bindings[routing_key] = []

        if queue_name not in self.bindings[routing_key]:
            self.bindings[routing_key].append(queue_name)

    def unbind_queue(self, queue_name: str, routing_key: str = "#"):
        """Unbind a queue from this exchange"""
        if routing_key in self.bindings:
            if queue_name in self.bindings[routing_key]:
                self.bindings[routing_key].remove(queue_name)

            if not self.bindings[routing_key]:
                del self.bindings[routing_key]

    def get_target_queues(self, routing_key: str) -> List[str]:
        """Get target queues for a routing key"""
        target_queues = []

        if self.type == ExchangeType.DIRECT:
            # Direct routing - exact match
            target_queues = self.bindings.get(routing_key, [])

        elif self.type == ExchangeType.FANOUT:
            # Fanout - all bound queues
            for queues in self.bindings.values():
                target_queues.extend(queues)

        elif self.type == ExchangeType.TOPIC:
            # Topic routing - pattern matching
            for pattern, queues in self.bindings.items():
                if self._matches_pattern(routing_key, pattern):
                    target_queues.extend(queues)

        return list(set(target_queues))  # Remove duplicates

    def _matches_pattern(self, routing_key: str, pattern: str) -> bool:
        """Check if routing key matches topic pattern"""
        # Simple pattern matching (* = one word, # = zero or more words)
        if pattern == "#":
            return True

        key_parts = routing_key.split(".")
        pattern_parts = pattern.split(".")

        i = j = 0
        while i < len(key_parts) and j < len(pattern_parts):
            if pattern_parts[j] == "#":
                return True  # # matches everything after
            elif pattern_parts[j] == "*" or pattern_parts[j] == key_parts[i]:
                i += 1
                j += 1
            else:
                return False

        return i == len(key_parts) and j == len(pattern_parts)


class MessageBroker:
    """Central message broker for the system"""

    def __init__(self):
        self.queues: Dict[str, Queue] = {}
        self.exchanges: Dict[str, Exchange] = {}
        self.consumers: Dict[str, List[Callable]] = defaultdict(list)
        self.logger = self._setup_logging()
        self.running = False
        self.executor = ThreadPoolExecutor(max_workers=10)
        self._consumer_tasks: Dict[str, asyncio.Task] = {}
        self._lock = threading.Lock()

        # Statistics
        self.stats = {
            "messages_published": 0,
            "messages_consumed": 0,
            "messages_failed": 0,
            "messages_expired": 0,
            "messages_dead_lettered": 0,
        }

        # Initialize default exchanges
        self._initialize_default_exchanges()

    def _setup_logging(self) -> logging.Logger:
        """Setup logging for message broker"""
        logger = logging.getLogger("MessageBroker")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "component": "MessageBroker", '
                '"level": "%(levelname)s", "message": "%(message)s"}'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _initialize_default_exchanges(self):
        """Initialize default exchanges"""
        # Default direct exchange
        self._declare_exchange_sync("", ExchangeType.DIRECT)

        # Default topic exchange
        self._declare_exchange_sync("amq.topic", ExchangeType.TOPIC)

        # Default fanout exchange
        self._declare_exchange_sync("amq.fanout", ExchangeType.FANOUT)

    def _declare_exchange_sync(
        self,
        name: str,
        type: ExchangeType,
        durable: bool = True,
        auto_delete: bool = False,
    ) -> Exchange:
        """Synchronous version of declare_exchange for internal use"""
        with self._lock:
            if name not in self.exchanges:
                exchange = Exchange(
                    name=name, type=type, durable=durable, auto_delete=auto_delete
                )
                self.exchanges[name] = exchange
                self.logger.info(f"Exchange declared: {name} (type: {type.value})")

            return self.exchanges[name]

    async def declare_queue(
        self,
        name: str,
        max_size: int = 1000,
        durable: bool = True,
        auto_delete: bool = False,
        exclusive: bool = False,
        dead_letter_queue: Optional[str] = None,
    ) -> Queue:
        """Declare a new queue"""
        with self._lock:
            if name not in self.queues:
                queue = Queue(
                    name=name,
                    max_size=max_size,
                    durable=durable,
                    auto_delete=auto_delete,
                    exclusive=exclusive,
                    dead_letter_queue=dead_letter_queue,
                )
                self.queues[name] = queue
                self.logger.info(f"Queue declared: {name}")

            return self.queues[name]

    async def declare_exchange(
        self,
        name: str,
        type: Union[ExchangeType, str],
        durable: bool = True,
        auto_delete: bool = False,
    ) -> Exchange:
        """Declare a new exchange"""
        # Convert string to ExchangeType if needed
        if isinstance(type, str):
            type = ExchangeType(type)

        with self._lock:
            if name not in self.exchanges:
                exchange = Exchange(
                    name=name, type=type, durable=durable, auto_delete=auto_delete
                )
                self.exchanges[name] = exchange
                self.logger.info(f"Exchange declared: {name} (type: {type.value})")

            return self.exchanges[name]

    async def bind_queue(
        self, queue_name: str, exchange_name: str, routing_key: str = "#"
    ):
        """Bind a queue to an exchange"""
        with self._lock:
            if exchange_name in self.exchanges and queue_name in self.queues:
                self.exchanges[exchange_name].bind_queue(queue_name, routing_key)
                self.logger.info(
                    f"Queue {queue_name} bound to exchange {exchange_name} with key {routing_key}"
                )

    async def publish(
        self,
        body: Any,
        routing_key: str = "",
        exchange: str = "",
        headers: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
        reply_to: Optional[str] = None,
        expiration: Optional[int] = None,  # seconds
        priority: MessagePriority = MessagePriority.NORMAL,
    ) -> str:
        """Publish a message"""
        # Create message
        message = Message(
            body=body,
            headers=headers or {},
            correlation_id=correlation_id,
            reply_to=reply_to,
            timestamp=datetime.now(),
            expiration=(
                datetime.now() + timedelta(seconds=expiration) if expiration else None
            ),
            priority=priority,
            routing_key=routing_key,
            exchange=exchange,
        )

        # Route message
        if exchange in self.exchanges:
            target_queues = self.exchanges[exchange].get_target_queues(routing_key)
        else:
            # Direct routing to queue
            target_queues = [routing_key] if routing_key in self.queues else []

        # Deliver to queues
        delivered = False
        for queue_name in target_queues:
            if queue_name in self.queues:
                queue = self.queues[queue_name]
                if queue.enqueue(message):
                    delivered = True
                    self.logger.debug(
                        f"Message {message.id} delivered to queue {queue_name}"
                    )
                else:
                    self.logger.warning(f"Queue {queue_name} is full, message dropped")

        if delivered:
            self.stats["messages_published"] += 1
        else:
            self.logger.warning(f"Message {message.id} could not be delivered")

        return message.id

    def subscribe(
        self, queue_name: str, callback: Callable[[Message], Any], auto_ack: bool = True
    ):
        """Subscribe to a queue"""
        if queue_name not in self.queues:
            self.declare_queue(queue_name)

        self.consumers[queue_name].append((callback, auto_ack))
        self.logger.info(f"Consumer subscribed to queue {queue_name}")

    async def _consume_queue(self, queue_name: str):
        """Consume messages from a queue"""
        queue = self.queues[queue_name]
        consumers = self.consumers[queue_name]

        while self.running:
            try:
                # Check for expired messages
                while queue.peek() and queue.peek().is_expired():
                    expired_msg = queue.dequeue()
                    self.stats["messages_expired"] += 1
                    self.logger.debug(f"Message {expired_msg.id} expired")

                # Get next message
                message = queue.dequeue()

                if message:
                    message.status = MessageStatus.PROCESSING

                    # Process with all consumers
                    success = False
                    for callback, auto_ack in consumers:
                        try:
                            # Execute callback
                            if asyncio.iscoroutinefunction(callback):
                                result = await callback(message)
                            else:
                                result = await asyncio.get_event_loop().run_in_executor(
                                    self.executor, callback, message
                                )

                            if auto_ack or result:
                                message.status = MessageStatus.COMPLETED
                                self.stats["messages_consumed"] += 1
                                success = True
                                break

                        except Exception as e:
                            self.logger.error(
                                f"Consumer error for message {message.id}: {e}"
                            )
                            message.retry_count += 1

                    # Handle failed messages
                    if not success:
                        if message.retry_count < message.max_retries:
                            # Retry
                            message.status = MessageStatus.PENDING
                            queue.enqueue(message)
                            self.logger.debug(
                                f"Message {message.id} requeued (retry {message.retry_count})"
                            )
                        else:
                            # Send to dead letter queue
                            message.status = MessageStatus.DEAD_LETTER
                            self.stats["messages_dead_lettered"] += 1

                            if (
                                queue.dead_letter_queue
                                and queue.dead_letter_queue in self.queues
                            ):
                                self.queues[queue.dead_letter_queue].enqueue(message)
                                self.logger.warning(
                                    f"Message {message.id} sent to dead letter queue"
                                )
                            else:
                                self.logger.error(
                                    f"Message {message.id} dropped after max retries"
                                )
                else:
                    # No messages, wait a bit
                    await asyncio.sleep(0.1)

            except Exception as e:
                self.logger.error(f"Queue consumer error for {queue_name}: {e}")
                await asyncio.sleep(1)

    async def start(self):
        """Start the message broker"""
        self.running = True
        self.logger.info("Message broker started")

        # Start consumers for all queues with subscribers
        for queue_name in self.consumers.keys():
            if queue_name in self.queues:
                task = asyncio.create_task(self._consume_queue(queue_name))
                self._consumer_tasks[queue_name] = task

    async def stop(self):
        """Stop the message broker"""
        self.running = False

        # Cancel all consumer tasks
        for task in self._consumer_tasks.values():
            task.cancel()

        # Wait for tasks to complete
        if self._consumer_tasks:
            await asyncio.gather(*self._consumer_tasks.values(), return_exceptions=True)

        self._consumer_tasks.clear()
        self.executor.shutdown(wait=True)

        self.logger.info("Message broker stopped")

    def get_queue_info(self, queue_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a queue"""
        if queue_name in self.queues:
            queue = self.queues[queue_name]
            return {
                "name": queue.name,
                "size": queue.size(),
                "max_size": queue.max_size,
                "consumers": len(self.consumers.get(queue_name, [])),
                "durable": queue.durable,
                "messages_pending": sum(
                    1 for m in queue.messages if m.status == MessageStatus.PENDING
                ),
            }
        return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get broker statistics"""
        return {
            **self.stats,
            "total_queues": len(self.queues),
            "total_exchanges": len(self.exchanges),
            "total_consumers": sum(len(c) for c in self.consumers.values()),
            "queue_sizes": {name: queue.size() for name, queue in self.queues.items()},
            # Add aliases for compatibility with tests
            "total_published": self.stats["messages_published"],
        }


# Global broker instance
_broker: Optional[MessageBroker] = None


def get_message_broker() -> MessageBroker:
    """Get singleton message broker instance"""
    global _broker
    if _broker is None:
        _broker = MessageBroker()
    return _broker


# Convenience functions
async def publish_message(
    body: Any, routing_key: str = "", exchange: str = "", **kwargs
) -> str:
    """Publish a message (convenience function)"""
    broker = get_message_broker()
    return await broker.publish(body, routing_key, exchange, **kwargs)


def subscribe_to_queue(
    queue_name: str, callback: Callable[[Message], Any], auto_ack: bool = True
):
    """Subscribe to a queue (convenience function)"""
    broker = get_message_broker()
    broker.subscribe(queue_name, callback, auto_ack)


def declare_queue(name: str, **kwargs) -> Queue:
    """Declare a queue (convenience function)"""
    broker = get_message_broker()
    return broker.declare_queue(name, **kwargs)


def declare_exchange(name: str, type: ExchangeType, **kwargs) -> Exchange:
    """Declare an exchange (convenience function)"""
    broker = get_message_broker()
    return broker.declare_exchange(name, type, **kwargs)
