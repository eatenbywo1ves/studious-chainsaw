package redking.integration

import redking.core.Crypto
import redking.core.Node
import redking.protocol.Message
import redking.protocol.MessageType
import redking.utils.VirtualSpace

/**
 * Integration layer for Apache Kafka distributed messaging.
 *
 * Uses Kafka topics for peer communication and applies Small World
 * topology for efficient message routing in large clusters.
 *
 * Dependencies to add to build.gradle.kts:
 *   implementation("org.apache.kafka:kafka-clients:3.6.1")
 *
 * Use cases:
 * - Distributed task coordination
 * - Event-driven microservices with P2P optimization
 * - Research on distributed consensus
 */
object KafkaIntegration {

    const val TOPOLOGY_TOPIC = "redking-topology"
    const val SWAP_TOPIC = "redking-swaps"
    const val BROADCAST_TOPIC = "redking-broadcast"

    /**
     * Configuration for Kafka-based RedKing cluster.
     */
    data class KafkaConfig(
        val bootstrapServers: String = "localhost:9092",
        val groupId: String = "redking-cluster",
        val nodeId: String = Crypto.generateSecureId(),
        val virtualLocation: Int = VirtualSpace.randomLocation()
    )

    /**
     * Message format for Kafka communication.
     */
    data class TopologyMessage(
        val nodeId: String,
        val virtualLocation: Int,
        val publicKey: String,
        val timestamp: Long = System.currentTimeMillis(),
        val type: String // ANNOUNCE, SWAP_REQUEST, SWAP_ACCEPT, HEARTBEAT
    ) {
        fun toJson(): String {
            return """{"nodeId":"$nodeId","virtualLocation":$virtualLocation,"publicKey":"$publicKey","timestamp":$timestamp,"type":"$type"}"""
        }

        companion object {
            fun fromJson(json: String): TopologyMessage? {
                // Simple JSON parsing (use kotlinx.serialization in production)
                return try {
                    val nodeId = json.substringAfter("\"nodeId\":\"").substringBefore("\"")
                    val location = json.substringAfter("\"virtualLocation\":").substringBefore(",").toInt()
                    val pubKey = json.substringAfter("\"publicKey\":\"").substringBefore("\"")
                    val timestamp = json.substringAfter("\"timestamp\":").substringBefore(",").toLong()
                    val type = json.substringAfter("\"type\":\"").substringBefore("\"")
                    TopologyMessage(nodeId, location, pubKey, timestamp, type)
                } catch (e: Exception) {
                    null
                }
            }
        }
    }

    /**
     * Kafka-based node that participates in Small World topology.
     *
     * Example usage:
     * ```
     * val config = KafkaConfig(bootstrapServers = "kafka:9092")
     * val node = KafkaTopologyNode(config)
     * node.start()
     * node.broadcastMessage("Hello cluster!")
     * ```
     */
    class KafkaTopologyNode(private val config: KafkaConfig) {
        private val localNode = Node(config.nodeId, config.virtualLocation)
        private val knownPeers = mutableMapOf<String, TopologyMessage>()

        // In production, these would be actual Kafka Producer/Consumer
        private var running = false

        /**
         * Start the node - announce presence and begin topology optimization.
         */
        fun start() {
            running = true
            announcePresence()
            println("KafkaTopologyNode started: ${config.nodeId} at location ${config.virtualLocation}")
        }

        /**
         * Announce this node to the cluster.
         */
        fun announcePresence() {
            val announcement = TopologyMessage(
                nodeId = config.nodeId,
                virtualLocation = config.virtualLocation,
                publicKey = Crypto.exportPublicKey(localNode.publicKey),
                type = "ANNOUNCE"
            )
            // In production: kafkaProducer.send(ProducerRecord(TOPOLOGY_TOPIC, announcement.toJson()))
            println("Announced: ${announcement.toJson()}")
        }

        /**
         * Process incoming topology message.
         */
        fun handleTopologyMessage(message: TopologyMessage) {
            when (message.type) {
                "ANNOUNCE" -> {
                    knownPeers[message.nodeId] = message
                    localNode.addNeighbor(
                        message.nodeId,
                        Crypto.importPublicKey(message.publicKey),
                        message.virtualLocation
                    )
                }
                "SWAP_REQUEST" -> handleSwapRequest(message)
                "SWAP_ACCEPT" -> handleSwapAccept(message)
                "HEARTBEAT" -> knownPeers[message.nodeId] = message
            }
        }

        private fun handleSwapRequest(message: TopologyMessage) {
            // Evaluate if swap is beneficial
            val shouldAccept = localNode.proposeSwap(message.nodeId)
            if (shouldAccept) {
                // Send acceptance
                println("Accepting swap with ${message.nodeId}")
            }
        }

        private fun handleSwapAccept(message: TopologyMessage) {
            // Execute the swap
            println("Swap accepted by ${message.nodeId}")
        }

        /**
         * Route a message to a target location using greedy routing.
         */
        fun routeMessage(targetLocation: Int, payload: String): String? {
            val neighbors = localNode.getNeighbors()
            if (neighbors.isEmpty()) return null

            // Find closest neighbor to target
            val nextHop = neighbors.minByOrNull {
                Math.abs(it.virtualLocation - targetLocation)
            } ?: return null

            val message = localNode.createMessage(MessageType.DATA, payload)
            // In production: send via Kafka to specific node topic
            return nextHop.nodeId
        }

        /**
         * Broadcast a message to all peers.
         */
        fun broadcastMessage(payload: String) {
            val message = localNode.createMessage(MessageType.BROADCAST, payload)
            // In production: kafkaProducer.send(ProducerRecord(BROADCAST_TOPIC, message.serialize()))
            println("Broadcasting: $payload")
        }

        fun getStats(): Map<String, Any> {
            return mapOf(
                "nodeId" to config.nodeId,
                "virtualLocation" to config.virtualLocation,
                "knownPeers" to knownPeers.size,
                "neighbors" to localNode.neighborCount()
            )
        }

        fun stop() {
            running = false
        }
    }
}
