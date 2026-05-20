package redking.core

import redking.protocol.Message
import redking.protocol.MessageType
import redking.utils.VirtualSpace
import java.security.KeyPair
import java.security.PublicKey
import java.util.concurrent.ConcurrentHashMap

/**
 * Represents a node in the RedKing P2P network.
 * Each node has a unique identity, virtual location, and set of neighbors.
 */
class Node(
    val id: String = Crypto.generateSecureId(),
    initialLocation: Int? = null
) {
    // Cryptographic identity
    val keyPair: KeyPair = Crypto.generateKeyPair()
    val publicKey: PublicKey get() = keyPair.public

    // Virtual addressing
    var virtualLocation: Int = initialLocation ?: VirtualSpace.randomLocation()
        private set

    // Network connections
    private val neighbors = ConcurrentHashMap<String, Neighbor>()
    private val knownNodes = ConcurrentHashMap<String, PublicKey>()

    // Message handlers
    private val messageHandlers = mutableMapOf<MessageType, (Message) -> Unit>()

    /**
     * Represents a neighbor connection.
     */
    data class Neighbor(
        val nodeId: String,
        val publicKey: PublicKey,
        var virtualLocation: Int,
        var lastSeen: Long = System.currentTimeMillis()
    )

    /**
     * Add a neighbor to this node.
     */
    fun addNeighbor(nodeId: String, publicKey: PublicKey, virtualLocation: Int) {
        neighbors[nodeId] = Neighbor(nodeId, publicKey, virtualLocation)
        knownNodes[nodeId] = publicKey
    }

    /**
     * Remove a neighbor.
     */
    fun removeNeighbor(nodeId: String) {
        neighbors.remove(nodeId)
    }

    /**
     * Get all neighbors.
     */
    fun getNeighbors(): List<Neighbor> = neighbors.values.toList()

    /**
     * Get neighbor count.
     */
    fun neighborCount(): Int = neighbors.size

    /**
     * Update this node's virtual location.
     */
    fun setVirtualLocation(newLocation: Int) {
        virtualLocation = newLocation
    }

    /**
     * Perform a swap with a neighbor.
     * Returns true if swap was executed.
     */
    fun proposeSwap(neighborId: String): Boolean {
        val neighbor = neighbors[neighborId] ?: return false

        // Calculate D1: current configuration distance product
        val d1 = calculateDistanceProduct(virtualLocation) *
                 calculateNeighborDistanceProduct(neighbor)

        // Calculate D2: swapped configuration distance product
        val d2 = calculateDistanceProduct(neighbor.virtualLocation) *
                 calculateNeighborDistanceProductSwapped(neighbor)

        if (d1 == 0.0 || d2 == 0.0) return false

        // Decision: swap if beneficial or probabilistically
        val shouldSwap = if (d2 <= d1) {
            true
        } else {
            Math.random() < (d1 / d2)
        }

        if (shouldSwap) {
            val tempLocation = virtualLocation
            virtualLocation = neighbor.virtualLocation
            neighbor.virtualLocation = tempLocation
            return true
        }

        return false
    }

    /**
     * Calculate product of distances to all neighbors.
     */
    private fun calculateDistanceProduct(fromLocation: Int): Double {
        var product = 1.0
        for (neighbor in neighbors.values) {
            val distance = Math.abs(fromLocation - neighbor.virtualLocation)
            if (distance > 0) product *= distance
        }
        return product
    }

    /**
     * Calculate product of distances for a neighbor to its neighbors.
     * (Simplified - in real implementation, would need neighbor's neighbor info)
     */
    private fun calculateNeighborDistanceProduct(neighbor: Neighbor): Double {
        // Simplified calculation using this node's location
        val distance = Math.abs(neighbor.virtualLocation - virtualLocation)
        return if (distance > 0) distance.toDouble() else 1.0
    }

    private fun calculateNeighborDistanceProductSwapped(neighbor: Neighbor): Double {
        val distance = Math.abs(virtualLocation - neighbor.virtualLocation)
        return if (distance > 0) distance.toDouble() else 1.0
    }

    /**
     * Create and sign a message.
     */
    fun createMessage(type: MessageType, payload: String): Message {
        val message = Message(
            type = type,
            senderId = id,
            payload = payload,
            timestamp = System.currentTimeMillis()
        )
        message.signature = Crypto.signMessage(keyPair.private, message.toSignableString())
        return message
    }

    /**
     * Verify and process an incoming message.
     */
    fun receiveMessage(message: Message): Boolean {
        // Get sender's public key
        val senderKey = knownNodes[message.senderId] ?: return false

        // Verify signature
        if (!Crypto.verifyMessage(senderKey, message.toSignableString(), message.signature)) {
            return false
        }

        // Process message
        messageHandlers[message.type]?.invoke(message)
        return true
    }

    /**
     * Register a message handler.
     */
    fun onMessage(type: MessageType, handler: (Message) -> Unit) {
        messageHandlers[type] = handler
    }

    override fun toString(): String {
        return "Node(id='$id', location=$virtualLocation, neighbors=${neighbors.size})"
    }
}
