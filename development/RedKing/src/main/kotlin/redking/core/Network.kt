package redking.core

import redking.protocol.Message
import redking.protocol.MessageType
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap

/**
 * Manages the P2P network layer for RedKing.
 * Handles node discovery, message routing, and network maintenance.
 */
class Network(
    private val localNode: Node,
    private val maxNeighbors: Int = 6
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val pendingSwaps = ConcurrentHashMap<String, Long>()

    // Network statistics
    var messagesSent: Long = 0
        private set
    var messagesReceived: Long = 0
        private set
    var swapsCompleted: Long = 0
        private set

    init {
        setupMessageHandlers()
    }

    /**
     * Setup default message handlers.
     */
    private fun setupMessageHandlers() {
        localNode.onMessage(MessageType.SWAP_REQUEST) { message ->
            handleSwapRequest(message)
        }

        localNode.onMessage(MessageType.SWAP_ACCEPT) { message ->
            handleSwapAccept(message)
        }

        localNode.onMessage(MessageType.SWAP_REJECT) { message ->
            handleSwapReject(message)
        }

        localNode.onMessage(MessageType.PING) { message ->
            handlePing(message)
        }

        localNode.onMessage(MessageType.BROADCAST) { message ->
            handleBroadcast(message)
        }
    }

    /**
     * Initiate the swap protocol with a random neighbor.
     */
    fun initiateSwap(): Boolean {
        val neighbors = localNode.getNeighbors()
        if (neighbors.isEmpty()) return false

        val target = neighbors.random()

        // Check if we already have a pending swap with this node
        if (pendingSwaps.containsKey(target.nodeId)) {
            return false
        }

        // Create swap request
        val swapData = "${localNode.virtualLocation}"
        val message = localNode.createMessage(MessageType.SWAP_REQUEST, swapData)

        // Mark as pending
        pendingSwaps[target.nodeId] = System.currentTimeMillis()

        // In a real implementation, this would send over the network
        println("Swap request sent to ${target.nodeId}")
        messagesSent++

        return true
    }

    /**
     * Handle incoming swap request.
     */
    private fun handleSwapRequest(message: Message) {
        messagesReceived++

        val requestedLocation = message.payload.toIntOrNull() ?: return
        val senderId = message.senderId

        // Calculate if swap is beneficial
        val neighbor = localNode.getNeighbors().find { it.nodeId == senderId } ?: return

        val shouldAccept = localNode.proposeSwap(senderId)

        val responseType = if (shouldAccept) MessageType.SWAP_ACCEPT else MessageType.SWAP_REJECT
        val response = localNode.createMessage(responseType, "${localNode.virtualLocation}")

        println("Swap ${if (shouldAccept) "accepted" else "rejected"} from $senderId")

        if (shouldAccept) {
            swapsCompleted++
        }
    }

    /**
     * Handle swap acceptance.
     */
    private fun handleSwapAccept(message: Message) {
        messagesReceived++
        pendingSwaps.remove(message.senderId)

        val newLocation = message.payload.toIntOrNull() ?: return
        val neighbor = localNode.getNeighbors().find { it.nodeId == message.senderId } ?: return

        // Execute the swap
        val oldLocation = localNode.virtualLocation
        localNode.setVirtualLocation(neighbor.virtualLocation)
        neighbor.virtualLocation = oldLocation

        swapsCompleted++
        println("Swap completed with ${message.senderId}. New location: ${localNode.virtualLocation}")
    }

    /**
     * Handle swap rejection.
     */
    private fun handleSwapReject(message: Message) {
        messagesReceived++
        pendingSwaps.remove(message.senderId)
        println("Swap rejected by ${message.senderId}")
    }

    /**
     * Handle ping message.
     */
    private fun handlePing(message: Message) {
        messagesReceived++
        // Update neighbor's last seen time
        val neighbor = localNode.getNeighbors().find { it.nodeId == message.senderId }
        neighbor?.lastSeen = System.currentTimeMillis()

        // Send pong response
        val response = localNode.createMessage(MessageType.PONG, "pong")
        messagesSent++
    }

    /**
     * Handle broadcast message - forward to all neighbors except sender.
     */
    private fun handleBroadcast(message: Message) {
        messagesReceived++

        // Process the broadcast locally
        println("Received broadcast from ${message.senderId}: ${message.payload}")

        // Forward to neighbors (except sender)
        for (neighbor in localNode.getNeighbors()) {
            if (neighbor.nodeId != message.senderId) {
                // In real implementation, forward the message
                messagesSent++
            }
        }
    }

    /**
     * Start periodic network maintenance.
     */
    fun startMaintenance(intervalMs: Long = 30000) {
        scope.launch {
            while (isActive) {
                delay(intervalMs)
                performMaintenance()
            }
        }
    }

    /**
     * Perform network maintenance tasks.
     */
    private fun performMaintenance() {
        // Clean up stale pending swaps (older than 60 seconds)
        val now = System.currentTimeMillis()
        pendingSwaps.entries.removeIf { now - it.value > 60000 }

        // Ping neighbors to check connectivity
        for (neighbor in localNode.getNeighbors()) {
            val ping = localNode.createMessage(MessageType.PING, "ping")
            messagesSent++
        }
    }

    /**
     * Get network statistics.
     */
    fun getStats(): NetworkStats {
        return NetworkStats(
            nodeId = localNode.id,
            virtualLocation = localNode.virtualLocation,
            neighborCount = localNode.neighborCount(),
            messagesSent = messagesSent,
            messagesReceived = messagesReceived,
            swapsCompleted = swapsCompleted
        )
    }

    /**
     * Shutdown the network layer.
     */
    fun shutdown() {
        scope.cancel()
    }

    data class NetworkStats(
        val nodeId: String,
        val virtualLocation: Int,
        val neighborCount: Int,
        val messagesSent: Long,
        val messagesReceived: Long,
        val swapsCompleted: Long
    )
}
