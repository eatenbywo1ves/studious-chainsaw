package redking.integration

import redking.core.Node
import redking.utils.VirtualSpace

/**
 * Integration layer for libp2p-based networks.
 *
 * libp2p is used by IPFS, Filecoin, and many decentralized applications.
 * This adapter applies Small World Network topology optimization to libp2p peers.
 *
 * Dependencies to add to build.gradle.kts:
 *   implementation("io.libp2p:jvm-libp2p:0.16.0-RELEASE")
 *
 * @see <a href="https://github.com/libp2p/jvm-libp2p">jvm-libp2p</a>
 */
object Libp2pIntegration {

    /**
     * Configuration for libp2p integration.
     */
    data class Config(
        val maxPeers: Int = 50,
        val swapInterval: Long = 30_000, // ms between swap attempts
        val bootstrapNodes: List<String> = emptyList(),
        val listenAddress: String = "/ip4/0.0.0.0/tcp/0"
    )

    /**
     * Maps libp2p PeerIds to virtual address space locations.
     * Uses consistent hashing to assign initial locations.
     */
    fun peerIdToVirtualLocation(peerId: String): Int {
        // Use hash of peerId to get consistent location
        val hash = peerId.hashCode()
        return Math.abs(hash) % VirtualSpace.SPACE_SIZE
    }

    /**
     * Example: Creating a libp2p host with Small World topology.
     *
     * Note: This is a template - actual implementation requires
     * jvm-libp2p dependency and proper async handling.
     */
    fun createTopologyAwareHost(config: Config): TopologyManager {
        return TopologyManager(config)
    }

    /**
     * Manages peer topology using Small World Network principles.
     */
    class TopologyManager(private val config: Config) {
        private val localNode = Node()
        private val peerLocations = mutableMapOf<String, Int>()

        /**
         * Register a new peer and assign virtual location.
         */
        fun registerPeer(peerId: String): Int {
            val location = peerIdToVirtualLocation(peerId)
            peerLocations[peerId] = location
            return location
        }

        /**
         * Get peers sorted by virtual distance (for greedy routing).
         */
        fun getPeersByDistance(targetLocation: Int): List<Pair<String, Int>> {
            return peerLocations.entries
                .map { it.key to Math.abs(it.value - targetLocation) }
                .sortedBy { it.second }
        }

        /**
         * Select best peer for routing to target.
         */
        fun selectNextHop(targetLocation: Int): String? {
            return getPeersByDistance(targetLocation).firstOrNull()?.first
        }

        /**
         * Evaluate if we should swap virtual locations with a peer.
         * Returns the peer to swap with, or null if no beneficial swap.
         */
        fun evaluateSwap(): String? {
            // Implement Sundberg swap logic
            for ((peerId, peerLocation) in peerLocations) {
                val currentDistance = calculateTotalDistance(localNode.virtualLocation)
                val swappedDistance = calculateTotalDistance(peerLocation)

                if (swappedDistance < currentDistance) {
                    return peerId
                }
            }
            return null
        }

        private fun calculateTotalDistance(fromLocation: Int): Double {
            return peerLocations.values.sumOf {
                Math.abs(fromLocation - it).toDouble()
            }
        }

        fun getStats(): Map<String, Any> {
            return mapOf(
                "localLocation" to localNode.virtualLocation,
                "peerCount" to peerLocations.size,
                "avgDistance" to if (peerLocations.isNotEmpty())
                    calculateTotalDistance(localNode.virtualLocation) / peerLocations.size
                else 0.0
            )
        }
    }
}
