package redking.integration

import redking.core.Crypto
import redking.core.Node
import redking.utils.VirtualSpace

/**
 * Integration layer for Akka Cluster actor-based distributed systems.
 *
 * Maps Akka actors to virtual address space and uses Small World
 * topology for efficient actor-to-actor communication.
 *
 * Dependencies to add to build.gradle.kts:
 *   implementation("com.typesafe.akka:akka-actor-typed_2.13:2.8.5")
 *   implementation("com.typesafe.akka:akka-cluster-typed_2.13:2.8.5")
 *
 * Use cases:
 * - Distributed actor systems with optimized routing
 * - Resilient microservices
 * - Real-time event processing
 */
object AkkaIntegration {

    /**
     * Actor message types for topology management.
     */
    sealed class TopologyCommand {
        data class RegisterActor(val actorPath: String, val location: Int) : TopologyCommand()
        data class UnregisterActor(val actorPath: String) : TopologyCommand()
        data class SwapRequest(val fromActor: String, val toActor: String) : TopologyCommand()
        data class SwapAccept(val fromActor: String, val toActor: String) : TopologyCommand()
        data class RouteMessage(val targetLocation: Int, val payload: Any) : TopologyCommand()
        object GetTopology : TopologyCommand()
    }

    /**
     * Response types.
     */
    sealed class TopologyResponse {
        data class TopologySnapshot(
            val actors: Map<String, Int>,
            val localLocation: Int
        ) : TopologyResponse()
        data class RouteResult(val nextHop: String?, val distance: Int) : TopologyResponse()
    }

    /**
     * Topology-aware actor configuration.
     *
     * Example Akka Typed behavior:
     * ```scala
     * object TopologyActor {
     *   def apply(config: ActorConfig): Behavior[TopologyCommand] = Behaviors.setup { ctx =>
     *     val manager = TopologyActorManager(config)
     *     Behaviors.receiveMessage {
     *       case RegisterActor(path, loc) =>
     *         manager.register(path, loc)
     *         Behaviors.same
     *       case RouteMessage(target, payload) =>
     *         val next = manager.route(target)
     *         // forward to next hop
     *         Behaviors.same
     *     }
     *   }
     * }
     * ```
     */
    data class ActorConfig(
        val systemName: String = "redking-cluster",
        val seedNodes: List<String> = listOf("akka://redking-cluster@127.0.0.1:25520"),
        val maxNeighbors: Int = 6,
        val swapIntervalMs: Long = 10_000
    )

    /**
     * Manages actor topology using Small World Network principles.
     */
    class TopologyActorManager(private val config: ActorConfig) {
        private val localNode = Node()
        private val actorLocations = mutableMapOf<String, Int>()

        /**
         * Register an actor with a virtual location.
         */
        fun register(actorPath: String, location: Int = VirtualSpace.randomLocation()) {
            actorLocations[actorPath] = location
            println("Registered actor $actorPath at location $location")
        }

        /**
         * Unregister an actor.
         */
        fun unregister(actorPath: String) {
            actorLocations.remove(actorPath)
        }

        /**
         * Route to the nearest actor to target location.
         */
        fun route(targetLocation: Int): String? {
            if (actorLocations.isEmpty()) return null

            return actorLocations.entries
                .minByOrNull { Math.abs(it.value - targetLocation) }
                ?.key
        }

        /**
         * Get actors within a distance threshold.
         */
        fun getActorsNear(location: Int, maxDistance: Int): List<String> {
            return actorLocations.entries
                .filter { Math.abs(it.value - location) <= maxDistance }
                .sortedBy { Math.abs(it.value - location) }
                .map { it.key }
        }

        /**
         * Evaluate topology and suggest swaps for optimization.
         */
        fun suggestSwaps(): List<Pair<String, String>> {
            val suggestions = mutableListOf<Pair<String, String>>()
            val actors = actorLocations.entries.toList()

            for (i in actors.indices) {
                for (j in i + 1 until actors.size) {
                    val a = actors[i]
                    val b = actors[j]

                    // Calculate if swap would reduce total distance
                    val currentDist = calculateClusterDistance()
                    val swappedDist = calculateDistanceIfSwapped(a.key, b.key)

                    if (swappedDist < currentDist) {
                        suggestions.add(a.key to b.key)
                    }
                }
            }

            return suggestions
        }

        private fun calculateClusterDistance(): Double {
            var total = 0.0
            val actors = actorLocations.values.toList()
            for (i in actors.indices) {
                for (j in i + 1 until actors.size) {
                    total += Math.abs(actors[i] - actors[j])
                }
            }
            return total
        }

        private fun calculateDistanceIfSwapped(actor1: String, actor2: String): Double {
            val loc1 = actorLocations[actor1] ?: return Double.MAX_VALUE
            val loc2 = actorLocations[actor2] ?: return Double.MAX_VALUE

            // Temporarily swap
            actorLocations[actor1] = loc2
            actorLocations[actor2] = loc1

            val distance = calculateClusterDistance()

            // Swap back
            actorLocations[actor1] = loc1
            actorLocations[actor2] = loc2

            return distance
        }

        /**
         * Execute a swap between two actors.
         */
        fun executeSwap(actor1: String, actor2: String): Boolean {
            val loc1 = actorLocations[actor1] ?: return false
            val loc2 = actorLocations[actor2] ?: return false

            actorLocations[actor1] = loc2
            actorLocations[actor2] = loc1

            println("Swapped $actor1 (now at $loc2) with $actor2 (now at $loc1)")
            return true
        }

        fun getTopology(): Map<String, Int> = actorLocations.toMap()

        fun getStats(): Map<String, Any> {
            return mapOf(
                "actorCount" to actorLocations.size,
                "localLocation" to localNode.virtualLocation,
                "avgDistance" to if (actorLocations.size > 1) {
                    val actors = actorLocations.values.toList()
                    var sum = 0.0
                    var count = 0
                    for (i in actors.indices) {
                        for (j in i + 1 until actors.size) {
                            sum += Math.abs(actors[i] - actors[j])
                            count++
                        }
                    }
                    if (count > 0) sum / count else 0.0
                } else 0.0
            )
        }
    }
}
