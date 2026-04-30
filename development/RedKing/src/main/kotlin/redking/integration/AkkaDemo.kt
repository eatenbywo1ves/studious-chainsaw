package redking.integration

import redking.utils.VirtualSpace

/**
 * Demonstration of Akka-style actor system with Small World topology.
 *
 * This is a standalone simulation that demonstrates how the topology
 * optimization works in an actor-based system WITHOUT requiring
 * actual Akka dependencies.
 *
 * Run with: ./gradlew run --args="akka-demo"
 */
object AkkaDemo {

    /**
     * Simulated Actor - represents a processing unit in the cluster.
     */
    data class SimulatedActor(
        val path: String,
        var location: Int,
        val mailbox: MutableList<ActorMessage> = mutableListOf(),
        var messagesProcessed: Int = 0,
        var hopsReceived: Int = 0
    ) {
        fun receive(message: ActorMessage) {
            mailbox.add(message)
            messagesProcessed++
            hopsReceived += message.hopCount
        }

        fun process(): List<ActorMessage> {
            val responses = mutableListOf<ActorMessage>()
            val toProcess = mailbox.toList()
            mailbox.clear()

            for (msg in toProcess) {
                when (msg.type) {
                    "PING" -> responses.add(ActorMessage("PONG", msg.sender, path, msg.hopCount))
                    "WORK" -> {
                        // Simulate work
                        Thread.sleep(1)
                        responses.add(ActorMessage("RESULT", msg.sender, path, msg.hopCount, "done"))
                    }
                    else -> {}
                }
            }
            return responses
        }
    }

    /**
     * Message passed between actors.
     */
    data class ActorMessage(
        val type: String,
        val target: String,
        val sender: String,
        var hopCount: Int = 0,
        val payload: String = ""
    )

    /**
     * Actor System with Small World topology routing.
     */
    class SmallWorldActorSystem(val name: String) {
        private val actors = mutableMapOf<String, SimulatedActor>()
        private val topology = AkkaIntegration.TopologyActorManager(
            AkkaIntegration.ActorConfig(systemName = name)
        )

        // Metrics
        var totalMessages: Long = 0
        var totalHops: Long = 0
        var directRoutes: Long = 0
        var greedyRoutes: Long = 0

        /**
         * Spawn a new actor at a random or specified location.
         */
        fun spawn(actorName: String, location: Int = VirtualSpace.randomLocation()): SimulatedActor {
            val path = "akka://$name/user/$actorName"
            val actor = SimulatedActor(path, location)
            actors[path] = actor
            topology.register(path, location)
            return actor
        }

        /**
         * Send a message using greedy routing based on virtual locations.
         */
        fun send(message: ActorMessage): Boolean {
            totalMessages++

            // Direct delivery if we know the exact target
            val targetActor = actors[message.target]
            if (targetActor != null) {
                targetActor.receive(message)
                directRoutes++
                totalHops += message.hopCount
                return true
            }

            // Greedy routing - find actor closest to target's location
            val targetLocation = actors.values
                .find { it.path == message.target }
                ?.location ?: return false

            val nextHop = topology.route(targetLocation)
            if (nextHop != null && nextHop != message.sender) {
                message.hopCount++
                actors[nextHop]?.receive(message)
                greedyRoutes++
                totalHops += message.hopCount
                return true
            }

            return false
        }

        /**
         * Route message to a virtual location (not a specific actor).
         */
        fun routeToLocation(type: String, targetLocation: Int, sender: String): String? {
            val nextHop = topology.route(targetLocation)
            if (nextHop != null) {
                val message = ActorMessage(type, nextHop, sender)
                send(message)
                return nextHop
            }
            return null
        }

        /**
         * Run topology optimization (swap algorithm).
         */
        fun optimizeTopology(iterations: Int = 100): Int {
            var totalSwaps = 0

            repeat(iterations) {
                val suggestions = topology.suggestSwaps()
                for ((actor1, actor2) in suggestions.take(5)) {
                    if (topology.executeSwap(actor1, actor2)) {
                        // Update actor locations
                        val loc1 = actors[actor1]?.location ?: continue
                        val loc2 = actors[actor2]?.location ?: continue
                        actors[actor1]?.location = loc2
                        actors[actor2]?.location = loc1
                        totalSwaps++
                    }
                }
            }

            return totalSwaps
        }

        /**
         * Process all pending messages in all actors.
         */
        fun tick(): Int {
            var processed = 0
            val responses = mutableListOf<ActorMessage>()

            for (actor in actors.values) {
                responses.addAll(actor.process())
                processed += actor.mailbox.size
            }

            // Deliver responses
            for (response in responses) {
                send(response)
            }

            return processed
        }

        /**
         * Broadcast a message to all actors.
         */
        fun broadcast(type: String, sender: String, payload: String = "") {
            for (actor in actors.values) {
                if (actor.path != sender) {
                    send(ActorMessage(type, actor.path, sender, 0, payload))
                }
            }
        }

        /**
         * Get system statistics.
         */
        fun getStats(): Map<String, Any> {
            val avgHops = if (totalMessages > 0) totalHops.toDouble() / totalMessages else 0.0
            val topologyStats = topology.getStats()

            return mapOf(
                "systemName" to name,
                "actorCount" to actors.size,
                "totalMessages" to totalMessages,
                "totalHops" to totalHops,
                "avgHopsPerMessage" to String.format("%.2f", avgHops),
                "directRoutes" to directRoutes,
                "greedyRoutes" to greedyRoutes,
                "topologyAvgDistance" to (topologyStats["avgDistance"] ?: 0.0)
            )
        }

        fun shutdown() {
            actors.clear()
            println("Actor system '$name' shut down.")
        }
    }

    /**
     * Run the Akka-style demo.
     */
    fun run() {
        println("""
            ╔═══════════════════════════════════════════════════════════╗
            ║     AKKA-STYLE ACTOR SYSTEM WITH SMALL WORLD TOPOLOGY     ║
            ╚═══════════════════════════════════════════════════════════╝
        """.trimIndent())
        println()

        // Create actor system
        val system = SmallWorldActorSystem("redking-demo")

        // Spawn actors
        println("1. Spawning 100 actors...")
        repeat(100) { i ->
            system.spawn("worker-$i")
        }
        println("   Spawned 100 actors")
        println()

        // Initial stats
        println("2. Initial topology stats:")
        system.getStats().forEach { (k, v) -> println("   $k: $v") }
        println()

        // Send messages before optimization
        println("3. Sending 1000 random messages (before optimization)...")
        val actors = (0 until 100).map { "akka://redking-demo/user/worker-$it" }
        repeat(1000) {
            val sender = actors.random()
            val target = actors.random()
            if (sender != target) {
                system.send(ActorMessage("PING", target, sender))
            }
        }
        system.tick()

        println("   Stats after messaging:")
        system.getStats().forEach { (k, v) -> println("   $k: $v") }
        println()

        // Optimize topology
        println("4. Running topology optimization (100 iterations)...")
        val swaps = system.optimizeTopology(100)
        println("   Executed $swaps swaps")
        println()

        // Reset metrics
        system.totalMessages = 0
        system.totalHops = 0
        system.directRoutes = 0
        system.greedyRoutes = 0

        // Send messages after optimization
        println("5. Sending 1000 random messages (after optimization)...")
        repeat(1000) {
            val sender = actors.random()
            val target = actors.random()
            if (sender != target) {
                system.send(ActorMessage("PING", target, sender))
            }
        }
        system.tick()

        println("   Stats after optimization:")
        system.getStats().forEach { (k, v) -> println("   $k: $v") }
        println()

        // Broadcast test
        println("6. Broadcasting message from worker-0...")
        system.broadcast("WORK", "akka://redking-demo/user/worker-0", "process this")
        system.tick()
        println("   Broadcast complete")
        println()

        // Final stats
        println("7. Final system stats:")
        system.getStats().forEach { (k, v) -> println("   $k: $v") }

        system.shutdown()
        println()
        println("Demo complete!")
    }
}
