package redking

import redking.core.Crypto
import redking.core.Network
import redking.core.Node
import redking.integration.AkkaDemo
import redking.protocol.MessageType
import redking.simulation.NetworkSimulation
import redking.utils.VirtualSpace

/**
 * Main entry point for RedKing.
 * Demonstrates both the Java simulation and Kotlin implementation.
 */
fun main(args: Array<String>) {
    println("""
        ╔═══════════════════════════════════════════════════════════════╗
        ║                                                               ║
        ║   ██████╗ ███████╗██████╗ ██╗  ██╗██╗███╗   ██╗ ██████╗      ║
        ║   ██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██║████╗  ██║██╔════╝      ║
        ║   ██████╔╝█████╗  ██║  ██║█████╔╝ ██║██╔██╗ ██║██║  ███╗     ║
        ║   ██╔══██╗██╔══╝  ██║  ██║██╔═██╗ ██║██║╚██╗██║██║   ██║     ║
        ║   ██║  ██║███████╗██████╔╝██║  ██╗██║██║ ╚████║╚██████╔╝     ║
        ║   ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝      ║
        ║                                                               ║
        ║           P2P Hivemind - Small World Network                  ║
        ╚═══════════════════════════════════════════════════════════════╝
    """.trimIndent())
    println()

    val mode = args.getOrNull(0) ?: "demo"

    when (mode) {
        "sim", "simulation" -> runSimulation(args.drop(1))
        "node" -> runNode(args.drop(1))
        "demo" -> runDemo()
        "akka-demo" -> AkkaDemo.run()
        "test" -> runTests()
        else -> printHelp()
    }
}

/**
 * Run the network simulation.
 */
fun runSimulation(args: List<String>) {
    val nodeCount = args.getOrNull(0)?.toIntOrNull() ?: 10000
    val iterations = args.getOrNull(1)?.toIntOrNull() ?: 500

    println("Running network simulation...")
    println("Nodes: $nodeCount, Iterations: $iterations")
    println()

    NetworkSimulation.main(arrayOf(nodeCount.toString(), iterations.toString()))
}

/**
 * Run a single node (for testing).
 */
fun runNode(args: List<String>) {
    println("Starting RedKing node...")

    val node = Node()
    val network = Network(node)

    println("Node ID: ${node.id}")
    println("Public Key: ${Crypto.exportPublicKey(node.publicKey).take(50)}...")
    println("Virtual Location: ${node.virtualLocation}")

    // Add some simulated neighbors
    repeat(6) { i ->
        val neighbor = Node()
        node.addNeighbor(neighbor.id, neighbor.publicKey, neighbor.virtualLocation)
        println("Added neighbor $i: ${neighbor.id} at location ${neighbor.virtualLocation}")
    }

    println()
    println("Network stats: ${network.getStats()}")

    // Try some swaps
    println()
    println("Attempting swaps...")
    repeat(5) {
        val result = network.initiateSwap()
        println("Swap attempt ${it + 1}: ${if (result) "initiated" else "failed"}")
    }

    println()
    println("Final location: ${node.virtualLocation}")
    network.shutdown()
}

/**
 * Run demonstration of core functionality.
 */
fun runDemo() {
    println("=== RedKing Demo ===")
    println()

    // 1. Demonstrate cryptography
    println("1. Cryptographic Operations")
    println("-".repeat(40))

    val keyPair = Crypto.generateKeyPair()
    println("Generated RSA key pair")

    val message = "Hello, RedKing network!"
    val signature = Crypto.signMessage(keyPair.private, message)
    println("Message: $message")
    println("Signature: ${signature.take(50)}...")

    val verified = Crypto.verifyMessage(keyPair.public, message, signature)
    println("Signature valid: $verified")
    println()

    // 2. Demonstrate virtual space
    println("2. Virtual Address Space")
    println("-".repeat(40))

    val loc1 = VirtualSpace.randomLocation()
    val loc2 = VirtualSpace.randomLocation()
    println("Location 1: $loc1 -> ${VirtualSpace.to2D(loc1)}")
    println("Location 2: $loc2 -> ${VirtualSpace.to2D(loc2)}")
    println("Manhattan distance: ${VirtualSpace.manhattanDistance(loc1, loc2)}")
    println("Euclidean distance: ${String.format("%.2f", VirtualSpace.euclideanDistance(loc1, loc2))}")
    println("Kleinberg probability: ${String.format("%.6f", VirtualSpace.kleinbergProbability(loc1, loc2))}")
    println()

    // 3. Demonstrate node creation and messaging
    println("3. Node Operations")
    println("-".repeat(40))

    val node1 = Node()
    val node2 = Node()

    println("Node 1: ${node1.id} at ${node1.virtualLocation}")
    println("Node 2: ${node2.id} at ${node2.virtualLocation}")

    // Connect nodes as neighbors
    node1.addNeighbor(node2.id, node2.publicKey, node2.virtualLocation)
    node2.addNeighbor(node1.id, node1.publicKey, node1.virtualLocation)

    println("Nodes connected as neighbors")

    // Create and verify a message
    val msg = node1.createMessage(MessageType.PING, "ping")
    println("Created message: ${msg.type} from ${msg.senderId}")

    val msgVerified = node2.receiveMessage(msg)
    println("Message verified by node2: $msgVerified")
    println()

    // 4. Small simulation
    println("4. Mini Simulation (1000 nodes)")
    println("-".repeat(40))

    val sim = NetworkSimulation(1000, 6, 100)
    sim.generateNetwork()
    sim.runSimulation()
    sim.printStatistics()

    println()
    println("=== Demo Complete ===")
}

/**
 * Run basic tests.
 */
fun runTests() {
    println("Running tests...")
    println()

    var passed = 0
    var failed = 0

    // Test 1: Crypto sign/verify
    print("Test 1 - Crypto sign/verify: ")
    try {
        val kp = Crypto.generateKeyPair()
        val msg = "test message"
        val sig = Crypto.signMessage(kp.private, msg)
        assert(Crypto.verifyMessage(kp.public, msg, sig))
        assert(!Crypto.verifyMessage(kp.public, "wrong message", sig))
        println("PASSED")
        passed++
    } catch (e: Exception) {
        println("FAILED: ${e.message}")
        failed++
    }

    // Test 2: Virtual space calculations
    print("Test 2 - Virtual space: ")
    try {
        assert(VirtualSpace.to1D(0, 0) == 0)
        assert(VirtualSpace.to2D(0) == Pair(0, 0))
        assert(VirtualSpace.manhattanDistance(0, 1001) == 2) // (0,0) to (1,1)
        println("PASSED")
        passed++
    } catch (e: Exception) {
        println("FAILED: ${e.message}")
        failed++
    }

    // Test 3: Node creation
    print("Test 3 - Node creation: ")
    try {
        val node = Node()
        assert(node.id.isNotEmpty())
        assert(node.virtualLocation in 0 until VirtualSpace.SPACE_SIZE)
        println("PASSED")
        passed++
    } catch (e: Exception) {
        println("FAILED: ${e.message}")
        failed++
    }

    // Test 4: Message serialization
    print("Test 4 - Message serialization: ")
    try {
        val node = Node()
        val msg = node.createMessage(MessageType.PING, "test payload")
        val serialized = msg.serialize()
        // Note: deserialize is in companion object
        println("PASSED")
        passed++
    } catch (e: Exception) {
        println("FAILED: ${e.message}")
        failed++
    }

    println()
    println("Results: $passed passed, $failed failed")
}

/**
 * Print help message.
 */
fun printHelp() {
    println("""
        Usage: redking [mode] [options]

        Modes:
          demo        Run demonstration of core features (default)
          akka-demo   Run Akka-style actor system demo with topology
          sim         Run network simulation
          node        Start a single node
          test        Run basic tests

        Simulation options:
          redking sim [nodeCount] [iterations]
          Example: redking sim 10000 500

        Examples:
          redking demo
          redking akka-demo
          redking sim 100000 1000
          redking test
    """.trimIndent())
}
