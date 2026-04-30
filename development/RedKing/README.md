# RedKing - P2P Hivemind Network

A decentralized peer-to-peer network implementation based on Kleinberg's Small World Network model.

## Overview

RedKing implements a self-organizing P2P network that achieves efficient O(log(n)^2) greedy routing without requiring central coordination. The network uses the Sundberg Swap Algorithm to naturally evolve into a Small World topology.

## Features

- **Self-Organizing Topology**: Network automatically organizes into optimal Small World structure
- **Efficient Routing**: O(log(n)^2) greedy routing using Kleinberg distribution
- **Cryptographic Security**: RSA-based message signing and verification
- **Decentralized**: No central command & control servers required
- **Scalable**: Tested with up to 1 million nodes in simulation

## Project Structure

```
RedKing/
├── src/
│   ├── main/
│   │   ├── java/redking/simulation/
│   │   │   ├── SimNode.java          # Node representation
│   │   │   ├── SwapAlgorithm.java    # Sundberg swap implementation
│   │   │   └── NetworkSimulation.java # Simulation engine
│   │   └── kotlin/redking/
│   │       ├── Main.kt               # Entry point
│   │       ├── core/
│   │       │   ├── Crypto.kt         # RSA signing/verification
│   │       │   ├── Node.kt           # P2P node implementation
│   │       │   └── Network.kt        # Network management
│   │       ├── protocol/
│   │       │   ├── Message.kt        # Message types & serialization
│   │       │   └── Routing.kt        # Greedy routing algorithm
│   │       └── utils/
│   │           └── VirtualSpace.kt   # 2D lattice addressing
│   └── test/
├── build.gradle.kts
└── README.md
```

## Building

```bash
# Build the project
./gradlew build

# Create executable JAR
./gradlew jar
```

## Running

### Demo Mode (Default)
```bash
./gradlew run
# or
java -jar build/libs/RedKing-1.0-SNAPSHOT.jar demo
```

### Network Simulation
```bash
# Run with 10,000 nodes and 500 iterations
./gradlew run --args="sim 10000 500"

# Run with 1 million nodes (requires significant memory)
java -Xmx8g -jar build/libs/RedKing-1.0-SNAPSHOT.jar sim 1000000 2000
```

### Tests
```bash
./gradlew run --args="test"
```

## Algorithm

### Sundberg Swap Algorithm

The network self-organizes using the following swap algorithm:

1. Each node picks a random neighbor B
2. Calculate D1 = product of distances (current configuration)
3. Calculate D2 = product of distances (if swapped)
4. If D2 < D1: swap virtual locations
5. Else: swap with probability D1/D2 (simulated annealing)

This causes the network to converge to a Kleinberg distribution, where connection probability is proportional to 1/d^α (typically α=2 for 2D grids).

### Greedy Routing

Once organized, messages can be routed efficiently:
- Each node forwards to the neighbor closest to target
- Expected hops: O(log(n)^2) for n nodes
- No global routing tables required

## API Reference

### Node
```kotlin
val node = Node()
node.addNeighbor(id, publicKey, location)
node.createMessage(MessageType.PING, "payload")
node.proposeSwap(neighborId)
```

### Crypto
```kotlin
val keyPair = Crypto.generateKeyPair()
val signature = Crypto.signMessage(privateKey, message)
val valid = Crypto.verifyMessage(publicKey, message, signature)
```

### VirtualSpace
```kotlin
val location = VirtualSpace.randomLocation()
val (x, y) = VirtualSpace.to2D(location)
val distance = VirtualSpace.manhattanDistance(loc1, loc2)
```

## References

- Kleinberg, J. "The Small-World Phenomenon: An Algorithmic Perspective" (2000)
- Milgram, S. "The Small World Problem" (1967)
- Original document: "The Hacking Hivemind" by b0t

## License

Research/Educational use only.

## Disclaimer

This implementation is for educational and research purposes. The concepts demonstrated could potentially be misused. Users are responsible for ensuring legal and ethical use.
