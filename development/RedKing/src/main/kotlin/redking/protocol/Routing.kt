package redking.protocol

import redking.core.Node

/**
 * Implements greedy routing for the Small World Network.
 * Uses the Kleinberg algorithm for efficient O(log(n)^2) routing.
 */
object Routing {

    /**
     * Find the best neighbor to route a message towards a target location.
     * Uses greedy routing - always picks the neighbor closest to target.
     */
    fun findNextHop(node: Node, targetLocation: Int): Node.Neighbor? {
        val neighbors = node.getNeighbors()
        if (neighbors.isEmpty()) return null

        // Find neighbor with minimum distance to target
        return neighbors.minByOrNull { neighbor ->
            Math.abs(neighbor.virtualLocation - targetLocation)
        }
    }

    /**
     * Calculate the expected number of hops to reach a target.
     * Based on Kleinberg's analysis: O(log(n)^2) for properly organized networks.
     */
    fun estimateHops(currentLocation: Int, targetLocation: Int, networkSize: Int): Int {
        val distance = Math.abs(currentLocation - targetLocation)
        if (distance == 0) return 0

        // Kleinberg's formula approximation
        val logN = Math.log(networkSize.toDouble())
        return (logN * logN * Math.log(distance.toDouble()) / Math.log(networkSize.toDouble())).toInt()
    }

    /**
     * Route a message through the network using greedy routing.
     * Returns the path taken as a list of node IDs.
     */
    fun routeMessage(
        startNode: Node,
        targetLocation: Int,
        maxHops: Int = 100,
        getNode: (String) -> Node?
    ): RoutingResult {
        val path = mutableListOf(startNode.id)
        var currentNode = startNode
        var hops = 0

        while (hops < maxHops) {
            // Check if we've reached the target
            if (currentNode.virtualLocation == targetLocation) {
                return RoutingResult(
                    success = true,
                    path = path,
                    hops = hops,
                    finalLocation = currentNode.virtualLocation
                )
            }

            // Find next hop
            val nextNeighbor = findNextHop(currentNode, targetLocation)
            if (nextNeighbor == null) {
                return RoutingResult(
                    success = false,
                    path = path,
                    hops = hops,
                    finalLocation = currentNode.virtualLocation,
                    error = "No neighbors available"
                )
            }

            // Check if we're making progress
            val currentDistance = Math.abs(currentNode.virtualLocation - targetLocation)
            val nextDistance = Math.abs(nextNeighbor.virtualLocation - targetLocation)

            if (nextDistance >= currentDistance) {
                // Not making progress - this is as close as we can get
                return RoutingResult(
                    success = true,
                    path = path,
                    hops = hops,
                    finalLocation = currentNode.virtualLocation,
                    note = "Closest reachable location"
                )
            }

            // Move to next node
            path.add(nextNeighbor.nodeId)
            currentNode = getNode(nextNeighbor.nodeId) ?: return RoutingResult(
                success = false,
                path = path,
                hops = hops,
                finalLocation = currentNode.virtualLocation,
                error = "Node not found: ${nextNeighbor.nodeId}"
            )
            hops++
        }

        return RoutingResult(
            success = false,
            path = path,
            hops = hops,
            finalLocation = currentNode.virtualLocation,
            error = "Max hops exceeded"
        )
    }

    /**
     * Result of a routing operation.
     */
    data class RoutingResult(
        val success: Boolean,
        val path: List<String>,
        val hops: Int,
        val finalLocation: Int,
        val error: String? = null,
        val note: String? = null
    )
}
