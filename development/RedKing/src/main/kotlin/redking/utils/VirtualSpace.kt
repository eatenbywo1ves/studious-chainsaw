package redking.utils

import java.security.SecureRandom

/**
 * Manages the virtual addressing space for the RedKing network.
 * Uses a 2D lattice as described in Kleinberg's model.
 */
object VirtualSpace {
    // Address space dimensions
    const val SPACE_SIZE = 1_000_000
    const val GRID_SIZE = 1000 // 1000x1000 = 1M locations

    private val random = SecureRandom()

    /**
     * Generate a random location in the virtual space.
     */
    fun randomLocation(): Int {
        return random.nextInt(SPACE_SIZE)
    }

    /**
     * Convert a 1D location to 2D grid coordinates.
     */
    fun to2D(location: Int): Pair<Int, Int> {
        val x = location % GRID_SIZE
        val y = location / GRID_SIZE
        return Pair(x, y)
    }

    /**
     * Convert 2D grid coordinates to 1D location.
     */
    fun to1D(x: Int, y: Int): Int {
        return y * GRID_SIZE + x
    }

    /**
     * Calculate Manhattan distance between two locations.
     */
    fun manhattanDistance(loc1: Int, loc2: Int): Int {
        val (x1, y1) = to2D(loc1)
        val (x2, y2) = to2D(loc2)
        return Math.abs(x1 - x2) + Math.abs(y1 - y2)
    }

    /**
     * Calculate Euclidean distance between two locations.
     */
    fun euclideanDistance(loc1: Int, loc2: Int): Double {
        val (x1, y1) = to2D(loc1)
        val (x2, y2) = to2D(loc2)
        val dx = x1 - x2
        val dy = y1 - y2
        return Math.sqrt((dx * dx + dy * dy).toDouble())
    }

    /**
     * Calculate ring distance (1D) between two locations.
     * Treats the space as a ring where location 0 and SPACE_SIZE-1 are adjacent.
     */
    fun ringDistance(loc1: Int, loc2: Int): Int {
        val direct = Math.abs(loc1 - loc2)
        val wrap = SPACE_SIZE - direct
        return minOf(direct, wrap)
    }

    /**
     * Calculate the Kleinberg probability for connecting two nodes.
     * P(connection) proportional to 1/d^alpha
     * where d is distance and alpha is typically 2 for 2D grids.
     */
    fun kleinbergProbability(loc1: Int, loc2: Int, alpha: Double = 2.0): Double {
        val distance = manhattanDistance(loc1, loc2)
        if (distance == 0) return 1.0
        return 1.0 / Math.pow(distance.toDouble(), alpha)
    }

    /**
     * Generate a set of locations that form a local neighborhood.
     */
    fun localNeighborhood(center: Int, radius: Int): Set<Int> {
        val neighbors = mutableSetOf<Int>()
        val (cx, cy) = to2D(center)

        for (dx in -radius..radius) {
            for (dy in -radius..radius) {
                if (dx == 0 && dy == 0) continue

                val nx = (cx + dx + GRID_SIZE) % GRID_SIZE
                val ny = (cy + dy + GRID_SIZE) % GRID_SIZE
                neighbors.add(to1D(nx, ny))
            }
        }

        return neighbors
    }

    /**
     * Select a long-range contact using Kleinberg distribution.
     * Higher probability for closer nodes, but allows long-range links.
     */
    fun selectLongRangeContact(fromLocation: Int, excludeLocations: Set<Int> = emptySet()): Int {
        // Use inverse square distribution
        var attempts = 0
        while (attempts < 1000) {
            val candidate = randomLocation()
            if (candidate == fromLocation || candidate in excludeLocations) {
                attempts++
                continue
            }

            val probability = kleinbergProbability(fromLocation, candidate)
            if (random.nextDouble() < probability * SPACE_SIZE) {
                return candidate
            }
            attempts++
        }

        // Fallback: return a random location
        var result: Int
        do {
            result = randomLocation()
        } while (result == fromLocation || result in excludeLocations)
        return result
    }

    /**
     * Validate a location is within bounds.
     */
    fun isValidLocation(location: Int): Boolean {
        return location in 0 until SPACE_SIZE
    }

    /**
     * Clamp a location to valid bounds.
     */
    fun clampLocation(location: Int): Int {
        return when {
            location < 0 -> location % SPACE_SIZE + SPACE_SIZE
            location >= SPACE_SIZE -> location % SPACE_SIZE
            else -> location
        }
    }
}
