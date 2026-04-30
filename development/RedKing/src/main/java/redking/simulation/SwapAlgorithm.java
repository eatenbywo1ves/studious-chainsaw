package redking.simulation;

import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Implements the Sundberg Swap Algorithm for self-organizing
 * the network into a Small World topology.
 *
 * The algorithm works by:
 * 1. Selecting a random neighbor
 * 2. Calculating distance products for current and swapped configurations
 * 3. Swapping if beneficial, or probabilistically otherwise (simulated annealing)
 */
public class SwapAlgorithm {
    private final SecureRandom random;

    public SwapAlgorithm() {
        this.random = new SecureRandom();
    }

    /**
     * Perform the Sundberg swap algorithm between two nodes.
     *
     * @param a The node initiating the swap
     * @param b The neighbor node to potentially swap with
     * @param graph The network graph
     * @return true if swap occurred, false otherwise
     */
    public boolean swap(SimNode a, SimNode b, Graph<SimNode, DefaultEdge> graph) {
        // Get neighbors for both nodes
        List<SimNode> aNeighbors = getNeighbors(a, graph);
        List<SimNode> bNeighbors = getNeighbors(b, graph);

        // Calculate D1: product of distances for current configuration
        double d1 = calculateDistanceProduct(a, aNeighbors) *
                    calculateDistanceProduct(b, bNeighbors);

        // Calculate D2: product of distances if we swap locations
        double d2 = calculateDistanceProductSwapped(a, b, aNeighbors) *
                    calculateDistanceProductSwapped(b, a, bNeighbors);

        // Prevent division by zero
        if (d1 == 0 || d2 == 0) {
            return false;
        }

        // Swap decision
        if (d2 <= d1) {
            // Swap is beneficial - do it
            performSwap(a, b);
            return true;
        } else {
            // Probabilistic swap (simulated annealing)
            double probability = d1 / d2;
            if (random.nextDouble() < probability) {
                performSwap(a, b);
                return true;
            }
        }
        return false;
    }

    /**
     * Calculate the product of distances from a node to all its neighbors.
     */
    private double calculateDistanceProduct(SimNode node, List<SimNode> neighbors) {
        double product = 1.0;
        for (SimNode neighbor : neighbors) {
            int distance = Math.abs(node.getLocation() - neighbor.getLocation());
            if (distance > 0) {
                product *= distance;
            }
        }
        return product;
    }

    /**
     * Calculate the product of distances as if nodeA had nodeB's location.
     */
    private double calculateDistanceProductSwapped(SimNode nodeA, SimNode nodeB,
                                                    List<SimNode> neighbors) {
        double product = 1.0;
        for (SimNode neighbor : neighbors) {
            int distance;
            if (neighbor.equals(nodeB)) {
                // If neighbor is the swap partner, use nodeA's current location
                distance = Math.abs(nodeB.getLocation() - nodeA.getLocation());
            } else {
                // Otherwise calculate distance from nodeB's location to neighbor
                distance = Math.abs(nodeB.getLocation() - neighbor.getLocation());
            }
            if (distance > 0) {
                product *= distance;
            }
        }
        return product;
    }

    /**
     * Swap the virtual locations of two nodes.
     */
    private void performSwap(SimNode a, SimNode b) {
        int tempLocation = a.getLocation();
        a.setLocation(b.getLocation());
        b.setLocation(tempLocation);
    }

    /**
     * Get all neighbors of a node in the graph.
     */
    public List<SimNode> getNeighbors(SimNode node, Graph<SimNode, DefaultEdge> graph) {
        List<SimNode> neighbors = new ArrayList<>();
        Set<DefaultEdge> edges = graph.edgesOf(node);
        for (DefaultEdge edge : edges) {
            SimNode source = graph.getEdgeSource(edge);
            SimNode target = graph.getEdgeTarget(edge);
            if (source.equals(node)) {
                neighbors.add(target);
            } else {
                neighbors.add(source);
            }
        }
        return neighbors;
    }

    /**
     * Select a random neighbor from the graph.
     */
    public SimNode selectRandomNeighbor(SimNode node, Graph<SimNode, DefaultEdge> graph) {
        List<SimNode> neighbors = getNeighbors(node, graph);
        if (neighbors.isEmpty()) {
            return null;
        }
        return neighbors.get(random.nextInt(neighbors.size()));
    }
}
