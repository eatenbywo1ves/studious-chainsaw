package redking.simulation;

import org.jgrapht.Graph;
import org.jgrapht.generate.RandomRegularGraphGenerator;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.util.SupplierUtil;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.*;
import java.util.function.Supplier;

/**
 * Main simulation class for the RedKing P2P network.
 * Generates a random regular graph and runs the Sundberg swap algorithm
 * to achieve Small World Network topology.
 */
public class NetworkSimulation {
    private final int nodeCount;
    private final int degree;
    private final int iterations;
    private final Graph<SimNode, DefaultEdge> graph;
    private final SwapAlgorithm swapAlgorithm;
    private final SecureRandom random;

    public NetworkSimulation(int nodeCount, int degree, int iterations) {
        this.nodeCount = nodeCount;
        this.degree = degree;
        this.iterations = iterations;
        this.swapAlgorithm = new SwapAlgorithm();
        this.random = new SecureRandom();

        // Create node supplier
        Supplier<SimNode> nodeSupplier = SimNode::new;

        // Create graph with node supplier
        this.graph = new SimpleGraph<>(nodeSupplier, SupplierUtil.DEFAULT_EDGE_SUPPLIER, false);
    }

    /**
     * Generate the initial random regular graph.
     */
    public void generateNetwork() {
        System.out.println("Generating random regular graph with " + nodeCount +
                           " nodes and degree " + degree + "...");

        RandomRegularGraphGenerator<SimNode, DefaultEdge> generator =
            new RandomRegularGraphGenerator<>(nodeCount, degree);

        generator.generateGraph(graph);

        System.out.println("Network generated. Nodes: " + graph.vertexSet().size() +
                           ", Edges: " + graph.edgeSet().size());
    }

    /**
     * Run the swap algorithm for the specified number of iterations.
     */
    public void runSimulation() {
        System.out.println("Running swap algorithm for " + iterations + " iterations...");

        List<SimNode> nodes = new ArrayList<>(graph.vertexSet());
        int totalSwaps = 0;

        for (int i = 0; i < iterations; i++) {
            int swapsThisIteration = 0;

            // Shuffle nodes for random order processing
            Collections.shuffle(nodes, random);

            for (SimNode node : nodes) {
                SimNode neighbor = swapAlgorithm.selectRandomNeighbor(node, graph);
                if (neighbor != null) {
                    if (swapAlgorithm.swap(node, neighbor, graph)) {
                        swapsThisIteration++;
                    }
                }
            }

            totalSwaps += swapsThisIteration;

            if ((i + 1) % 100 == 0 || i == 0) {
                System.out.println("Iteration " + (i + 1) + "/" + iterations +
                                   " - Swaps this iteration: " + swapsThisIteration);
            }
        }

        System.out.println("Simulation complete. Total swaps: " + totalSwaps);
    }

    /**
     * Calculate and return the distance distribution histogram.
     */
    public Map<Integer, Integer> calculateDistanceDistribution() {
        Map<Integer, Integer> distribution = new TreeMap<>();
        List<SimNode> nodes = new ArrayList<>(graph.vertexSet());

        for (SimNode node : nodes) {
            List<SimNode> neighbors = swapAlgorithm.getNeighbors(node, graph);
            for (SimNode neighbor : neighbors) {
                int distance = Math.abs(node.getLocation() - neighbor.getLocation());
                // Bucket distances into ranges
                int bucket = distance / 10000;
                distribution.merge(bucket, 1, Integer::sum);
            }
        }

        return distribution;
    }

    /**
     * Export distance distribution to a file for analysis.
     */
    public void exportDistribution(String filename) throws IOException {
        Map<Integer, Integer> distribution = calculateDistanceDistribution();

        try (PrintWriter writer = new PrintWriter(new FileWriter(filename))) {
            writer.println("bucket,count");
            for (Map.Entry<Integer, Integer> entry : distribution.entrySet()) {
                writer.println(entry.getKey() + "," + entry.getValue());
            }
        }

        System.out.println("Distribution exported to " + filename);
    }

    /**
     * Get network statistics.
     */
    public void printStatistics() {
        List<SimNode> nodes = new ArrayList<>(graph.vertexSet());

        // Calculate average distance to neighbors
        double totalDistance = 0;
        int edgeCount = 0;

        for (SimNode node : nodes) {
            List<SimNode> neighbors = swapAlgorithm.getNeighbors(node, graph);
            for (SimNode neighbor : neighbors) {
                totalDistance += Math.abs(node.getLocation() - neighbor.getLocation());
                edgeCount++;
            }
        }

        double avgDistance = totalDistance / edgeCount;

        System.out.println("\n=== Network Statistics ===");
        System.out.println("Nodes: " + nodes.size());
        System.out.println("Edges: " + graph.edgeSet().size());
        System.out.println("Average neighbor distance: " + String.format("%.2f", avgDistance));
    }

    public Graph<SimNode, DefaultEdge> getGraph() {
        return graph;
    }

    /**
     * Main entry point for running the simulation.
     */
    public static void main(String[] args) {
        // Default parameters (can be overridden via command line)
        int nodeCount = 10000;  // Use 10K for testing, 1M for full simulation
        int degree = 6;         // Each node has 6 neighbors
        int iterations = 500;   // Number of swap iterations

        if (args.length >= 1) {
            nodeCount = Integer.parseInt(args[0]);
        }
        if (args.length >= 2) {
            iterations = Integer.parseInt(args[1]);
        }

        System.out.println("=== RedKing Network Simulation ===");
        System.out.println("Node count: " + nodeCount);
        System.out.println("Degree: " + degree);
        System.out.println("Iterations: " + iterations);
        System.out.println();

        NetworkSimulation sim = new NetworkSimulation(nodeCount, degree, iterations);

        // Generate initial network
        sim.generateNetwork();

        // Print initial statistics
        System.out.println("\nBefore swap algorithm:");
        sim.printStatistics();

        // Run swap algorithm
        sim.runSimulation();

        // Print final statistics
        System.out.println("\nAfter swap algorithm:");
        sim.printStatistics();

        // Export distribution
        try {
            sim.exportDistribution("distance_distribution.csv");
        } catch (IOException e) {
            System.err.println("Failed to export distribution: " + e.getMessage());
        }
    }
}
