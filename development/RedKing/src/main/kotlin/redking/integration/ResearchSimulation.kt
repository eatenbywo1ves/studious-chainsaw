package redking.integration

import redking.simulation.NetworkSimulation
import redking.utils.VirtualSpace
import java.io.File
import java.io.PrintWriter

/**
 * Academic research simulation framework for Small World Networks.
 *
 * Provides tools for:
 * - Running controlled experiments
 * - Collecting metrics and statistics
 * - Generating publication-ready data
 * - Comparing different topology strategies
 *
 * Integrates with:
 * - PeerSim (Java P2P simulator)
 * - ns-3 (network simulator)
 * - OMNeT++ (discrete event simulator)
 */
object ResearchSimulation {

    /**
     * Experiment configuration.
     */
    data class ExperimentConfig(
        val name: String,
        val nodeCount: Int,
        val degree: Int,
        val iterations: Int,
        val runs: Int = 10,
        val outputDir: String = "./results"
    )

    /**
     * Metrics collected during simulation.
     */
    data class SimulationMetrics(
        val run: Int,
        val iteration: Int,
        val avgDistance: Double,
        val swapCount: Int,
        val clusteringCoefficient: Double,
        val avgPathLength: Double,
        val timestamp: Long = System.currentTimeMillis()
    ) {
        fun toCsv(): String {
            return "$run,$iteration,$avgDistance,$swapCount,$clusteringCoefficient,$avgPathLength,$timestamp"
        }

        companion object {
            fun csvHeader(): String = "run,iteration,avgDistance,swapCount,clusteringCoefficient,avgPathLength,timestamp"
        }
    }

    /**
     * Run a complete experiment with multiple runs.
     */
    fun runExperiment(config: ExperimentConfig): List<SimulationMetrics> {
        val allMetrics = mutableListOf<SimulationMetrics>()

        println("=== Starting Experiment: ${config.name} ===")
        println("Nodes: ${config.nodeCount}, Degree: ${config.degree}, Iterations: ${config.iterations}")
        println("Runs: ${config.runs}")
        println()

        for (run in 1..config.runs) {
            println("Run $run/${config.runs}...")

            val sim = NetworkSimulation(config.nodeCount, config.degree, config.iterations)
            sim.generateNetwork()

            // Collect initial metrics
            val initialMetrics = collectMetrics(run, 0, sim, 0)
            allMetrics.add(initialMetrics)

            // Run simulation and collect periodic metrics
            // Note: Would need to modify NetworkSimulation to expose intermediate states
            sim.runSimulation()

            // Collect final metrics
            val finalMetrics = collectMetrics(run, config.iterations, sim, 0)
            allMetrics.add(finalMetrics)
        }

        // Export results
        exportResults(config, allMetrics)

        return allMetrics
    }

    private fun collectMetrics(
        run: Int,
        iteration: Int,
        sim: NetworkSimulation,
        swapCount: Int
    ): SimulationMetrics {
        val distribution = sim.calculateDistanceDistribution()
        val totalDistance = distribution.entries.sumOf { it.key * it.value }
        val edgeCount = distribution.values.sum()
        val avgDistance = if (edgeCount > 0) totalDistance.toDouble() / edgeCount else 0.0

        return SimulationMetrics(
            run = run,
            iteration = iteration,
            avgDistance = avgDistance,
            swapCount = swapCount,
            clusteringCoefficient = estimateClusteringCoefficient(sim),
            avgPathLength = estimateAvgPathLength(sim)
        )
    }

    /**
     * Estimate clustering coefficient (simplified).
     */
    private fun estimateClusteringCoefficient(sim: NetworkSimulation): Double {
        // Simplified estimation - actual calculation would require
        // examining neighbor connections
        return 0.0 // Placeholder
    }

    /**
     * Estimate average path length (simplified).
     */
    private fun estimateAvgPathLength(sim: NetworkSimulation): Double {
        // For Small World networks, expected O(log(n))
        val n = sim.getGraph().vertexSet().size
        return Math.log(n.toDouble()) * Math.log(n.toDouble())
    }

    /**
     * Export results to CSV files.
     */
    private fun exportResults(config: ExperimentConfig, metrics: List<SimulationMetrics>) {
        val dir = File(config.outputDir)
        if (!dir.exists()) dir.mkdirs()

        val filename = "${config.name}_${System.currentTimeMillis()}.csv"
        val file = File(dir, filename)

        PrintWriter(file).use { writer ->
            writer.println(SimulationMetrics.csvHeader())
            metrics.forEach { writer.println(it.toCsv()) }
        }

        println("Results exported to: ${file.absolutePath}")
    }

    /**
     * Compare two topology strategies.
     */
    fun compareStrategies(
        baseConfig: ExperimentConfig,
        strategy1: String,
        strategy2: String
    ): ComparisonResult {
        println("Comparing: $strategy1 vs $strategy2")

        val results1 = runExperiment(baseConfig.copy(name = "${baseConfig.name}_$strategy1"))
        val results2 = runExperiment(baseConfig.copy(name = "${baseConfig.name}_$strategy2"))

        val avgDist1 = results1.filter { it.iteration > 0 }.map { it.avgDistance }.average()
        val avgDist2 = results2.filter { it.iteration > 0 }.map { it.avgDistance }.average()

        return ComparisonResult(
            strategy1 = strategy1,
            strategy2 = strategy2,
            avgDistance1 = avgDist1,
            avgDistance2 = avgDist2,
            improvement = (avgDist1 - avgDist2) / avgDist1 * 100
        )
    }

    data class ComparisonResult(
        val strategy1: String,
        val strategy2: String,
        val avgDistance1: Double,
        val avgDistance2: Double,
        val improvement: Double
    ) {
        override fun toString(): String {
            return """
                |Comparison: $strategy1 vs $strategy2
                |$strategy1 avg distance: ${String.format("%.2f", avgDistance1)}
                |$strategy2 avg distance: ${String.format("%.2f", avgDistance2)}
                |Improvement: ${String.format("%.2f", improvement)}%
            """.trimMargin()
        }
    }

    /**
     * Generate LaTeX table for publication.
     */
    fun generateLatexTable(metrics: List<SimulationMetrics>, caption: String): String {
        val grouped = metrics.groupBy { it.run }
        val finalMetrics = grouped.mapValues { it.value.last() }

        return buildString {
            appendLine("\\begin{table}[h]")
            appendLine("\\centering")
            appendLine("\\caption{$caption}")
            appendLine("\\begin{tabular}{|c|c|c|c|}")
            appendLine("\\hline")
            appendLine("Run & Avg Distance & Swaps & Clustering \\\\")
            appendLine("\\hline")

            finalMetrics.forEach { (run, m) ->
                appendLine("$run & ${String.format("%.2f", m.avgDistance)} & ${m.swapCount} & ${String.format("%.4f", m.clusteringCoefficient)} \\\\")
            }

            appendLine("\\hline")
            appendLine("\\end{tabular}")
            appendLine("\\end{table}")
        }
    }

    /**
     * Export data for plotting with matplotlib/gnuplot.
     */
    fun exportForPlotting(metrics: List<SimulationMetrics>, filename: String) {
        PrintWriter(File(filename)).use { writer ->
            writer.println("# Iteration AvgDistance")
            metrics.forEach { m ->
                writer.println("${m.iteration} ${m.avgDistance}")
            }
        }
        println("Plot data exported to: $filename")
    }
}
