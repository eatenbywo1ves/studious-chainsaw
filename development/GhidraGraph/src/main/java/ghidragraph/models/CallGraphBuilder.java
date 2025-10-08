/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidragraph.models;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.service.graph.*;
import ghidra.util.task.TaskMonitor;

/**
 * Builder for creating call graphs from Ghidra function analysis
 *
 * This class handles the recursive traversal of function calls and
 * builds an AttributedGraph suitable for display or export.
 */
public class CallGraphBuilder {

	private Set<String> visitedFunctions;
	private Pattern filterPattern;
	private int maxDepth;
	private boolean includeCallers;
	private boolean includeCallees;

	/**
	 * Constructor
	 */
	public CallGraphBuilder() {
		this.visitedFunctions = new HashSet<>();
		this.maxDepth = 5;
		this.includeCallers = false;
		this.includeCallees = true;
		this.filterPattern = null;
	}

	/**
	 * Set the maximum recursion depth
	 *
	 * @param depth Maximum depth (1-10)
	 */
	public void setMaxDepth(int depth) {
		if (depth < 1 || depth > 10) {
			throw new IllegalArgumentException("Depth must be between 1 and 10");
		}
		this.maxDepth = depth;
	}

	/**
	 * Set the direction of graph traversal
	 *
	 * @param includeCallers Include calling functions (parents)
	 * @param includeCallees Include called functions (children)
	 */
	public void setDirection(boolean includeCallers, boolean includeCallees) {
		this.includeCallers = includeCallers;
		this.includeCallees = includeCallees;
	}

	/**
	 * Set a regex filter for function names
	 *
	 * @param regex Regular expression pattern, or null for no filter
	 */
	public void setFilter(String regex) {
		if (regex == null || regex.trim().isEmpty()) {
			this.filterPattern = null;
		}
		else {
			this.filterPattern = Pattern.compile(regex);
		}
	}

	/**
	 * Build a call graph starting from a specific function
	 *
	 * @param startFunction The root function to analyze
	 * @param monitor Task monitor for cancellation
	 * @return AttributedGraph containing the call graph
	 * @throws Exception if graph building fails
	 */
	public AttributedGraph buildGraph(Function startFunction, TaskMonitor monitor)
			throws Exception {

		if (startFunction == null) {
			throw new IllegalArgumentException("Start function cannot be null");
		}

		// Clear visited set for new graph
		visitedFunctions.clear();

		// Create graph type
		GraphType graphType = new GraphTypeBuilder("Call Graph")
				.description("Function call relationships")
				.vertexType("Entry Function")
				.vertexType("Called Function")
				.vertexType("Calling Function")
				.edgeType("Calls")
				.edgeType("Called By")
				.build();

		// Create the graph
		AttributedGraph graph = new AttributedGraph(
			"Call Graph: " + startFunction.getName(),
			graphType
		);

		// Add the root vertex
		String rootId = getFunctionId(startFunction);
		AttributedVertex rootVertex = graph.addVertex(rootId, startFunction.getName());
		rootVertex.setVertexType("Entry Function");
		visitedFunctions.add(rootId);

		// Recursively build the graph
		if (includeCallees) {
			buildCalledGraph(graph, startFunction, rootVertex, 0, monitor);
		}

		if (includeCallers) {
			buildCallingGraph(graph, startFunction, rootVertex, 0, monitor);
		}

		return graph;
	}

	/**
	 * Recursively build graph of called functions (children)
	 *
	 * @param graph The graph being built
	 * @param function Current function
	 * @param currentVertex Vertex for current function
	 * @param depth Current recursion depth
	 * @param monitor Task monitor
	 */
	private void buildCalledGraph(AttributedGraph graph, Function function,
			AttributedVertex currentVertex, int depth, TaskMonitor monitor) {

		if (monitor.isCancelled() || depth >= maxDepth) {
			return;
		}

		Set<Function> calledFunctions = function.getCalledFunctions(monitor);

		for (Function calledFunc : calledFunctions) {
			if (monitor.isCancelled()) {
				break;
			}

			// Apply filter if set
			if (!matchesFilter(calledFunc)) {
				continue;
			}

			String funcId = getFunctionId(calledFunc);

			// Add vertex if not already visited
			AttributedVertex calledVertex;
			if (visitedFunctions.contains(funcId)) {
				calledVertex = graph.getVertex(funcId);
			}
			else {
				calledVertex = graph.addVertex(funcId, calledFunc.getName());
				calledVertex.setVertexType("Called Function");
				visitedFunctions.add(funcId);

				// Recurse into this function
				buildCalledGraph(graph, calledFunc, calledVertex, depth + 1, monitor);
			}

			// Add edge from current to called
			if (calledVertex != null) {
				AttributedEdge edge = graph.addEdge(currentVertex, calledVertex);
				edge.setEdgeType("Calls");
			}
		}
	}

	/**
	 * Recursively build graph of calling functions (parents)
	 *
	 * @param graph The graph being built
	 * @param function Current function
	 * @param currentVertex Vertex for current function
	 * @param depth Current recursion depth
	 * @param monitor Task monitor
	 */
	private void buildCallingGraph(AttributedGraph graph, Function function,
			AttributedVertex currentVertex, int depth, TaskMonitor monitor) {

		if (monitor.isCancelled() || depth >= maxDepth) {
			return;
		}

		Set<Function> callingFunctions = function.getCallingFunctions(monitor);

		for (Function callingFunc : callingFunctions) {
			if (monitor.isCancelled()) {
				break;
			}

			// Apply filter if set
			if (!matchesFilter(callingFunc)) {
				continue;
			}

			String funcId = getFunctionId(callingFunc);

			// Add vertex if not already visited
			AttributedVertex callingVertex;
			if (visitedFunctions.contains(funcId)) {
				callingVertex = graph.getVertex(funcId);
			}
			else {
				callingVertex = graph.addVertex(funcId, callingFunc.getName());
				callingVertex.setVertexType("Calling Function");
				visitedFunctions.add(funcId);

				// Recurse into this function
				buildCallingGraph(graph, callingFunc, callingVertex, depth + 1, monitor);
			}

			// Add edge from calling to current
			if (callingVertex != null) {
				AttributedEdge edge = graph.addEdge(callingVertex, currentVertex);
				edge.setEdgeType("Called By");
			}
		}
	}

	/**
	 * Check if function matches the filter pattern
	 *
	 * @param function Function to check
	 * @return true if matches or no filter set
	 */
	private boolean matchesFilter(Function function) {
		if (filterPattern == null) {
			return true;
		}
		return filterPattern.matcher(function.getName()).find();
	}

	/**
	 * Generate a unique ID for a function
	 *
	 * @param function The function
	 * @return Unique ID string
	 */
	private String getFunctionId(Function function) {
		return function.getEntryPoint().toString();
	}
}
