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
package ghidragraph.services;

import java.util.HashMap;
import java.util.Map;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.AttributedEdge;

/**
 * Exports AttributedGraph to Mermaid.js flowchart format
 *
 * Mermaid.js is a markdown-compatible diagram syntax that renders
 * in GitHub, GitLab, and many documentation tools.
 *
 * Format: flowchart TD
 *         A[Function A] --> B[Function B]
 *         B --> C[Function C]
 */
public class MermaidExporter {

	private Map<String, String> vertexIdMap;
	private int nextId;

	/**
	 * Constructor
	 */
	public MermaidExporter() {
		this.vertexIdMap = new HashMap<>();
		this.nextId = 1;
	}

	/**
	 * Export graph to Mermaid.js format
	 *
	 * @param graph The graph to export
	 * @return Mermaid.js flowchart string
	 */
	public String export(AttributedGraph graph) {
		vertexIdMap.clear();
		nextId = 1;

		StringBuilder sb = new StringBuilder();

		// Header with graph title
		sb.append("```mermaid\n");

		// Determine direction based on graph size
		String direction = graph.getVertexCount() < 350 ? "TD" : "LR";
		sb.append("flowchart ").append(direction).append("\n");

		// Add title as a comment
		sb.append("    %% ").append(graph.getName()).append("\n");
		if (graph.getDescription() != null && !graph.getDescription().isEmpty()) {
			sb.append("    %% ").append(graph.getDescription()).append("\n");
		}
		sb.append("\n");

		// Export vertices with styling
		exportVertices(graph, sb);

		// Export edges
		exportEdges(graph, sb);

		// Add styling classes
		addStyling(sb);

		sb.append("```\n");

		return sb.toString();
	}

	/**
	 * Export vertices to Mermaid format
	 *
	 * @param graph The graph
	 * @param sb StringBuilder to append to
	 */
	private void exportVertices(AttributedGraph graph, StringBuilder sb) {
		sb.append("    %% Vertices\n");

		for (AttributedVertex vertex : graph.vertexSet()) {
			String mermaidId = getMermaidId(vertex.getId());
			String label = sanitizeLabel(vertex.getName());
			String shape = getShapeForVertexType(vertex.getVertexType());

			sb.append("    ").append(mermaidId);
			sb.append(shape.charAt(0)).append(label).append(shape.charAt(1));
			sb.append("\n");

			// Add styling class based on vertex type
			String cssClass = getCssClassForVertexType(vertex.getVertexType());
			if (cssClass != null) {
				sb.append("    class ").append(mermaidId).append(" ").append(cssClass).append("\n");
			}
		}

		sb.append("\n");
	}

	/**
	 * Export edges to Mermaid format
	 *
	 * @param graph The graph
	 * @param sb StringBuilder to append to
	 */
	private void exportEdges(AttributedGraph graph, StringBuilder sb) {
		sb.append("    %% Edges\n");

		for (AttributedEdge edge : graph.edgeSet()) {
			AttributedVertex source = graph.getEdgeSource(edge);
			AttributedVertex target = graph.getEdgeTarget(edge);

			String sourceMermaidId = getMermaidId(source.getId());
			String targetMermaidId = getMermaidId(target.getId());

			String arrow = getArrowForEdgeType(edge.getEdgeType());

			sb.append("    ").append(sourceMermaidId);
			sb.append(" ").append(arrow).append(" ");
			sb.append(targetMermaidId).append("\n");
		}

		sb.append("\n");
	}

	/**
	 * Add CSS styling classes
	 *
	 * @param sb StringBuilder to append to
	 */
	private void addStyling(StringBuilder sb) {
		sb.append("    %% Styling\n");
		sb.append("    classDef entryFunc fill:#90EE90,stroke:#006400,stroke-width:3px\n");
		sb.append("    classDef calledFunc fill:#87CEEB,stroke:#00008B,stroke-width:2px\n");
		sb.append("    classDef callingFunc fill:#FFB6C1,stroke:#8B0000,stroke-width:2px\n");
	}

	/**
	 * Get Mermaid-safe ID for a vertex
	 *
	 * @param originalId Original vertex ID
	 * @return Mermaid-safe ID
	 */
	private String getMermaidId(String originalId) {
		return vertexIdMap.computeIfAbsent(originalId, k -> "n" + (nextId++));
	}

	/**
	 * Sanitize label for Mermaid format
	 *
	 * @param label Original label
	 * @return Sanitized label
	 */
	private String sanitizeLabel(String label) {
		if (label == null) {
			return "Unknown";
		}

		// Escape special characters
		return label.replace("\"", "&quot;")
			.replace("[", "&#91;")
			.replace("]", "&#93;")
			.replace("(", "&#40;")
			.replace(")", "&#41;")
			.replace("{", "&#123;")
			.replace("}", "&#125;");
	}

	/**
	 * Get Mermaid shape syntax for vertex type
	 *
	 * @param vertexType The vertex type
	 * @return Shape delimiters (e.g., "[]" for rectangle, "()" for rounded)
	 */
	private String getShapeForVertexType(String vertexType) {
		if (vertexType == null) {
			return "[]"; // Default: rectangle
		}

		switch (vertexType) {
			case "Entry Function":
				return "([])"; // Stadium shape
			case "Called Function":
				return "[]"; // Rectangle
			case "Calling Function":
				return "[]"; // Rectangle
			default:
				return "[]"; // Default: rectangle
		}
	}

	/**
	 * Get CSS class name for vertex type
	 *
	 * @param vertexType The vertex type
	 * @return CSS class name or null
	 */
	private String getCssClassForVertexType(String vertexType) {
		if (vertexType == null) {
			return null;
		}

		switch (vertexType) {
			case "Entry Function":
				return "entryFunc";
			case "Called Function":
				return "calledFunc";
			case "Calling Function":
				return "callingFunc";
			default:
				return null;
		}
	}

	/**
	 * Get Mermaid arrow syntax for edge type
	 *
	 * @param edgeType The edge type
	 * @return Arrow syntax (e.g., "-->", "-.->")
	 */
	private String getArrowForEdgeType(String edgeType) {
		if (edgeType == null) {
			return "-->"; // Default: solid arrow
		}

		switch (edgeType) {
			case "Calls":
				return "-->"; // Solid arrow
			case "Called By":
				return "-.->"; // Dotted arrow
			default:
				return "-->"; // Default: solid arrow
		}
	}
}
