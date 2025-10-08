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
package ghidragraph.ui;

import java.awt.BorderLayout;
import java.io.File;
import javax.swing.*;
import docking.ComponentProvider;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.GraphDisplay;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidragraph.models.CallGraphBuilder;
import ghidragraph.services.GraphExportService;
import ghidragraph.services.GraphExportService.ExportFormat;

/**
 * UI Provider for GhidraGraph plugin
 *
 * Manages the display window and user interaction for call graph generation
 */
public class GhidraGraphProvider extends ComponentProvider {

	private JPanel mainPanel;
	private Plugin plugin;
	private CallGraphBuilder graphBuilder;
	private GraphExportService exportService;

	// Configuration panel components
	private JComboBox<String> directionCombo;
	private JSpinner depthSpinner;
	private JComboBox<String> formatCombo;
	private JTextField filterField;
	private JTextArea statusArea;

	// Current state
	private Function currentFunction;
	private AttributedGraph currentGraph;

	/**
	 * Constructor
	 *
	 * @param plugin The parent plugin
	 * @param name The provider name
	 */
	public GhidraGraphProvider(Plugin plugin, String name) {
		super(plugin.getTool(), name, name);
		this.plugin = plugin;
		this.graphBuilder = new CallGraphBuilder();
		this.exportService = new GraphExportService();

		buildMainPanel();
		setVisible(false);
	}

	/**
	 * Build the main UI panel
	 */
	private void buildMainPanel() {
		mainPanel = new JPanel(new BorderLayout());

		// Configuration panel at top
		JPanel configPanel = buildConfigPanel();
		mainPanel.add(configPanel, BorderLayout.NORTH);

		// Status area in center
		statusArea = new JTextArea(10, 50);
		statusArea.setEditable(false);
		statusArea.setText("Ready to generate call graphs.\n\nUsage:\n" +
			"1. Right-click on a function\n" +
			"2. Select 'Export Call Graph...'\n" +
			"3. Configure options and click 'Generate'\n");

		JScrollPane scrollPane = new JScrollPane(statusArea);
		mainPanel.add(scrollPane, BorderLayout.CENTER);

		// Button panel at bottom
		JPanel buttonPanel = buildButtonPanel();
		mainPanel.add(buttonPanel, BorderLayout.SOUTH);
	}

	/**
	 * Build the configuration panel
	 *
	 * @return Configuration panel
	 */
	private JPanel buildConfigPanel() {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setBorder(BorderFactory.createTitledBorder("Graph Configuration"));

		// Direction selection
		JPanel dirPanel = new JPanel(new BorderLayout());
		dirPanel.add(new JLabel("Direction: "), BorderLayout.WEST);
		directionCombo = new JComboBox<>(new String[] {
			"Calling (Callers)",
			"Called (Callees)",
			"Both Directions"
		});
		directionCombo.setSelectedIndex(1); // Default to "Called"
		dirPanel.add(directionCombo, BorderLayout.CENTER);
		panel.add(dirPanel);

		// Depth spinner
		JPanel depthPanel = new JPanel(new BorderLayout());
		depthPanel.add(new JLabel("Max Depth: "), BorderLayout.WEST);
		SpinnerNumberModel spinnerModel = new SpinnerNumberModel(5, 1, 10, 1);
		depthSpinner = new JSpinner(spinnerModel);
		depthPanel.add(depthSpinner, BorderLayout.CENTER);
		panel.add(depthPanel);

		// Export format
		JPanel formatPanel = new JPanel(new BorderLayout());
		formatPanel.add(new JLabel("Export Format: "), BorderLayout.WEST);
		formatCombo = new JComboBox<>(new String[] {
			"Mermaid.js",
			"DOT/Graphviz",
			"JSON"
		});
		formatPanel.add(formatCombo, BorderLayout.CENTER);
		panel.add(formatPanel);

		// Filter field
		JPanel filterPanel = new JPanel(new BorderLayout());
		filterPanel.add(new JLabel("Filter (regex): "), BorderLayout.WEST);
		filterField = new JTextField();
		filterField.setToolTipText("Optional regex pattern to filter function names");
		filterPanel.add(filterField, BorderLayout.CENTER);
		panel.add(filterPanel);

		return panel;
	}

	/**
	 * Build the button panel
	 *
	 * @return Button panel
	 */
	private JPanel buildButtonPanel() {
		JPanel panel = new JPanel();

		JButton generateButton = new JButton("Generate Graph");
		generateButton.addActionListener(e -> generateCurrentGraph());
		panel.add(generateButton);

		JButton exportButton = new JButton("Export to File");
		exportButton.addActionListener(e -> exportCurrentGraph());
		panel.add(exportButton);

		JButton clearButton = new JButton("Clear");
		clearButton.addActionListener(e -> clearStatus());
		panel.add(clearButton);

		return panel;
	}

	/**
	 * Show graph generation dialog for a specific function
	 *
	 * @param function The function to analyze
	 */
	public void showGraphForFunction(Function function) {
		this.currentFunction = function;
		setVisible(true);
		toFront();

		appendStatus("\n=== New Graph Request ===\n");
		appendStatus("Function: " + function.getName() + "\n");
		appendStatus("Address: " + function.getEntryPoint() + "\n");
		appendStatus("Ready to generate. Click 'Generate Graph' button.\n");
	}

	/**
	 * Generate graph with current configuration
	 */
	private void generateCurrentGraph() {
		if (currentFunction == null) {
			appendStatus("[ERROR] No function selected\n");
			return;
		}

		try {
			appendStatus("\n[INFO] Generating call graph...\n");

			// Configure graph builder
			int depth = (Integer) depthSpinner.getValue();
			graphBuilder.setMaxDepth(depth);

			String direction = (String) directionCombo.getSelectedItem();
			boolean includeCalling = direction.contains("Calling") || direction.contains("Both");
			boolean includeCalled = direction.contains("Called") || direction.contains("Both");
			graphBuilder.setDirection(includeCalling, includeCalled);

			String filter = filterField.getText().trim();
			if (!filter.isEmpty()) {
				graphBuilder.setFilter(filter);
				appendStatus("[INFO] Applied filter: " + filter + "\n");
			}

			// Build the graph
			currentGraph = graphBuilder.buildGraph(currentFunction, TaskMonitor.DUMMY);

			appendStatus("[SUCCESS] Graph generated successfully!\n");
			appendStatus("  Vertices: " + currentGraph.getVertexCount() + "\n");
			appendStatus("  Edges: " + currentGraph.getEdgeCount() + "\n");

			// Display the graph
			displayGraph(currentGraph);

		} catch (Exception e) {
			appendStatus("[ERROR] Failed to generate graph: " + e.getMessage() + "\n");
			Msg.showError(this, mainPanel, "Graph Generation Error",
				"Failed to generate call graph", e);
		}
	}

	/**
	 * Display graph using Ghidra's native graph viewer
	 *
	 * @param graph The graph to display
	 */
	private void displayGraph(AttributedGraph graph) {
		try {
			GraphDisplayBroker broker = plugin.getTool().getService(GraphDisplayBroker.class);
			if (broker == null) {
				appendStatus("[WARNING] GraphDisplayBroker not available\n");
				appendStatus("[INFO] Graph created but cannot be displayed\n");
				return;
			}

			GraphDisplay display = broker.getDefaultGraphDisplay(false, TaskMonitor.DUMMY);
			display.setGraph(graph, graph.getName(), false, TaskMonitor.DUMMY);

			appendStatus("[SUCCESS] Graph displayed in viewer\n");

		} catch (Exception e) {
			appendStatus("[ERROR] Failed to display graph: " + e.getMessage() + "\n");
		}
	}

	/**
	 * Export current graph to file
	 */
	private void exportCurrentGraph() {
		if (currentGraph == null) {
			appendStatus("[ERROR] No graph to export. Generate a graph first.\n");
			return;
		}

		try {
			// Determine export format
			String formatStr = (String) formatCombo.getSelectedItem();
			ExportFormat format = ExportFormat.MERMAID; // Default

			if (formatStr.contains("DOT")) {
				format = ExportFormat.DOT;
			} else if (formatStr.contains("JSON")) {
				format = ExportFormat.JSON;
			}

			// Show file chooser
			JFileChooser fileChooser = new JFileChooser();
			fileChooser.setDialogTitle("Export Call Graph");
			fileChooser.setSelectedFile(new File(
				currentFunction.getName() + "_callgraph." + format.getExtension()
			));

			int result = fileChooser.showSaveDialog(mainPanel);
			if (result != JFileChooser.APPROVE_OPTION) {
				appendStatus("[INFO] Export cancelled by user\n");
				return;
			}

			File outputFile = fileChooser.getSelectedFile();

			// Export the graph
			appendStatus("\n[INFO] Exporting to " + format.getDisplayName() + "...\n");
			exportService.exportGraph(currentGraph, outputFile, format);

			appendStatus("[SUCCESS] Exported to: " + outputFile.getAbsolutePath() + "\n");
			appendStatus("  Format: " + format.getDisplayName() + "\n");
			appendStatus("  Size: " + (outputFile.length() / 1024) + " KB\n");

		} catch (Exception e) {
			appendStatus("[ERROR] Export failed: " + e.getMessage() + "\n");
			Msg.showError(this, mainPanel, "Export Error",
				"Failed to export graph", e);
		}
	}

	/**
	 * Clear the status area
	 */
	private void clearStatus() {
		statusArea.setText("");
	}

	/**
	 * Append text to status area
	 *
	 * @param text Text to append
	 */
	private void appendStatus(String text) {
		statusArea.append(text);
		statusArea.setCaretPosition(statusArea.getDocument().getLength());
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	/**
	 * Dispose of resources
	 */
	public void dispose() {
		// Cleanup if needed
	}
}
