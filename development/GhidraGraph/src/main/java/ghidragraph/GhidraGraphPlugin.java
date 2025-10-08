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
package ghidragraph;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidragraph.ui.GhidraGraphProvider;

/**
 * GhidraGraph Plugin - Advanced call graph visualization and export
 *
 * This plugin provides comprehensive call graph generation with support for:
 * - Interactive graph visualization
 * - Multiple export formats (Mermaid, DOT, JSON)
 * - Bidirectional analysis (calling/called functions)
 * - Configurable depth and filtering
 */
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.GRAPH,
	shortDescription = "Call Graph Visualization",
	description = "Advanced call graph visualization and export plugin with Mermaid.js support",
	servicesRequired = { GraphDisplayBroker.class }
)
public class GhidraGraphPlugin extends ProgramPlugin {

	private GhidraGraphProvider provider;
	private DockingAction exportCallGraphAction;

	/**
	 * Plugin constructor
	 *
	 * @param tool The plugin tool that this plugin is added to
	 */
	public GhidraGraphPlugin(PluginTool tool) {
		super(tool);

		String pluginName = getName();
		provider = new GhidraGraphProvider(this, pluginName);

		setupActions();
	}

	@Override
	public void init() {
		super.init();
	}

	/**
	 * Setup the plugin actions (context menu items, etc.)
	 */
	private void setupActions() {
		// Context menu action for exporting call graphs
		exportCallGraphAction = new DockingAction("Export Call Graph", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Function function = getCurrentFunction();
				if (function != null) {
					provider.showGraphForFunction(function);
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return getCurrentFunction() != null;
			}
		};

		exportCallGraphAction.setPopupMenuData(
			new MenuData(
				new String[] { "Export Call Graph..." },
				null,
				"graph"
			)
		);

		exportCallGraphAction.setEnabled(true);
		exportCallGraphAction.setHelpLocation(
			new HelpLocation("GhidraGraph", "ExportCallGraph")
		);

		tool.addAction(exportCallGraphAction);
	}

	/**
	 * Get the function at the current cursor location
	 *
	 * @return The function at current location, or null if not on a function
	 */
	private Function getCurrentFunction() {
		if (currentProgram == null) {
			return null;
		}

		ProgramLocation location = currentLocation;
		if (location == null) {
			return null;
		}

		return currentProgram.getFunctionManager()
			.getFunctionContaining(location.getAddress());
	}

	@Override
	protected void dispose() {
		if (provider != null) {
			provider.dispose();
		}
		super.dispose();
	}
}
