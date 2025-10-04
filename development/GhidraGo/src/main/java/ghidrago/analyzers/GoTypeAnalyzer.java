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
package ghidrago.analyzers;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraState;
import generic.jar.ResourceFile;

import java.io.File;
import java.util.List;

/**
 * GoTypeAnalyzer - Automatic Go function and type recovery analyzer
 *
 * This analyzer automatically detects Go binaries and invokes the Python-based
 * type extraction scripts to recover:
 * - Function names from PCLNTAB
 * - Struct types with fields
 * - Interface types with methods
 * - Nested type relationships
 *
 * @author Catalytic Computing
 * @version 1.1 Phase 3
 */
public class GoTypeAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Go Type Analyzer";
	private static final String DESCRIPTION =
		"Automatically recovers Go functions and types (structs, interfaces) from Go binaries";

	// Analyzer options
	private static final String OPTION_EXTRACT_TYPES = "Extract Type Information";
	private static final String OPTION_EXTRACT_TYPES_DESC =
		"Extract detailed type information (structs, interfaces) in addition to functions";

	private static final String OPTION_MAX_TYPES = "Maximum Types to Process";
	private static final String OPTION_MAX_TYPES_DESC =
		"Maximum number of types to extract (prevents excessive processing time)";

	private static final String OPTION_ENABLE_PHASE2 = "Enable Phase 2 Enhancements";
	private static final String OPTION_ENABLE_PHASE2_DESC =
		"Enable Phase 2 struct field and interface method parsing";

	// Default option values
	private boolean extractTypes = true;
	private int maxTypes = 1000;
	private boolean enablePhase2 = true;

	/**
	 * Constructor
	 */
	public GoTypeAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);

		// Set analyzer priority (run after basic analysis)
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.after());

		// This analyzer should run on Go binaries
		setDefaultEnablement(true);

		// Supported by this analyzer
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Check if this is a Go binary by looking for common Go indicators
		return isGoBinary(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		monitor.setMessage("Go Type Analyzer: Detecting Go binary...");

		// Verify this is a Go binary
		if (!isGoBinary(program)) {
			log.appendMsg("Not a Go binary - skipping Go Type Analyzer");
			return false;
		}

		log.appendMsg("Detected Go binary - starting type extraction");
		monitor.setMessage("Go Type Analyzer: Running type extraction...");

		try {
			// Invoke the Python script
			boolean success = runPythonScript(program, monitor, log);

			if (success) {
				log.appendMsg("Go Type Analyzer completed successfully");
				monitor.setMessage("Go Type Analyzer: Complete");
				return true;
			} else {
				log.appendMsg("Go Type Analyzer encountered errors");
				return false;
			}

		} catch (Exception e) {
			log.appendException(e);
			monitor.setMessage("Go Type Analyzer: Failed");
			return false;
		}
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_EXTRACT_TYPES, extractTypes, null,
			OPTION_EXTRACT_TYPES_DESC);

		options.registerOption(OPTION_MAX_TYPES, maxTypes, null,
			OPTION_MAX_TYPES_DESC);

		options.registerOption(OPTION_ENABLE_PHASE2, enablePhase2, null,
			OPTION_ENABLE_PHASE2_DESC);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		extractTypes = options.getBoolean(OPTION_EXTRACT_TYPES, extractTypes);
		maxTypes = options.getInt(OPTION_MAX_TYPES, maxTypes);
		enablePhase2 = options.getBoolean(OPTION_ENABLE_PHASE2, enablePhase2);
	}

	/**
	 * Check if the program is a Go binary
	 *
	 * @param program The program to check
	 * @return true if Go binary detected
	 */
	private boolean isGoBinary(Program program) {
		// Method 1: Check for .gopclntab section
		if (program.getMemory().getBlock(".gopclntab") != null) {
			return true;
		}

		// Method 2: Check for .go.buildinfo section (Go 1.18+)
		if (program.getMemory().getBlock(".go.buildinfo") != null) {
			return true;
		}

		// Method 3: Check for common Go runtime symbols
		if (program.getSymbolTable().getExternalSymbol("runtime.main") != null ||
		    program.getSymbolTable().getExternalSymbol("runtime.goexit") != null) {
			return true;
		}

		// Method 4: Check for Go type sections
		if (program.getMemory().getBlock(".noptrdata") != null &&
		    program.getMemory().getBlock(".data") != null) {
			// Likely a Go binary (has common Go sections)
			return true;
		}

		return false;
	}

	/**
	 * Run the Python type extraction script
	 *
	 * @param program The program being analyzed
	 * @param monitor Task monitor for progress
	 * @param log Message log for output
	 * @return true if successful
	 */
	private boolean runPythonScript(Program program, TaskMonitor monitor, MessageLog log) {
		try {
			// Get the GhidraGo Python script path
			File scriptFile = findPythonScript("RecoverGoFunctionsAndTypes.py");

			if (scriptFile == null || !scriptFile.exists()) {
				log.appendMsg("Error: RecoverGoFunctionsAndTypes.py not found");
				log.appendMsg("Please ensure GhidraGo scripts are installed");
				return false;
			}

			log.appendMsg("Running: " + scriptFile.getName());

			// Create a script instance using Ghidra 11.4.2 API
			ResourceFile scriptResource = GhidraScriptUtil.findScriptByName(scriptFile.getName());

			if (scriptResource != null) {
				GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptResource);
				if (provider == null) {
					log.appendMsg("Error: Could not get script provider for: " + scriptFile.getName());
					return false;
				}

				GhidraScript script = provider.getScriptInstance(scriptResource, null);
				if (script == null) {
					log.appendMsg("Error: Could not create script instance: " + scriptFile.getName());
					return false;
				}

				// Create GhidraState and set script context
				GhidraState state = new GhidraState(null, null, program, null, null, null);
				script.set(state, monitor, null);

				// Run the script using runScript method
				script.runScript(scriptFile.getName(), new String[0]);

				return true;
			} else {
				log.appendMsg("Error: Could not find script: " + scriptFile.getName());
				return false;
			}

		} catch (Exception e) {
			log.appendMsg("Error running Python script: " + e.getMessage());
			return false;
		}
	}

	/**
	 * Find the Python script in Ghidra's script directories
	 *
	 * @param scriptName Name of the script to find
	 * @return File object for the script, or null if not found
	 */
	private File findPythonScript(String scriptName) {
		// Get all script directories (Ghidra 11.4.2 returns List)
		List<ResourceFile> scriptDirs = GhidraScriptUtil.getScriptSourceDirectories();

		// Search for the script
		for (ResourceFile dir : scriptDirs) {
			File scriptFile = new File(dir.getFile(false), scriptName);
			if (scriptFile.exists()) {
				return scriptFile;
			}
		}

		return null;
	}
}
