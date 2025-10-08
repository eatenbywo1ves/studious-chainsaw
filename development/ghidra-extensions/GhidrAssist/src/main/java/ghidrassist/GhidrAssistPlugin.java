package ghidrassist;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.app.decompiler.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import docking.ComponentProvider;
import docking.WindowPosition;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "GhidrAssist",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "AI-powered analysis assistant",
    description = "Provides AI-powered function explanation, variable renaming, and vulnerability detection via MCP integration"
)
public class GhidrAssistPlugin extends ProgramPlugin {
    private MCPClient mcpClient;
    private ExplanationPanel explanationPanel;
    private ComponentProvider explanationProvider;
    private DecompInterface decompiler;
    private Properties config;

    public GhidrAssistPlugin(PluginTool tool) {
        super(tool);

        // Load configuration
        loadConfiguration();

        // Initialize MCP client
        String endpoint = config.getProperty("mcp.endpoint", "http://localhost:3000");
        int timeout = Integer.parseInt(config.getProperty("mcp.timeout", "30"));
        mcpClient = new MCPClient(endpoint, timeout);

        // Initialize decompiler
        decompiler = new DecompInterface();
    }

    @Override
    protected void init() {
        super.init();

        // Create explanation panel
        explanationPanel = new ExplanationPanel();

        // Create component provider for dockable window
        explanationProvider = new ComponentProvider(getTool(), "GhidrAssist Explanations", getName()) {
            @Override
            public JComponent getComponent() {
                return explanationPanel;
            }
        };
        explanationProvider.setVisible(true);
        getTool().addComponentProvider(explanationProvider, false);

        // Register actions
        getTool().addAction(new FunctionExplanationAction(this));
        getTool().addAction(new VariableRenameAction(this));
        getTool().addAction(new VulnerabilityDetectionAction(this));
    }

    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);

        // Initialize decompiler with current program
        if (program != null) {
            decompiler.openProgram(program);
        }
    }

    @Override
    protected void programDeactivated(Program program) {
        super.programDeactivated(program);

        // Clean up decompiler
        if (decompiler != null) {
            decompiler.dispose();
        }
    }

    @Override
    protected void dispose() {
        // Clean up resources
        if (decompiler != null) {
            decompiler.dispose();
        }

        if (explanationProvider != null) {
            getTool().removeComponentProvider(explanationProvider);
        }

        super.dispose();
    }

    /**
     * Main method called when user requests function explanation
     */
    public void explainFunction(Function function) {
        // Show progress
        explanationPanel.showProgress("Analyzing function " + function.getName() + "...");

        // Execute in background thread to avoid blocking UI
        new Thread(() -> {
            try {
                // Get decompiled code
                String functionCode = getFunctionDecompilation(function);

                // Call MCP AI for explanation
                String explanation = mcpClient.explainFunction(
                    functionCode,
                    function.getName()
                );

                // Display result
                SwingUtilities.invokeLater(() -> {
                    explanationPanel.showExplanation(explanation);
                });

            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    explanationPanel.showError(e.getMessage());
                    logError("Failed to explain function", e);
                });
            }
        }).start();
    }

    /**
     * Get decompiled C code for a function
     */
    public String getFunctionDecompilation(Function function) throws Exception {
        if (currentProgram == null) {
            throw new Exception("No program loaded");
        }

        // Ensure decompiler is initialized
        decompiler.openProgram(currentProgram);

        // Decompile function
        DecompileResults results = decompiler.decompileFunction(
            function,
            30,  // 30 second timeout
            TaskMonitor.DUMMY
        );

        if (!results.decompileCompleted()) {
            throw new Exception("Decompilation failed: " + results.getErrorMessage());
        }

        // Get C code
        DecompiledFunction decompiledFunc = results.getDecompiledFunction();
        if (decompiledFunc == null) {
            throw new Exception("Could not decompile function");
        }

        return decompiledFunc.getC();
    }

    /**
     * Get MCP client instance
     */
    public MCPClient getMCPClient() {
        return mcpClient;
    }

    /**
     * Show progress message in panel
     */
    public void showProgress(String message) {
        SwingUtilities.invokeLater(() -> {
            explanationPanel.showProgress(message);
        });
    }

    /**
     * Show error in panel
     */
    public void showError(String error) {
        SwingUtilities.invokeLater(() -> {
            explanationPanel.showError(error);
        });
    }

    /**
     * Show success message
     */
    public void showSuccess(String message) {
        ConsoleService console = getTool().getService(ConsoleService.class);
        if (console != null) {
            console.addMessage(getName(), message);
        }
    }

    /**
     * Load configuration from properties file
     */
    private void loadConfiguration() {
        config = new Properties();

        // Default configuration
        config.setProperty("mcp.endpoint", "http://localhost:3000");
        config.setProperty("mcp.timeout", "30");
        config.setProperty("ai.model", "codellama");
        config.setProperty("ai.temperature", "0.3");
        config.setProperty("feature.explanation.enabled", "true");
        config.setProperty("feature.renaming.enabled", "true");
        config.setProperty("feature.vulnerability_scan.enabled", "true");

        // Try to load user configuration
        String userHome = System.getProperty("user.home");
        File configFile = new File(userHome, ".ghidra/.ghidrassist/config.properties");

        if (configFile.exists()) {
            try (FileInputStream fis = new FileInputStream(configFile)) {
                config.load(fis);
            } catch (IOException e) {
                logError("Failed to load configuration file", e);
            }
        }
    }

    /**
     * Log error to console
     */
    private void logError(String message, Exception e) {
        ConsoleService console = getTool().getService(ConsoleService.class);
        if (console != null) {
            console.addErrorMessage(getName(), message + ": " + e.getMessage());
        }
    }
}
