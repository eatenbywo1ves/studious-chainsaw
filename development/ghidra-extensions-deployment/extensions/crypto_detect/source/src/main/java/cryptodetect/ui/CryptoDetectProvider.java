package cryptodetect.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToolBar;
import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import resources.Icons;

import cryptodetect.CryptoDetectPlugin;
import cryptodetect.analyzers.CryptoRoutineAnalyzer.CryptoDetection;

/**
 * Main UI provider for the CryptoDetect extension.
 * Provides analysis controls and displays results in a docking window.
 */
public class CryptoDetectProvider extends ComponentProvider {
    
    private final CryptoDetectPlugin plugin;
    private final JPanel mainPanel;
    private final JToolBar toolBar;
    private final CryptoResultsPanel resultsPanel;
    
    private JButton analyzeButton;
    private JButton stopButton;
    private JButton clearButton;
    
    private Program currentProgram;
    
    public CryptoDetectProvider(CryptoDetectPlugin plugin, String name) {
        super(plugin.getTool(), name, plugin.getName());
        this.plugin = plugin;
        
        // Initialize UI components
        this.mainPanel = new JPanel(new BorderLayout());
        this.toolBar = new JToolBar();
        this.resultsPanel = new CryptoResultsPanel(plugin);
        
        buildPanel();
        createActions();
        
        // Set help location
        setHelpLocation(new HelpLocation("CryptoDetect", "CryptoDetect"));
    }
    
    @Override
    public JPanel getComponent() {
        return mainPanel;
    }
    
    /**
     * Build the main UI panel.
     */
    private void buildPanel() {
        // Configure toolbar
        toolBar.setFloatable(false);
        createToolbarButtons();
        
        // Add components to main panel
        mainPanel.add(toolBar, BorderLayout.NORTH);
        mainPanel.add(new JScrollPane(resultsPanel), BorderLayout.CENTER);
        
        // Set initial state
        updateButtonStates(false);
    }
    
    /**
     * Create toolbar buttons.
     */
    private void createToolbarButtons() {
        // Analyze button
        analyzeButton = new JButton("Analyze", Icons.REFRESH_ICON);
        analyzeButton.setToolTipText("Start cryptographic analysis");
        analyzeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                startAnalysis();
            }
        });
        toolBar.add(analyzeButton);
        
        // Stop button
        stopButton = new JButton("Stop", Icons.STOP_ICON);
        stopButton.setToolTipText("Stop analysis");
        stopButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                stopAnalysis();
            }
        });
        toolBar.add(stopButton);
        
        toolBar.addSeparator();
        
        // Clear button
        clearButton = new JButton("Clear", Icons.CLEAR_ICON);
        clearButton.setToolTipText("Clear results");
        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                clearResults();
            }
        });
        toolBar.add(clearButton);
    }
    
    /**
     * Create docking actions.
     */
    private void createActions() {
        // Analyze action
        DockingAction analyzeAction = new DockingAction("Analyze", plugin.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                startAnalysis();
            }
        };
        analyzeAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, "Analysis"));
        analyzeAction.setDescription("Start cryptographic analysis");
        analyzeAction.setHelpLocation(new HelpLocation("CryptoDetect", "Analyze"));
        plugin.getTool().addAction(analyzeAction);
        
        // Clear action
        DockingAction clearAction = new DockingAction("Clear Results", plugin.getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                clearResults();
            }
        };
        clearAction.setToolBarData(new ToolBarData(Icons.CLEAR_ICON, "Clear"));
        clearAction.setDescription("Clear analysis results");
        clearAction.setHelpLocation(new HelpLocation("CryptoDetect", "Clear"));
        plugin.getTool().addAction(clearAction);
    }
    
    /**
     * Start cryptographic analysis.
     */
    private void startAnalysis() {
        if (currentProgram == null) {
            plugin.getConsoleService().println("[CryptoDetect] No program loaded");
            return;
        }
        
        updateButtonStates(true);
        resultsPanel.setStatusMessage("Analysis in progress...");
        
        // Start analysis in background
        plugin.startAnalysis().thenRun(() -> {
            SwingUtilities.invokeLater(() -> {
                updateButtonStates(false);
                refreshResults();
                resultsPanel.setStatusMessage("Analysis completed");
            });
        }).exceptionally(throwable -> {
            SwingUtilities.invokeLater(() -> {
                updateButtonStates(false);
                resultsPanel.setStatusMessage("Analysis failed: " + throwable.getMessage());
            });
            return null;
        });
    }
    
    /**
     * Stop running analysis.
     */
    private void stopAnalysis() {
        plugin.stopAnalysis();
        updateButtonStates(false);
        resultsPanel.setStatusMessage("Analysis stopped");
    }
    
    /**
     * Clear analysis results.
     */
    public void clearResults() {
        resultsPanel.clearResults();
        resultsPanel.setStatusMessage("Results cleared");
    }
    
    /**
     * Refresh results display with latest analysis data.
     */
    private void refreshResults() {
        if (plugin.getAnalysisService() != null) {
            List<CryptoDetection> detections = plugin.getAnalysisService()
                .getAnalyzers().get(0).getDetections();
            resultsPanel.setResults(detections);
        }
    }
    
    /**
     * Update button states based on analysis status.
     */
    private void updateButtonStates(boolean analysisRunning) {
        if (analyzeButton != null) {
            analyzeButton.setEnabled(!analysisRunning && currentProgram != null);
        }
        if (stopButton != null) {
            stopButton.setEnabled(analysisRunning);
        }
        if (clearButton != null) {
            clearButton.setEnabled(!analysisRunning);
        }
    }
    
    /**
     * Set the current program being analyzed.
     */
    public void setProgram(Program program) {
        this.currentProgram = program;
        updateButtonStates(plugin.isAnalysisRunning());
        
        if (program != null) {
            resultsPanel.setStatusMessage("Program loaded: " + program.getName());
        } else {
            resultsPanel.setStatusMessage("No program loaded");
            clearResults();
        }
    }
    
    /**
     * Get the current program.
     */
    public Program getProgram() {
        return currentProgram;
    }
    
    /**
     * Get the results panel.
     */
    public CryptoResultsPanel getResultsPanel() {
        return resultsPanel;
    }
    
    @Override
    public void dispose() {
        if (resultsPanel != null) {
            resultsPanel.dispose();
        }
        super.dispose();
    }
}