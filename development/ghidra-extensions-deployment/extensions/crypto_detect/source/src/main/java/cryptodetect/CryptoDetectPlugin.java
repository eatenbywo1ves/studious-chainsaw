package cryptodetect;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

import cryptodetect.services.CryptoAnalysisService;
import cryptodetect.services.PatternMatchingService;
import cryptodetect.ui.CryptoDetectProvider;

/**
 * Main plugin class for CryptoDetect extension.
 * Provides cryptographic routine detection and analysis capabilities for Ghidra.
 */
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Cryptographic routine detection and analysis",
    description = "Advanced detection and analysis of cryptographic algorithms in binary code",
    servicesRequired = {
        ProgramManager.class,
        ConsoleService.class,
        GoToService.class
    },
    eventsConsumed = {
        ProgramActivatedPluginEvent.class,
        ProgramClosedPluginEvent.class
    }
)
public class CryptoDetectPlugin extends ProgramPlugin {
    
    // UI Component
    private CryptoDetectProvider provider;
    
    // Services
    private ConsoleService consoleService;
    private GoToService goToService;
    private ProgramManager programManager;
    private CryptoAnalysisService analysisService;
    private PatternMatchingService patternService;
    
    // Background processing
    private ExecutorService executorService;
    
    // State
    private Program currentProgram;
    private boolean isAnalysisRunning = false;
    
    public CryptoDetectPlugin(PluginTool tool) {
        super(tool);
        
        // Initialize executor service for background tasks
        executorService = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "CryptoDetect-" + System.currentTimeMillis());
            t.setDaemon(true);
            return t;
        });
    }
    
    @Override
    public void init() {
        super.init();
        
        // Initialize services
        consoleService = tool.getService(ConsoleService.class);
        goToService = tool.getService(GoToService.class);
        programManager = tool.getService(ProgramManager.class);
        
        // Initialize internal services
        analysisService = new CryptoAnalysisService(this);
        patternService = new PatternMatchingService();
        
        // Initialize UI
        provider = new CryptoDetectProvider(this, getName());
        
        consoleService.println("[CryptoDetect] Plugin initialized successfully");
    }
    
    @Override
    protected void dispose() {
        if (provider != null) {
            provider.dispose();
            provider = null;
        }
        
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
        
        super.dispose();
    }
    
    @Override
    protected void programActivated(Program activatedProgram) {
        this.currentProgram = activatedProgram;
        
        if (provider != null) {
            provider.setProgram(activatedProgram);
        }
        
        consoleService.println("[CryptoDetect] Program activated: " + activatedProgram.getName());
    }
    
    @Override
    protected void programDeactivated(Program deactivatedProgram) {
        // Clean up any program-specific state
        if (currentProgram == deactivatedProgram) {
            currentProgram = null;
        }
        
        consoleService.println("[CryptoDetect] Program deactivated: " + deactivatedProgram.getName());
    }
    
    @Override
    protected void programClosed(Program closedProgram) {
        if (currentProgram == closedProgram) {
            currentProgram = null;
            if (provider != null) {
                provider.clearResults();
            }
        }
        
        consoleService.println("[CryptoDetect] Program closed: " + closedProgram.getName());
    }
    
    /**
     * Start cryptographic analysis on the current program.
     * Analysis runs in background thread to avoid blocking the UI.
     */
    public CompletableFuture<Void> startAnalysis() {
        if (currentProgram == null) {
            consoleService.println("[CryptoDetect] No program available for analysis");
            return CompletableFuture.completedFuture(null);
        }
        
        if (isAnalysisRunning) {
            consoleService.println("[CryptoDetect] Analysis already in progress");
            return CompletableFuture.completedFuture(null);
        }
        
        isAnalysisRunning = true;
        consoleService.println("[CryptoDetect] Starting analysis on: " + currentProgram.getName());
        
        return CompletableFuture.runAsync(() -> {
            try {
                analysisService.analyzeProgram(currentProgram);
            } catch (Exception e) {
                consoleService.println("[CryptoDetect] Analysis failed: " + e.getMessage());
                e.printStackTrace();
            } finally {
                isAnalysisRunning = false;
            }
        }, executorService);
    }
    
    /**
     * Stop any running analysis.
     */
    public void stopAnalysis() {
        if (isAnalysisRunning) {
            // TODO: Implement proper cancellation mechanism
            isAnalysisRunning = false;
            consoleService.println("[CryptoDetect] Analysis stopped");
        }
    }
    
    // Getters for services and state
    public ConsoleService getConsoleService() {
        return consoleService;
    }
    
    public GoToService getGoToService() {
        return goToService;
    }
    
    public ProgramManager getProgramManager() {
        return programManager;
    }
    
    public CryptoAnalysisService getAnalysisService() {
        return analysisService;
    }
    
    public PatternMatchingService getPatternService() {
        return patternService;
    }
    
    public Program getCurrentProgram() {
        return currentProgram;
    }
    
    public boolean isAnalysisRunning() {
        return isAnalysisRunning;
    }
    
    public CryptoDetectProvider getProvider() {
        return provider;
    }
}