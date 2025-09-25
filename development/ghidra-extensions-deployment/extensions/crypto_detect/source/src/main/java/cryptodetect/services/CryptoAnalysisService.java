package cryptodetect.services;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

import cryptodetect.CryptoDetectPlugin;
import cryptodetect.analyzers.CryptoRoutineAnalyzer;

/**
 * Core analysis service that coordinates cryptographic routine detection.
 */
public class CryptoAnalysisService {
    
    private final CryptoDetectPlugin plugin;
    private final List<CryptoRoutineAnalyzer> analyzers;
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    
    public CryptoAnalysisService(CryptoDetectPlugin plugin) {
        this.plugin = plugin;
        this.analyzers = new ArrayList<>();
        initializeAnalyzers();
    }
    
    private void initializeAnalyzers() {
        // Initialize built-in crypto analyzers
        analyzers.add(new CryptoRoutineAnalyzer());
    }
    
    /**
     * Analyze the given program for cryptographic routines.
     * 
     * @param program The program to analyze
     */
    public void analyzeProgram(Program program) {
        if (!isRunning.compareAndSet(false, true)) {
            plugin.getConsoleService().println("[CryptoDetect] Analysis already running");
            return;
        }
        
        try {
            plugin.getConsoleService().println("[CryptoDetect] Starting comprehensive crypto analysis...");
            
            // Clear previous results
            if (plugin.getProvider() != null) {
                plugin.getProvider().clearResults();
            }
            
            // Analyze different program sections
            analyzeInstructions(program);
            analyzeDataSections(program);
            analyzeStrings(program);
            
            plugin.getConsoleService().println("[CryptoDetect] Analysis completed");
            
        } catch (Exception e) {
            plugin.getConsoleService().println("[CryptoDetect] Analysis error: " + e.getMessage());
            throw new RuntimeException("Analysis failed", e);
        } finally {
            isRunning.set(false);
        }
    }
    
    /**
     * Analyze program instructions for crypto patterns.
     */
    private void analyzeInstructions(Program program) {
        plugin.getConsoleService().println("[CryptoDetect] Analyzing instructions...");
        
        AddressSetView executableSet = program.getMemory().getExecuteSet();
        InstructionIterator instructions = program.getListing().getInstructions(executableSet, true);
        
        int instructionCount = 0;
        while (instructions.hasNext() && isRunning.get()) {
            Instruction instruction = instructions.next();
            
            // Run all analyzers on this instruction
            for (CryptoRoutineAnalyzer analyzer : analyzers) {
                analyzer.analyzeInstruction(instruction, program);
            }
            
            instructionCount++;
            
            // Progress reporting every 10000 instructions
            if (instructionCount % 10000 == 0) {
                plugin.getConsoleService().println(
                    "[CryptoDetect] Analyzed " + instructionCount + " instructions...");
            }
        }
        
        plugin.getConsoleService().println(
            "[CryptoDetect] Instruction analysis complete. Processed " + instructionCount + " instructions");
    }
    
    /**
     * Analyze data sections for crypto constants and structures.
     */
    private void analyzeDataSections(Program program) {
        plugin.getConsoleService().println("[CryptoDetect] Analyzing data sections...");
        
        Memory memory = program.getMemory();
        AddressSetView initializedSet = memory.getInitializedAddressSet();
        
        // Look for crypto constants in data sections
        for (Address addr : initializedSet.getAddresses(true)) {
            if (!isRunning.get()) break;
            
            try {
                // Read chunks of data and analyze for crypto patterns
                analyzeDataChunk(program, addr);
            } catch (MemoryAccessException e) {
                // Skip inaccessible memory regions
                continue;
            }
        }
        
        plugin.getConsoleService().println("[CryptoDetect] Data section analysis complete");
    }
    
    /**
     * Analyze a chunk of data for cryptographic patterns.
     */
    private void analyzeDataChunk(Program program, Address addr) throws MemoryAccessException {
        Memory memory = program.getMemory();
        
        // Read up to 64 bytes for pattern analysis
        int chunkSize = Math.min(64, (int) memory.getSize() - (int) addr.getOffset());
        if (chunkSize <= 0) return;
        
        byte[] data = new byte[chunkSize];
        int bytesRead = memory.getBytes(addr, data);
        
        if (bytesRead > 0) {
            // Run analyzers on data chunk
            for (CryptoRoutineAnalyzer analyzer : analyzers) {
                analyzer.analyzeData(addr, data, program);
            }
        }
    }
    
    /**
     * Analyze strings for crypto-related content.
     */
    private void analyzeStrings(Program program) {
        plugin.getConsoleService().println("[CryptoDetect] Analyzing strings...");
        
        // TODO: Implement string analysis for crypto-related strings
        // This would look for algorithm names, error messages, etc.
        
        plugin.getConsoleService().println("[CryptoDetect] String analysis complete");
    }
    
    /**
     * Check if analysis is currently running.
     */
    public boolean isRunning() {
        return isRunning.get();
    }
    
    /**
     * Stop the current analysis.
     */
    public void stopAnalysis() {
        isRunning.set(false);
        plugin.getConsoleService().println("[CryptoDetect] Analysis stop requested");
    }
    
    /**
     * Get list of registered analyzers.
     */
    public List<CryptoRoutineAnalyzer> getAnalyzers() {
        return new ArrayList<>(analyzers);
    }
}