package cryptodetect.analyzers;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;

import cryptodetect.services.PatternMatchingService;

/**
 * Main analyzer for detecting cryptographic routines in binary code.
 * Uses pattern matching, entropy analysis, and heuristic detection methods.
 */
public class CryptoRoutineAnalyzer {
    
    private final PatternMatchingService patternService;
    private final List<CryptoDetection> detections;
    
    // Instruction patterns that commonly appear in crypto implementations
    private static final String[] CRYPTO_INSTRUCTION_PATTERNS = {
        "XOR", "ROL", "ROR", "SHL", "SHR", "AND", "OR", "NOT"
    };
    
    // Common crypto constants (in various byte orders)
    private static final Map<String, Long[]> CRYPTO_CONSTANTS = Map.of(
        "SHA1_H0", new Long[]{0x67452301L, 0x01234567L},
        "SHA1_H1", new Long[]{0xEFCDAB89L, 0x89ABCDEFL},
        "SHA1_H2", new Long[]{0x98BADCFEL, 0xFEDCBA98L},
        "SHA1_H3", new Long[]{0x10325476L, 0x76543210L},
        "SHA1_H4", new Long[]{0xC3D2E1F0L, 0xF0E1D2C3L},
        "MD5_A", new Long[]{0x67452301L, 0x01234567L},
        "MD5_B", new Long[]{0xEFCDAB89L, 0x89ABCDEFL},
        "MD5_C", new Long[]{0x98BADCFEL, 0xFEDCBA98L},
        "MD5_D", new Long[]{0x10325476L, 0x76543210L}
    );
    
    public CryptoRoutineAnalyzer() {
        this.patternService = new PatternMatchingService();
        this.detections = new ArrayList<>();
    }
    
    /**
     * Analyze an instruction for cryptographic patterns.
     */
    public void analyzeInstruction(Instruction instruction, Program program) {
        String mnemonic = instruction.getMnemonicString();
        Address address = instruction.getAddress();
        
        // Check for crypto-related instruction patterns
        if (isCryptoInstruction(mnemonic)) {
            analyzeInstructionContext(instruction, program);
        }
        
        // Check for immediate values that match crypto constants
        analyzeOperands(instruction, program);
    }
    
    /**
     * Analyze data for cryptographic patterns.
     */
    public void analyzeData(Address address, byte[] data, Program program) {
        // Pattern matching against known crypto signatures
        PatternMatchingService.MatchResult match = patternService.matchBytePattern(data);
        if (match != null) {
            addDetection(new CryptoDetection(
                address.add(match.getOffset()),
                match.getPattern().getName(),
                match.getPattern().getDescription(),
                match.getPattern().getConfidence(),
                CryptoDetection.DetectionType.PATTERN_MATCH
            ));
        }
        
        // Entropy analysis for potential encrypted data or keys
        analyzeEntropy(address, data, program);
        
        // Look for S-box tables and other crypto structures
        analyzeStructures(address, data, program);
    }
    
    /**
     * Check if instruction mnemonic suggests cryptographic operations.
     */
    private boolean isCryptoInstruction(String mnemonic) {
        for (String pattern : CRYPTO_INSTRUCTION_PATTERNS) {
            if (mnemonic.contains(pattern)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Analyze instruction context for crypto patterns.
     */
    private void analyzeInstructionContext(Instruction instruction, Program program) {
        Address address = instruction.getAddress();
        
        // Check if instruction is part of a loop (common in crypto)
        if (isInLoop(instruction, program)) {
            // Analyze surrounding instructions for crypto patterns
            analyzeInstructionSequence(instruction, program);
        }
    }
    
    /**
     * Analyze instruction operands for crypto constants.
     */
    private void analyzeOperands(Instruction instruction, Program program) {
        int numOperands = instruction.getNumOperands();
        
        for (int i = 0; i < numOperands; i++) {
            Object[] operandObjects = instruction.getOpObjects(i);
            
            for (Object operand : operandObjects) {
                if (operand instanceof Scalar) {
                    Scalar scalar = (Scalar) operand;
                    checkCryptoConstant(instruction.getAddress(), scalar.getUnsignedValue(), program);
                }
            }
        }
    }
    
    /**
     * Check if a value matches known cryptographic constants.
     */
    private void checkCryptoConstant(Address address, long value, Program program) {
        for (Map.Entry<String, Long[]> entry : CRYPTO_CONSTANTS.entrySet()) {
            String constantName = entry.getKey();
            Long[] variants = entry.getValue();
            
            for (Long variant : variants) {
                if (value == variant) {
                    addDetection(new CryptoDetection(
                        address,
                        constantName,
                        "Cryptographic constant: " + constantName,
                        0.8,
                        CryptoDetection.DetectionType.CONSTANT_MATCH
                    ));
                    return;
                }
            }
        }
    }
    
    /**
     * Perform entropy analysis on data to detect potential crypto material.
     */
    private void analyzeEntropy(Address address, byte[] data, Program program) {
        if (data.length < 16) return; // Need sufficient data for meaningful entropy analysis
        
        double entropy = calculateEntropy(data);
        
        // High entropy suggests encrypted data or random keys
        if (entropy > 7.5) { // Threshold for high entropy
            addDetection(new CryptoDetection(
                address,
                "HIGH_ENTROPY_DATA",
                String.format("High entropy data (%.2f bits)", entropy),
                Math.min(0.9, entropy / 8.0),
                CryptoDetection.DetectionType.ENTROPY_ANALYSIS
            ));
        }
    }
    
    /**
     * Calculate Shannon entropy of byte array.
     */
    private double calculateEntropy(byte[] data) {
        int[] frequency = new int[256];
        
        // Count frequency of each byte value
        for (byte b : data) {
            frequency[b & 0xFF]++;
        }
        
        // Calculate entropy
        double entropy = 0.0;
        double length = data.length;
        
        for (int count : frequency) {
            if (count > 0) {
                double probability = count / length;
                entropy -= probability * (Math.log(probability) / Math.log(2));
            }
        }
        
        return entropy;
    }
    
    /**
     * Analyze data structures for crypto tables (S-boxes, etc.).
     */
    private void analyzeStructures(Address address, byte[] data, Program program) {
        // Check for common S-box sizes and patterns
        if (data.length >= 256) {
            analyzeForSBox(address, data, 256, "Potential 256-byte S-box");
        }
        if (data.length >= 16) {
            analyzeForSBox(address, data, 16, "Potential 16-byte S-box");
        }
        
        // Check for key schedules and round constants
        analyzeForKeySchedule(address, data, program);
    }
    
    /**
     * Check if data looks like an S-box substitution table.
     */
    private void analyzeForSBox(Address address, byte[] data, int expectedSize, String description) {
        if (data.length < expectedSize) return;
        
        byte[] sboxCandidate = new byte[expectedSize];
        System.arraycopy(data, 0, sboxCandidate, 0, expectedSize);
        
        // S-boxes typically contain each value exactly once (permutation)
        if (isPotentialSBox(sboxCandidate)) {
            addDetection(new CryptoDetection(
                address,
                "SBOX_TABLE",
                description,
                0.7,
                CryptoDetection.DetectionType.STRUCTURE_ANALYSIS
            ));
        }
    }
    
    /**
     * Check if byte array looks like an S-box (contains unique values).
     */
    private boolean isPotentialSBox(byte[] data) {
        boolean[] seen = new boolean[256];
        int uniqueCount = 0;
        
        for (byte b : data) {
            int value = b & 0xFF;
            if (!seen[value]) {
                seen[value] = true;
                uniqueCount++;
            }
        }
        
        // S-box should have high uniqueness ratio
        double uniquenessRatio = (double) uniqueCount / data.length;
        return uniquenessRatio > 0.8;
    }
    
    /**
     * Analyze for key schedule patterns.
     */
    private void analyzeForKeySchedule(Address address, byte[] data, Program program) {
        // Look for patterns that suggest key expansion algorithms
        // This is a simplified heuristic
        
        if (data.length >= 32) {
            // Check for repeating patterns that might indicate key expansion
            int patternLength = findRepeatingPattern(data);
            if (patternLength > 0 && patternLength <= 16) {
                addDetection(new CryptoDetection(
                    address,
                    "KEY_SCHEDULE",
                    "Potential key schedule or expanded key",
                    0.6,
                    CryptoDetection.DetectionType.STRUCTURE_ANALYSIS
                ));
            }
        }
    }
    
    /**
     * Find repeating patterns in data.
     */
    private int findRepeatingPattern(byte[] data) {
        for (int patternLen = 4; patternLen <= Math.min(16, data.length / 2); patternLen++) {
            boolean isRepeating = true;
            
            for (int i = patternLen; i < data.length - patternLen; i++) {
                if (data[i] != data[i % patternLen]) {
                    isRepeating = false;
                    break;
                }
            }
            
            if (isRepeating) {
                return patternLen;
            }
        }
        return 0;
    }
    
    /**
     * Check if instruction is likely within a loop.
     */
    private boolean isInLoop(Instruction instruction, Program program) {
        // Simple heuristic: check if there are backward jumps nearby
        try {
            Memory memory = program.getMemory();
            Address current = instruction.getAddress();
            
            // Check a small window around the instruction
            for (int offset = -20; offset <= 20; offset += 4) {
                Address checkAddr = current.add(offset);
                if (memory.contains(checkAddr)) {
                    Instruction checkInstr = program.getListing().getInstructionAt(checkAddr);
                    if (checkInstr != null && isJumpInstruction(checkInstr)) {
                        // Check if it's a backward jump (potential loop)
                        Address[] flows = checkInstr.getFlows();
                        for (Address target : flows) {
                            if (target.compareTo(checkAddr) < 0) {
                                return true; // Backward jump found
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Ignore errors in heuristic analysis
        }
        
        return false;
    }
    
    /**
     * Check if instruction is a jump/branch.
     */
    private boolean isJumpInstruction(Instruction instruction) {
        return instruction.getFlowType().isJump() || 
               instruction.getFlowType().isConditional();
    }
    
    /**
     * Analyze sequence of instructions for crypto patterns.
     */
    private void analyzeInstructionSequence(Instruction startInstruction, Program program) {
        // Look for common crypto instruction sequences
        Address current = startInstruction.getAddress();
        int xorCount = 0;
        int rotateCount = 0;
        
        // Analyze next 20 instructions
        for (int i = 0; i < 20; i++) {
            Instruction instr = program.getListing().getInstructionAfter(current);
            if (instr == null) break;
            
            String mnemonic = instr.getMnemonicString();
            if (mnemonic.contains("XOR")) xorCount++;
            if (mnemonic.contains("ROL") || mnemonic.contains("ROR")) rotateCount++;
            
            current = instr.getAddress();
        }
        
        // High concentration of crypto operations suggests crypto function
        if (xorCount >= 3 && rotateCount >= 2) {
            addDetection(new CryptoDetection(
                startInstruction.getAddress(),
                "CRYPTO_SEQUENCE",
                "Instruction sequence with crypto operations",
                0.6,
                CryptoDetection.DetectionType.PATTERN_MATCH
            ));
        }
    }
    
    /**
     * Add a detection to the results list.
     */
    private void addDetection(CryptoDetection detection) {
        detections.add(detection);
    }
    
    /**
     * Get all detections found by this analyzer.
     */
    public List<CryptoDetection> getDetections() {
        return new ArrayList<>(detections);
    }
    
    /**
     * Clear all detections.
     */
    public void clearDetections() {
        detections.clear();
    }
    
    /**
     * Inner class representing a cryptographic detection.
     */
    public static class CryptoDetection {
        public enum DetectionType {
            PATTERN_MATCH, CONSTANT_MATCH, ENTROPY_ANALYSIS, STRUCTURE_ANALYSIS, HEURISTIC
        }
        
        private final Address address;
        private final String algorithmName;
        private final String description;
        private final double confidence;
        private final DetectionType type;
        
        public CryptoDetection(Address address, String algorithmName, String description, 
                             double confidence, DetectionType type) {
            this.address = address;
            this.algorithmName = algorithmName;
            this.description = description;
            this.confidence = confidence;
            this.type = type;
        }
        
        // Getters
        public Address getAddress() { return address; }
        public String getAlgorithmName() { return algorithmName; }
        public String getDescription() { return description; }
        public double getConfidence() { return confidence; }
        public DetectionType getType() { return type; }
        
        @Override
        public String toString() {
            return String.format("%s at %s (%.1f%% confidence): %s", 
                algorithmName, address, confidence * 100, description);
        }
    }
}