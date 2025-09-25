package cryptodetect.services;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Service for managing and matching cryptographic patterns.
 * Handles pattern compilation, optimization, and matching operations.
 */
public class PatternMatchingService {
    
    // Pattern databases for different crypto algorithms
    private final Map<String, CryptoPattern> patterns;
    private final Map<String, Pattern> compiledRegexPatterns;
    
    public PatternMatchingService() {
        this.patterns = new HashMap<>();
        this.compiledRegexPatterns = new HashMap<>();
        initializePatterns();
    }
    
    /**
     * Initialize built-in cryptographic patterns.
     */
    private void initializePatterns() {
        // AES S-Box patterns
        addBytePattern("AES_SBOX", new byte[]{
            (byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5,
            (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76
        }, "AES S-Box table", 0.9);
        
        // AES Inverse S-Box
        addBytePattern("AES_INV_SBOX", new byte[]{
            (byte)0x52, (byte)0x09, (byte)0x6a, (byte)0xd5, (byte)0x30, (byte)0x36, (byte)0xa5, (byte)0x38,
            (byte)0xbf, (byte)0x40, (byte)0xa3, (byte)0x9e, (byte)0x81, (byte)0xf3, (byte)0xd7, (byte)0xfb
        }, "AES Inverse S-Box table", 0.9);
        
        // DES S-Box patterns
        addBytePattern("DES_SBOX", new byte[]{
            (byte)0x0e, (byte)0x04, (byte)0x0d, (byte)0x01, (byte)0x02, (byte)0x0f, (byte)0x0b, (byte)0x08,
            (byte)0x03, (byte)0x0a, (byte)0x06, (byte)0x0c, (byte)0x05, (byte)0x09, (byte)0x00, (byte)0x07
        }, "DES S-Box table", 0.85);
        
        // SHA-1 Constants
        addBytePattern("SHA1_K1", new byte[]{
            (byte)0x5a, (byte)0x82, (byte)0x79, (byte)0x99
        }, "SHA-1 K1 constant", 0.8);
        
        addBytePattern("SHA1_K2", new byte[]{
            (byte)0x6e, (byte)0xd9, (byte)0xeb, (byte)0xa1
        }, "SHA-1 K2 constant", 0.8);
        
        // MD5 Constants
        addBytePattern("MD5_INIT_A", new byte[]{
            (byte)0x67, (byte)0x45, (byte)0x23, (byte)0x01
        }, "MD5 Initial A value", 0.8);
        
        addBytePattern("MD5_INIT_B", new byte[]{
            (byte)0xef, (byte)0xcd, (byte)0xab, (byte)0x89
        }, "MD5 Initial B value", 0.8);
        
        // RSA common exponents
        addBytePattern("RSA_E_65537", new byte[]{
            (byte)0x01, (byte)0x00, (byte)0x01
        }, "RSA public exponent 65537", 0.7);
        
        // Add regex patterns for strings
        addStringPattern("CRYPTO_ALGORITHM_NAMES", 
            "(?i)(aes|des|rsa|sha|md5|blowfish|twofish|serpent|cast|idea|rc4|rc5|rc6)", 
            "Cryptographic algorithm names", 0.6);
        
        addStringPattern("CRYPTO_MODES",
            "(?i)(ecb|cbc|cfb|ofb|ctr|gcm|ccm)",
            "Cryptographic modes of operation", 0.6);
    }
    
    /**
     * Add a byte pattern to the database.
     */
    public void addBytePattern(String name, byte[] pattern, String description, double confidence) {
        patterns.put(name, new CryptoPattern(name, pattern, description, confidence, PatternType.BYTE));
    }
    
    /**
     * Add a string pattern to the database.
     */
    public void addStringPattern(String name, String regex, String description, double confidence) {
        patterns.put(name, new CryptoPattern(name, regex, description, confidence, PatternType.STRING));
        compiledRegexPatterns.put(name, Pattern.compile(regex));
    }
    
    /**
     * Match byte patterns against data.
     */
    public MatchResult matchBytePattern(byte[] data) {
        for (Map.Entry<String, CryptoPattern> entry : patterns.entrySet()) {
            CryptoPattern pattern = entry.getValue();
            
            if (pattern.getType() == PatternType.BYTE) {
                byte[] patternBytes = pattern.getBytePattern();
                int index = findBytePattern(data, patternBytes);
                
                if (index >= 0) {
                    return new MatchResult(pattern, index, patternBytes.length);
                }
            }
        }
        return null;
    }
    
    /**
     * Match string patterns against text.
     */
    public MatchResult matchStringPattern(String text) {
        for (Map.Entry<String, CryptoPattern> entry : patterns.entrySet()) {
            CryptoPattern pattern = entry.getValue();
            
            if (pattern.getType() == PatternType.STRING) {
                Pattern compiledPattern = compiledRegexPatterns.get(entry.getKey());
                if (compiledPattern != null && compiledPattern.matcher(text).find()) {
                    return new MatchResult(pattern, 0, text.length());
                }
            }
        }
        return null;
    }
    
    /**
     * Find byte pattern in data array.
     */
    private int findBytePattern(byte[] data, byte[] pattern) {
        for (int i = 0; i <= data.length - pattern.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }
    
    /**
     * Get pattern by name.
     */
    public CryptoPattern getPattern(String name) {
        return patterns.get(name);
    }
    
    /**
     * Get all registered patterns.
     */
    public Map<String, CryptoPattern> getAllPatterns() {
        return new HashMap<>(patterns);
    }
    
    // Inner classes for pattern management
    
    public enum PatternType {
        BYTE, STRING
    }
    
    public static class CryptoPattern {
        private final String name;
        private final String description;
        private final double confidence;
        private final PatternType type;
        private final byte[] bytePattern;
        private final String stringPattern;
        
        public CryptoPattern(String name, byte[] pattern, String description, double confidence, PatternType type) {
            this.name = name;
            this.bytePattern = pattern.clone();
            this.stringPattern = null;
            this.description = description;
            this.confidence = confidence;
            this.type = type;
        }
        
        public CryptoPattern(String name, String pattern, String description, double confidence, PatternType type) {
            this.name = name;
            this.bytePattern = null;
            this.stringPattern = pattern;
            this.description = description;
            this.confidence = confidence;
            this.type = type;
        }
        
        // Getters
        public String getName() { return name; }
        public String getDescription() { return description; }
        public double getConfidence() { return confidence; }
        public PatternType getType() { return type; }
        public byte[] getBytePattern() { return bytePattern != null ? bytePattern.clone() : null; }
        public String getStringPattern() { return stringPattern; }
    }
    
    public static class MatchResult {
        private final CryptoPattern pattern;
        private final int offset;
        private final int length;
        
        public MatchResult(CryptoPattern pattern, int offset, int length) {
            this.pattern = pattern;
            this.offset = offset;
            this.length = length;
        }
        
        // Getters
        public CryptoPattern getPattern() { return pattern; }
        public int getOffset() { return offset; }
        public int getLength() { return length; }
    }
}