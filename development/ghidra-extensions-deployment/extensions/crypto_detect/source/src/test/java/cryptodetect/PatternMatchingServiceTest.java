package cryptodetect;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import cryptodetect.services.PatternMatchingService;

/**
 * Unit tests for PatternMatchingService.
 */
public class PatternMatchingServiceTest {
    
    private PatternMatchingService patternService;
    
    @Before
    public void setUp() {
        patternService = new PatternMatchingService();
    }
    
    @Test
    public void testAESPatternMatching() {
        // AES S-Box first 16 bytes
        byte[] aesData = new byte[]{
            (byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, 
            (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5,
            (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, 
            (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76
        };
        
        PatternMatchingService.MatchResult result = patternService.matchBytePattern(aesData);
        assertNotNull("AES S-Box pattern should be detected", result);
        assertEquals("Should detect AES_SBOX pattern", "AES_SBOX", result.getPattern().getName());
        assertTrue("Confidence should be high", result.getPattern().getConfidence() > 0.8);
    }
    
    @Test
    public void testSHA1ConstantMatching() {
        // SHA-1 K1 constant
        byte[] sha1Data = new byte[]{
            (byte)0x5a, (byte)0x82, (byte)0x79, (byte)0x99
        };
        
        PatternMatchingService.MatchResult result = patternService.matchBytePattern(sha1Data);
        assertNotNull("SHA-1 constant should be detected", result);
        assertEquals("Should detect SHA1_K1 pattern", "SHA1_K1", result.getPattern().getName());
    }
    
    @Test
    public void testStringPatternMatching() {
        String cryptoString = "Using AES encryption with CBC mode";
        
        PatternMatchingService.MatchResult result = patternService.matchStringPattern(cryptoString);
        assertNotNull("Crypto algorithm name should be detected", result);
        assertTrue("Should detect crypto algorithm or mode", 
            result.getPattern().getName().equals("CRYPTO_ALGORITHM_NAMES") ||
            result.getPattern().getName().equals("CRYPTO_MODES"));
    }
    
    @Test
    public void testNoMatchForRandomData() {
        byte[] randomData = new byte[]{
            (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,
            (byte)0x9a, (byte)0xbc, (byte)0xde, (byte)0xf0
        };
        
        PatternMatchingService.MatchResult result = patternService.matchBytePattern(randomData);
        assertNull("Random data should not match any crypto patterns", result);
    }
    
    @Test
    public void testPatternRetrieval() {
        PatternMatchingService.CryptoPattern pattern = patternService.getPattern("AES_SBOX");
        assertNotNull("AES_SBOX pattern should exist", pattern);
        assertEquals("Pattern name should match", "AES_SBOX", pattern.getName());
        assertEquals("Pattern type should be BYTE", 
            PatternMatchingService.PatternType.BYTE, pattern.getType());
    }
}