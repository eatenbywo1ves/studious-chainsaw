package cryptodetect;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

import cryptodetect.analyzers.CryptoRoutineAnalyzer;
import cryptodetect.analyzers.CryptoRoutineAnalyzer.CryptoDetection;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.GenericAddressSpace;

/**
 * Unit tests for CryptoRoutineAnalyzer.
 */
public class CryptoRoutineAnalyzerTest {
    
    private CryptoRoutineAnalyzer analyzer;
    private AddressFactory addressFactory;
    
    @Before
    public void setUp() {
        analyzer = new CryptoRoutineAnalyzer();
        
        // Create a simple address factory for testing
        GenericAddressSpace space = new GenericAddressSpace("test", 32, AddressFactory.DEFAULT_ENDIANNESS, 0);
        addressFactory = new AddressFactory(new GenericAddressSpace[]{space});
    }
    
    @Test
    public void testAESDataDetection() {
        // AES S-Box data
        byte[] aesData = new byte[]{
            (byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5,
            (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76,
            (byte)0xca, (byte)0x82, (byte)0xc9, (byte)0x7d, (byte)0xfa, (byte)0x59, (byte)0x47, (byte)0xf0,
            (byte)0xad, (byte)0xd4, (byte)0xa2, (byte)0xaf, (byte)0x9c, (byte)0xa4, (byte)0x72, (byte)0xc0
        };
        
        Address testAddress = addressFactory.getAddress("test:1000");
        analyzer.analyzeData(testAddress, aesData, null);
        
        assertEquals("Should have at least one detection", true, analyzer.getDetections().size() > 0);
        
        boolean foundAES = analyzer.getDetections().stream()
            .anyMatch(detection -> detection.getAlgorithmName().contains("AES"));
        assertTrue("Should detect AES pattern", foundAES);
    }
    
    @Test
    public void testHighEntropyDetection() {
        // High entropy data (pseudo-random)
        byte[] highEntropyData = new byte[]{
            (byte)0x8f, (byte)0x3a, (byte)0xc7, (byte)0x91, (byte)0x45, (byte)0xbe, (byte)0x2d, (byte)0x76,
            (byte)0x59, (byte)0xa1, (byte)0x68, (byte)0xfc, (byte)0x84, (byte)0x37, (byte)0x95, (byte)0x6e,
            (byte)0x23, (byte)0xd8, (byte)0x41, (byte)0x7f, (byte)0x9c, (byte)0x52, (byte)0x18, (byte)0xab,
            (byte)0x64, (byte)0xe9, (byte)0x35, (byte)0xc2, (byte)0x78, (byte)0x46, (byte)0xd1, (byte)0x5a
        };
        
        Address testAddress = addressFactory.getAddress("test:2000");
        analyzer.analyzeData(testAddress, highEntropyData, null);
        
        boolean foundHighEntropy = analyzer.getDetections().stream()
            .anyMatch(detection -> detection.getAlgorithmName().equals("HIGH_ENTROPY_DATA"));
        assertTrue("Should detect high entropy data", foundHighEntropy);
    }
    
    @Test
    public void testSBoxDetection() {
        // Create a simple S-box like structure (unique values)
        byte[] sboxData = new byte[16];
        for (int i = 0; i < 16; i++) {
            sboxData[i] = (byte)(15 - i); // Reverse order for uniqueness
        }
        
        Address testAddress = addressFactory.getAddress("test:3000");
        analyzer.analyzeData(testAddress, sboxData, null);
        
        boolean foundSBox = analyzer.getDetections().stream()
            .anyMatch(detection -> detection.getAlgorithmName().equals("SBOX_TABLE"));
        assertTrue("Should detect S-box table", foundSBox);
    }
    
    @Test
    public void testClearDetections() {
        // Add some test data
        byte[] testData = new byte[]{
            (byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b
        };
        
        Address testAddress = addressFactory.getAddress("test:4000");
        analyzer.analyzeData(testAddress, testData, null);
        
        assertTrue("Should have detections before clear", analyzer.getDetections().size() > 0);
        
        analyzer.clearDetections();
        assertEquals("Should have no detections after clear", 0, analyzer.getDetections().size());
    }
    
    @Test
    public void testDetectionProperties() {
        byte[] aesData = new byte[]{
            (byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b
        };
        
        Address testAddress = addressFactory.getAddress("test:5000");
        analyzer.analyzeData(testAddress, aesData, null);
        
        if (analyzer.getDetections().size() > 0) {
            CryptoDetection detection = analyzer.getDetections().get(0);
            
            assertNotNull("Detection should have an address", detection.getAddress());
            assertNotNull("Detection should have an algorithm name", detection.getAlgorithmName());
            assertNotNull("Detection should have a description", detection.getDescription());
            assertNotNull("Detection should have a type", detection.getType());
            assertTrue("Confidence should be between 0 and 1", 
                detection.getConfidence() >= 0.0 && detection.getConfidence() <= 1.0);
        }
    }
}