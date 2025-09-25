# CryptoDetect Changelog

## [1.0.0-SNAPSHOT] - 2024-09-24

### Added
- Initial release of CryptoDetect extension
- Core plugin framework with background analysis support
- Cryptographic routine detection algorithms:
  - AES S-Box pattern recognition
  - DES S-Box detection
  - SHA-1 and MD5 constant identification
  - RSA common exponent detection
  - High entropy data analysis
  - S-Box table structure recognition
- Pattern matching service with extensible pattern database
- Interactive UI with results table and navigation
- Real-time analysis progress reporting
- Color-coded confidence levels in results
- Comprehensive help documentation
- Unit test coverage for core functionality
- Gradle build system integration

### Features
- **Algorithm Detection**: Supports AES, DES, SHA-1, MD5, RSA
- **Pattern Matching**: Byte pattern and string pattern recognition
- **Entropy Analysis**: Detects high-entropy cryptographic data
- **Structure Analysis**: Identifies crypto tables and key schedules
- **Interactive Navigation**: Double-click to jump to detections
- **Confidence Scoring**: Reliability assessment for each detection
- **Background Processing**: Non-blocking analysis execution

### Technical Details
- Java 17+ compatibility
- Ghidra 12.0+ API integration
- Modular architecture for extensibility
- Thread-safe background processing
- Memory-efficient pattern matching
- Comprehensive error handling

### Known Limitations
- Limited to common cryptographic algorithms
- May produce false positives with obfuscated code
- Performance depends on binary size and complexity
- String pattern matching is basic (planned for enhancement)

### Future Enhancements (Planned)
- Additional algorithm support (Blowfish, Twofish, etc.)
- Advanced anti-analysis detection
- String obfuscation decoder
- Control flow analysis
- Machine learning-based detection
- Custom pattern definition support
- Export/import functionality for results