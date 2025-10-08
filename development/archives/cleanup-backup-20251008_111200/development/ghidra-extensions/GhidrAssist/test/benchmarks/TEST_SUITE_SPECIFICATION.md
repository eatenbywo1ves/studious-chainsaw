# GhidrAssist Benchmark Test Suite
**MEASURE Phase - Day 4**

---

## Overview

This benchmark suite validates GhidrAssist performance and accuracy across diverse binary samples ranging from simple programs to complex malware.

**Test Categories:**
1. Simple Binaries (Baseline)
2. Medium Complexity (Real-world utilities)
3. High Complexity (Large applications, malware)

**Metrics Collected:**
- Analysis time per function
- Total analysis time per binary
- Memory usage
- AI response quality
- Vulnerability detection accuracy
- Variable naming relevance

---

## Test Binary Suite

### Category 1: Simple Binaries (Baseline)

#### 1. hello_world
- **Size:** ~1KB
- **Functions:** 5
- **Expected Analysis Time:** <1s
- **Expected Vulnerabilities:** 0
- **Purpose:** Baseline performance, verify plugin loads correctly

**Test Binaries:**
```c
// hello_world.c
#include <stdio.h>
int main() {
    printf("Hello, World!\n");
    return 0;
}
```

**Compile:**
```bash
gcc -o hello_world hello_world.c
```

---

#### 2. simple_math
- **Size:** ~2KB
- **Functions:** 10
- **Expected Analysis Time:** <2s
- **Expected Vulnerabilities:** 0
- **Purpose:** Test arithmetic analysis, variable naming

**Test Binaries:**
```c
// simple_math.c
#include <stdio.h>

int add(int a, int b) { return a + b; }
int subtract(int a, int b) { return a - b; }
int multiply(int a, int b) { return a * b; }
int divide(int a, int b) { return b != 0 ? a / b : 0; }

int main() {
    printf("10 + 5 = %d\n", add(10, 5));
    printf("10 - 5 = %d\n", subtract(10, 5));
    printf("10 * 5 = %d\n", multiply(10, 5));
    printf("10 / 5 = %d\n", divide(10, 5));
    return 0;
}
```

---

### Category 2: Medium Complexity

#### 3. vulnerable_network_client
- **Size:** ~50KB
- **Functions:** 50-100
- **Expected Analysis Time:** <10s
- **Expected Vulnerabilities:** 3-5 (HIGH severity)
- **Purpose:** Test vulnerability detection accuracy

**Intentional Vulnerabilities:**
```c
// vulnerable_network_client.c
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

void process_data(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // VULN: Buffer overflow
    printf(buffer);         // VULN: Format string
}

int calculate_size(int count, int item_size) {
    return count * item_size;  // VULN: Integer overflow
}

int main() {
    char user_input[256];
    fgets(user_input, sizeof(user_input), stdin);
    process_data(user_input);
    return 0;
}
```

**Expected Detections:**
- Buffer Overflow (strcpy) - HIGH
- Format String (printf) - CRITICAL
- Integer Overflow (multiplication) - MEDIUM

---

#### 4. crypto_sample
- **Size:** ~100KB
- **Functions:** 150-200
- **Expected Analysis Time:** <20s
- **Expected Vulnerabilities:** 1-2 (weak crypto usage)
- **Purpose:** Test complex function analysis

**Sample:**
```c
// crypto_sample.c
#include <openssl/aes.h>
#include <string.h>

void encrypt_data(unsigned char *plaintext, int len,
                  unsigned char *key, unsigned char *ciphertext) {
    AES_KEY enc_key;
    AES_set_encrypt_key(key, 128, &enc_key);
    AES_encrypt(plaintext, ciphertext, &enc_key);
}

// Additional crypto functions...
```

---

### Category 3: High Complexity

#### 5. opensource_utility (e.g., curl)
- **Size:** ~500KB
- **Functions:** 1000+
- **Expected Analysis Time:** <60s
- **Expected Vulnerabilities:** 5-10
- **Purpose:** Real-world performance validation

**Source:**
- Download curl source: https://github.com/curl/curl
- Compile with debug symbols: `gcc -g -o curl_test curl.c`

**Metrics Focus:**
- Scalability to large codebases
- Memory efficiency
- AI explanation quality on complex functions

---

#### 6. malware_sample (obfuscated)
- **Size:** ~2MB
- **Functions:** 5000+
- **Expected Analysis Time:** <300s (5 minutes)
- **Expected Vulnerabilities:** 10-20
- **Purpose:** Stress test, obfuscation handling

**Sample Sources:**
- Use VirusTotal samples (with permission)
- Or create synthetic obfuscated binary

**Warning:** Handle with care, use isolated VM

---

## Success Criteria

### Performance Targets

| Binary Category | Function Count | Target Time | Acceptable | Unacceptable |
|----------------|----------------|-------------|------------|--------------|
| Simple | <10 | <2s | <5s | >10s |
| Medium | 50-200 | <15s | <30s | >60s |
| Large | 1000+ | <60s | <120s | >300s |
| Malware | 5000+ | <180s | <300s | >600s |

### Accuracy Targets

| Metric | Target | Acceptable | Unacceptable |
|--------|--------|------------|--------------|
| Vulnerability Detection Rate | >90% | >75% | <75% |
| False Positive Rate | <10% | <20% | >20% |
| Explanation Quality Score | >0.80 | >0.65 | <0.65 |
| Variable Naming Relevance | >85% | >70% | <70% |

---

## Metrics Collection

### Automated Metrics
```json
{
  "binary_name": "vulnerable_network_client",
  "file_size_kb": 52,
  "function_count": 87,
  "analysis_time_sec": 8.3,
  "memory_usage_mb": 512,
  "vulnerabilities": {
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 0,
    "total": 4
  },
  "true_positives": 4,
  "false_positives": 0,
  "false_negatives": 1
}
```

### Manual Validation
- Review 10 AI function explanations per binary
- Score quality on 0-1 scale
- Verify variable name suggestions make sense
- Confirm vulnerability findings are accurate

---

## Test Execution Plan

### Phase 1: Setup (30 minutes)
1. Compile all test binaries
2. Copy to `test/binaries/` directory
3. Verify Ghidra can open each binary
4. Configure MCP server with test model

### Phase 2: Baseline Tests (1 hour)
1. Run hello_world test
2. Run simple_math test
3. Collect baseline metrics
4. Verify plugin functionality

### Phase 3: Medium Complexity (1.5 hours)
1. Run vulnerable_network_client
2. Validate vulnerability detection
3. Run crypto_sample
4. Measure analysis times

### Phase 4: High Complexity (1.5 hours)
1. Run opensource_utility
2. Test scalability
3. Run malware_sample (optional)
4. Stress test

### Phase 5: Analysis (30 minutes)
1. Aggregate all metrics
2. Generate summary report
3. Identify performance bottlenecks
4. Document findings

**Total Time:** ~4 hours (as planned for Day 4)

---

## Sample Benchmark Results (Template)

```markdown
# GhidrAssist Benchmark Results

**Date:** October 7, 2025
**Version:** 1.0.0
**Test System:** Intel i7-12700K, 32GB RAM, Windows 11

## Performance Summary

| Binary | Size | Functions | Time | Memory | Status |
|--------|------|-----------|------|--------|--------|
| hello_world | 1KB | 5 | 0.8s | 350MB | ✅ PASS |
| simple_math | 2KB | 10 | 1.3s | 380MB | ✅ PASS |
| vulnerable_client | 52KB | 87 | 8.3s | 512MB | ✅ PASS |
| crypto_sample | 105KB | 178 | 17.2s | 720MB | ✅ PASS |
| curl | 512KB | 1247 | 58.9s | 1.8GB | ✅ PASS |
| malware | 2.1MB | 5432 | 247.3s | 3.2GB | ⚠️ SLOW |

## Vulnerability Detection

| Binary | Expected | Detected | Missed | False+ | Accuracy |
|--------|----------|----------|--------|--------|----------|
| vulnerable_client | 5 | 4 | 1 | 0 | 80% |
| crypto_sample | 2 | 2 | 0 | 1 | 67% |
| curl | 8 | 7 | 1 | 2 | 78% |

**Overall Detection Rate:** 81.3% ✅ (Target: >75%)
**False Positive Rate:** 15.4% ✅ (Target: <20%)

## AI Quality Assessment

**Explanation Quality:** 0.79 ✅ (Target: >0.75)
**Variable Naming:** 82% ✅ (Target: >80%)

## Conclusion

GhidrAssist meets performance targets for simple and medium binaries.
Large binary performance is acceptable but could be optimized.
Vulnerability detection accuracy exceeds minimum threshold.

**Overall Grade:** B+ (Pass with recommendations)
```

---

## Known Test Limitations

1. **MCP Dependency:** Requires live MCP server for full testing
2. **AI Variability:** LLM responses may vary between runs
3. **Binary Availability:** Some test binaries require compilation/download
4. **Malware Samples:** May require special permissions or VM setup

---

## Future Enhancements

### v1.1 Test Suite
- [ ] Add ARM binaries
- [ ] Add stripped binaries (no symbols)
- [ ] Add Go binaries
- [ ] Add Rust binaries
- [ ] Automated regression testing

### v2.0 Test Suite
- [ ] Cross-architecture tests
- [ ] Multi-threading performance
- [ ] Batch mode benchmarks
- [ ] Cache effectiveness tests

---

**Document Version:** 1.0
**Last Updated:** October 7, 2025
**Status:** Ready for execution
