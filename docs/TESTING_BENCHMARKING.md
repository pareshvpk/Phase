# Testing & Benchmarking Plan

## Test Suite

### Unit Tests (JUnit 4, pure Kotlin, no Android framework required)

| Test File | Classes Covered | Tests | Status |
|-----------|----------------|-------|--------|
| `Phase2InputTest.kt` | InputNormalizer, ManualInputAdapter, ShareSheetAdapter, ProcessTextAdapter, AnalysisInput | 20 | Passing |
| `FastRuleEngineTest.kt` | FastRuleEngine (all 37 rules, 5 categories) | 51 | Passing |
| `SmsTextPreprocessorTest.kt` | SmsTextPreprocessor (NFC, tokenization, n-grams) | 13 | Passing |
| `TfIdfVectorizerTest.kt` | TfIdfVectorizer (vocabulary, IDF, L2 norm) | 7 | Passing |
| `SmsSpecialistClassifierTest.kt` | SmsSpecialistClassifier (inference, edge cases) | 15 | Passing |
| `SmsClassifierIntegrationTest.kt` | Classifier + rule engine integration | 6 | Passing |
| `ThreatVerdictTest.kt` | Domain models (ThreatVerdict, AnalysisStatus, etc.) | 5 | Passing |
| `UrlSpecialistDetectorTest.kt` | UrlSpecialistDetector (all detection categories) | 13 | Passing |
| `RiskPolicyEngineTest.kt` | RiskPolicyEngine (verdict logic, boundary cases) | 14 | Passing |
| **Total** | **9 test classes** | **144** | **0 failures** |

### Test Coverage Areas

- **Input normalization**: NFC, zero-width char detection, URL/host/phone extraction, malformed URLs, empty/oversized input, UTF-8 boundary safety
- **Rule detection**: All 37 rules across 5 categories, false positive resistance, case/punctuation/whitespace tolerance, Unicode handling, deduplication
- **SMS classifier**: Preprocessing, TF-IDF vectorization, logistic regression inference, threat/safe classification, model unavailability (never SAFE), determinism
- **URL detection**: IP-based URLs, shorteners, suspicious TLDs, homograph attacks, unusual ports, encoded characters, misleading structure, suspicious domain keywords
- **Risk policy**: Verdict determination (SAFE/SUSPICIOUS/HIGH_RISK/INSUFFICIENT_EVIDENCE), threshold boundaries, conflicting evidence, classifier confidence, deterministic output

### Test Execution

Requirements: JDK 21 (Android Studio bundled JBR) and Android SDK 35.

```bash
export JAVA_HOME='C:/Program Files/Android/Android Studio/jbr'   # Windows bash
./gradlew testDebugUnitTest
```

The suite executes successfully: 144 tests, 0 failures.

## Benchmarking Plan

### Detection Metrics (to be measured with real labelled dataset)

| Metric | Definition | Target |
|--------|-----------|--------|
| Precision | TP / (TP + FP) | > 0.85 |
| Recall | TP / (TP + FN) | > 0.80 |
| F1 Score | 2 × P × R / (P + R) | > 0.82 |
| False Positive Rate | FP / (FP + TN) | < 0.05 |

### Performance Metrics (to be measured on target hardware)

| Metric | Definition |
|--------|-----------|
| Message processing latency | End-to-end time from input to verdict |
| Classifier inference latency | Time for SMS classifier inference only |
| Rule engine latency | Time for FastRuleEngine detection only |
| URL detection latency | Time for UrlSpecialistDetector only |
| Risk policy latency | Time for RiskPolicyEngine verdict only |
| Total end-to-end latency | Sum of all detection stages |
| Peak memory consumption | Maximum RSS during analysis |
| Model file size | Size of model artifact in APK |
| CPU utilization | CPU time during analysis |

### Test Platforms

A. **Development environment** — JVM unit tests (running: 144 tests pass)
B. **Raspberry Pi 5** — 64-bit ARM Linux, additional benchmark platform (not available)
C. **Actual Android ARM device** — target deployment platform (not available)

**Important**: Raspberry Pi results do not prove Android compatibility. All benchmark results must be measured, not estimated. No benchmark results are claimed in this implementation.

## Known Limitations

1. No production-labelled dataset available — synthetic fixture model only
2. No Android device — the APK can be built but not installed or device-tested
3. The `androidTest` instrumentation source set needs a device/emulator and is not part of the verified JVM test run
4. No Raspberry Pi 5 — ARM benchmarking cannot be performed
5. All performance metrics are estimated, not measured

## Recommended Next Steps for Testing

1. Install the debug APK on a physical ARM Android device and verify offline behaviour
2. Obtain a labelled SMS dataset (UCI SMS Spam Collection or similar)
3. Train a production model via `tools/sms_classifier/train.py`
4. Measure detection metrics on held-out test data
5. Deploy to Android device and measure end-to-end latency
