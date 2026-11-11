# Testing & Benchmarking Plan

## Test Suite

### Unit Tests (JUnit 4, pure Kotlin, no Android framework required)

| Test File | Classes Covered | Status |
|-----------|----------------|--------|
| `Phase2InputTest.kt` | InputNormalizer, ManualInputAdapter, ShareSheetAdapter, ProcessTextAdapter, AnalysisInput | Existing |
| `FastRuleEngineTest.kt` | FastRuleEngine (all 31 rules, 5 categories) | Existing |
| `SmsTextPreprocessorTest.kt` | SmsTextPreprocessor (NFC, tokenization, n-grams) | Existing |
| `TfIdfVectorizerTest.kt` | TfIdfVectorizer (vocabulary, IDF, L2 norm) | Existing |
| `SmsSpecialistClassifierTest.kt` | SmsSpecialistClassifier (inference, edge cases) | Existing |
| `SmsClassifierIntegrationTest.kt` | Classifier + rule engine integration | Existing |
| `ThreatVerdictTest.kt` | Domain models (ThreatVerdict, AnalysisStatus, etc.) | Existing |
| `UrlSpecialistDetectorTest.kt` | UrlSpecialistDetector (all detection categories) | **New** |
| `RiskPolicyEngineTest.kt` | RiskPolicyEngine (verdict logic, boundary cases) | **New** |

### Test Coverage Areas

- **Input normalization**: NFC, zero-width char detection, URL/host/phone extraction, malformed URLs, empty/oversized input, UTF-8 boundary safety
- **Rule detection**: All 31 rules across 5 categories, false positive resistance, case/punctuation/whitespace tolerance, Unicode handling, deduplication
- **SMS classifier**: Preprocessing, TF-IDF vectorization, logistic regression inference, threat/safe classification, model unavailability (never SAFE), determinism
- **URL detection**: IP-based URLs, shorteners, suspicious TLDs, homograph attacks, unusual ports, encoded characters, misleading structure, suspicious domain keywords
- **Risk policy**: Verdict determination (SAFE/SUSPICIOUS/HIGH_RISK/INSUFFICIENT_EVIDENCE), threshold boundaries, conflicting evidence, classifier confidence, deterministic output

### Test Execution

```bash
./gradlew :app:testDebugUnitTest
```

**Blocker**: No JDK or Android SDK available in this environment. Tests cannot be executed locally.

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

A. **Development environment** — JVM unit tests (cannot run, no JDK)
B. **Raspberry Pi 5** — 64-bit ARM Linux, additional benchmark platform (not available)
C. **Actual Android ARM device** — target deployment platform (not available)

**Important**: Raspberry Pi results do not prove Android compatibility. All benchmark results must be measured, not estimated. No results are claimed in this implementation.

## Known Limitations

1. No production-labelled dataset available — synthetic fixture model only
2. No JDK/Android SDK — builds and tests cannot be executed
3. No Android device — APK cannot be installed or tested
4. No Raspberry Pi 5 — ARM benchmarking cannot be performed
5. All performance metrics are estimated, not measured

## Recommended Next Steps for Testing

1. Install JDK 17 and Android SDK
2. Run `./gradlew :app:testDebugUnitTest` to execute unit tests
3. Run `./gradlew :app:assembleDebug` to generate debug APK
4. Obtain a labelled SMS dataset (UCI SMS Spam Collection or similar)
5. Train a production model via `tools/sms_classifier/train.py`
6. Measure detection metrics on held-out test data
7. Deploy to Android device and measure end-to-end latency
