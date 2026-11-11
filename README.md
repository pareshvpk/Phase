# ARM Digital Safety Guardian

Android Threat Assistant is an on-device tool for inspecting suspicious messages (for example SMS text) for potential threats. No network requests, no SMS collection, and no analytics are used. User-entered text stays on the device.

## Project Status

| Phase | Name | Status |
|-------|------|--------|
| Phase 1 | Foundation (domain models) | Complete |
| Phase 2 | Input Ingestion and Normalization | Complete |
| Phase 3A | Deterministic Rule Detection (FastRuleEngine) | Complete |
| Phase 3B | SMS Specialist Classifier | Complete (test fixture model only) |
| Phase 3B+ | URL Specialist Detector | Complete |
| Phase 4 | Risk Policy Engine (authoritative verdict) | Complete |
| Phase 5 | ExecuTorch Integration | Evaluated — deferred (pure Kotlin sufficient) |
| Phase 6 | Jetpack Compose UI (7 screens) | Complete |
| Phase 7 | Privacy & Security | Verified |
| Phase 8 | Testing & Benchmarking | Test suite complete (unexecuted — no JDK/Android SDK) |
| Phase 9 | Final Deliverables | Documentation complete |

## Features

- **Manual text entry**: Type or paste a suspicious message for analysis
- **Android Share Sheet**: Receive shared text from other apps via `ACTION_SEND`
- **Android Process Text**: Receive selected text from other apps via `ACTION_PROCESS_TEXT`
- **Offline detection**: All analysis runs locally on the device — no network required
- **URL analysis**: Detects IP-based URLs, shorteners, homograph attacks, suspicious TLDs, unusual ports, encoded characters, and misleading structures
- **Rule-based detection**: 31 deterministic rules across 5 categories (urgency/coercion, credential requests, financial impersonation, payment demands, account suspension)
- **ML classification**: Pure-Kotlin logistic regression with TF-IDF features (test fixture model)
- **Authoritative verdict**: RiskPolicyEngine combines all evidence into SAFE / SUSPICIOUS / HIGH_RISK / INSUFFICIENT_EVIDENCE
- **Explainable output**: Evidence summary, contributing features, matched rule descriptions
- **Recommended actions**: Context-specific guidance based on verdict level

## Privacy & Security

- No `READ_SMS` / `RECEIVE_SMS` permissions and no background SMS collection
- No network requests; `INTERNET` permission declared as `android:required="false"` and unused
- No analytics and no message-content logging
- Extracted links are never opened or executed automatically
- The original message is always preserved
- No message persistence — data held in memory only

## Getting Started

The project is a Gradle Android application (Kotlin + Jetpack Compose).

```bash
./gradlew :app:assembleDebug      # debug build
./gradlew :app:testDebugUnitTest  # unit tests
```

**Note**: A Gradle wrapper, JDK 17, and Android SDK are required to build. Neither JDK nor Android SDK is present in this checkout, so builds and tests cannot be executed in this environment.

## Documentation

- `ARCHITECTURE.md` — Phase architecture and component design
- `docs/IMPLEMENTATION_STATUS.md` — Per-phase implementation status
- `docs/PRIVACY_SECURITY.md` — Privacy architecture and security model
- `docs/TESTING_BENCHMARKING.md` — Test suite and benchmarking plan
- `docs/EXECUTORCH_EVALUATION.md` — ExecuTorch integration evaluation
