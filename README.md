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
| Phase 6 | Jetpack Compose UI (7 UI areas) | Complete |
| Phase 7 | Privacy & Security | Verified |
| Phase 8 | Testing & Benchmarking | Complete — 144 JVM unit tests pass |
| Phase 9 | Final Deliverables | Documentation complete |

## Features

- **Manual text entry**: Type or paste a suspicious message for analysis
- **Android Share Sheet**: Receive shared text from other apps via `ACTION_SEND`
- **Android Process Text**: Receive selected text from other apps via `ACTION_PROCESS_TEXT`
- **Offline detection**: All analysis runs locally on the device — no network required
- **URL analysis**: Detects IP-based URLs, shorteners, homograph attacks, suspicious TLDs, unusual ports, encoded characters, and misleading structures
- **Rule-based detection**: 37 deterministic rules across 5 categories (urgency/coercion, credential requests, financial impersonation, payment demands, account suspension)
- **ML classification**: Pure-Kotlin logistic regression with TF-IDF features (test fixture model)
- **Authoritative verdict**: RiskPolicyEngine combines all evidence into SAFE / SUSPICIOUS / HIGH_RISK / INSUFFICIENT_EVIDENCE
- **Explainable output**: Evidence summary, contributing features, matched rule descriptions
- **Recommended actions**: Context-specific guidance based on verdict level

## Privacy & Security

- No permissions are declared in `AndroidManifest.xml` — no `INTERNET`, no `READ_SMS` / `RECEIVE_SMS`, no storage access
- No network requests
- No analytics and no message-content logging
- Extracted links are never opened or executed automatically
- The original message is always preserved
- No message persistence — data held in memory only

## Build & test

Requirements:

- **JDK 21** — the Android Studio bundled JBR (`C:\Program Files\Android\Android Studio\jbr`)
- **Android SDK 35** (compileSdk/targetSdk 35, minSdk 26), pointed at by `sdk.dir` in `local.properties`

```bash
./gradlew assembleDebug        # debug APK -> app/build/outputs/apk/debug/app-debug.apk
./gradlew testDebugUnitTest    # 144 JVM unit tests
```

On Windows (bash), point Gradle at the Android Studio JBR:

```bash
export JAVA_HOME='C:/Program Files/Android/Android Studio/jbr'
```

Both commands currently succeed: the debug APK builds and all 144 unit tests pass.

> Earlier revisions of this repository documented a build blocker caused by
> "stub Compose artifacts" in the Gradle cache. That diagnosis was incorrect —
> the build failures were source and build-configuration errors, and they are
> now fixed. No local Maven repository, `libs/` directory, or artifact-renaming
> workaround is part of the project.

## Documentation

- `ARCHITECTURE.md` — Phase architecture and component design
- `docs/IMPLEMENTATION_STATUS.md` — Per-phase implementation status
- `docs/PRIVACY_SECURITY.md` — Privacy architecture and security model
- `docs/TESTING_BENCHMARKING.md` — Test suite and benchmarking plan
- `docs/EXECUTORCH_EVALUATION.md` — ExecuTorch integration evaluation
- `docs/ENGINEERING_REPORT.md` — Implementation and build summary
- `docs/POST_IMPLEMENTATION_AUDIT.md` — Engineering audit findings
- `docs/COMPOSE_DEPENDENCY_DIAGNOSIS.md` — Dependency configuration and build status
