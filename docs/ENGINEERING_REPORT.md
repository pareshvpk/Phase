# Engineering Report — ARM Digital Safety Guardian

## Project Overview

**Project**: Android Threat Assistant (ARM Digital Safety Guardian)
**Package**: `com.arm.threatassistant`
**Platform**: Android (minSdk 26, targetSdk 35, compileSdk 35)
**Framework**: Kotlin + Jetpack Compose, Gradle build
**AGP**: 8.6.0, **Kotlin**: 2.0.0, **Compose**: aligned via Compose BOM 2024.09.00

## What Was Implemented

### Phase 1 — Foundation (existing, preserved)
- Domain models: `AnalysisInput`, `AnalysisResult`, `AnalysisStatus`, `ThreatVerdict`
- `ThreatAnalysisViewModel` with `ThreatAnalysisUiState`

### Phase 2 — Input Ingestion and Normalization (existing, preserved)
- 3 ingestion adapters: Manual, Share Sheet (ACTION_SEND), Process Text (ACTION_PROCESS_TEXT)
- `InputNormalizer`: NFC normalization, invisible char detection, URL/host/phone extraction
- Manifest intent filters for share sheet and process text

### Phase 3A — FastRuleEngine (existing, preserved)
- 37 deterministic rules across 5 categories
- Structured `DetectionSignal` output, no verdict

### Phase 3B — SMS Specialist Classifier (existing, preserved)
- Pure-Kotlin logistic regression with TF-IDF
- Test fixture model (NOT FOR PRODUCTION)

### Phase 3B+ — URL Specialist Detector (NEW)
- `UrlDetectionEvidence.kt` — evidence data classes
- `UrlSpecialistDetector.kt` — 10 detection categories (IP-based, shorteners, homographs, suspicious TLDs, unusual ports, encoded chars, misleading structure, etc.)
- `UrlDetectionSection.kt` — Compose UI component
- `UrlSpecialistDetectorTest.kt` — 13 unit tests

### Phase 4 — Risk Policy Engine (NEW)
- `RiskPolicyEngine.kt` — authoritative verdict engine
- Verdict levels: SAFE, SUSPICIOUS, HIGH_RISK, INSUFFICIENT_EVIDENCE
- Deterministic scoring with configurable weights and thresholds
- `RiskPolicyEngineTest.kt` — 14 unit tests (boundary cases, conflicting signals, determinism)

### Phase 5 — ExecuTorch Integration (EVALUATED, DEFERRED)
- Evaluated against pure-Kotlin logistic regression
- Deferred due to excessive runtime overhead (~30-50MB) for lightweight model
- See `docs/EXECUTORCH_EVALUATION.md`

### Phase 6 — UI (NEW/EXISTING)
- 7 UI areas: Home, Input, Analysis, Verdict, Evidence, Actions, Settings
- New components: `RiskVerdictSection`, `EvidenceSection`, `RecommendedActionsSection`, `UrlDetectionSection`, `ThreatAssistantScreen`, `SettingsScreen`
- `ThreatAssistantScreen` replaces `MainScreen` as entry point with settings navigation

### Phase 7 — Privacy & Security (VERIFIED)
- No permissions declared in the manifest, no network usage, no analytics
- URLs never auto-opened
- Original message preserved
- See `docs/PRIVACY_SECURITY.md`

### Phase 8 — Testing (EXECUTED, PASSING)
- 9 JVM unit test classes, 144 tests, 0 failures
- Requires JDK 21 (Android Studio JBR) and Android SDK 35
- See `docs/TESTING_BENCHMARKING.md`

### Phase 9 — Documentation (COMPLETE)
- README.md, ARCHITECTURE.md, IMPLEMENTATION_STATUS.md updated
- New docs: PRIVACY_SECURITY.md, TESTING_BENCHMARKING.md, EXECUTORCH_EVALUATION.md

## What Was Fixed

1. **ViewModel integration**: `ThreatAnalysisViewModel` now runs all three detectors (FastRuleEngine, UrlSpecialistDetector, SmsSpecialistClassifier) and feeds results into `RiskPolicyEngine` for authoritative verdict.
2. **UI state**: `ThreatAnalysisUiState` extended with `urlDetectionResult` and `riskAssessment` fields.
3. **Verdict output**: `AnalysisResult.verdict` is now populated from `RiskPolicyEngine.assess()` output (mapped from `ThreatVerdictLevel` to `ThreatVerdict`).
4. **Result message**: `buildResultMessage()` produces explainable output with verdict, risk score, evidence summary, contributing features, and recommended actions.
5. **Strings**: Added all new section labels and privacy strings to `strings.xml`.
6. **MainActivity**: Updated to use `ThreatAssistantScreen` instead of `MainScreen`.

## Build and Detection Fixes

The build was previously blocked by source and build-configuration errors, not by
dependency artifacts:

1. **Compose dependencies**: switched from hard-pinned Compose versions to the
   Compose BOM platform (`compose-bom = 2024.09.00`); no `exclude()` statements.
2. **Java/Kotlin target**: `1.8` → `17`.
3. **Gradle properties**: removed `android.injected.test.only.run.unit.tests=true`,
   an Android Studio injected property that does not belong in the project file.
4. **Compose imports**: corrected imports and composables that did not match the
   artifacts in use (`Row` from `foundation-layout`, `FontWeight`/`TextStyle`
   from `ui-text`, removal of `Chip`/`ChipDefaults` and Material icons,
   `collectAsStateWithLifecycle` → `collectAsState`).
5. **Manifest**: removed the unused `INTERNET` permission — the app now declares
   no permissions at all.
6. **Detection logic**: URL detector treats a missing port as absent and parses
   non-ASCII hosts; `RiskPolicyEngine` applies severity-aware multi-signal rules
   and ignores low-confidence classifier scores; `FastRuleEngine` strips
   zero-width characters and normalizes before matching; the SMS preprocessor
   and vectorizer use Unicode-aware tokens with a stem fallback.

## What Was Not Implemented

| Item | Reason |
|------|--------|
| Release APK | No signing configuration |
| Production model training | No labelled dataset available (only 30-row synthetic sample) |
| ExecuTorch integration | Evaluated, deferred — pure Kotlin sufficient |
| Android device testing | No device available |
| Raspberry Pi 5 benchmarking | No hardware available |

## Files Created (New)

### Source
1. `app/src/main/java/com/arm/threatassistant/domain/detection/urldetection/UrlDetectionEvidence.kt`
2. `app/src/main/java/com/arm/threatassistant/domain/detection/urldetection/UrlSpecialistDetector.kt`
3. `app/src/main/java/com/arm/threatassistant/domain/detection/riskpolicy/RiskPolicyEngine.kt`
4. `app/src/main/java/com/arm/threatassistant/presentation/components/RiskVerdictSection.kt`
5. `app/src/main/java/com/arm/threatassistant/presentation/components/EvidenceSection.kt`
6. `app/src/main/java/com/arm/threatassistant/presentation/components/RecommendedActionsSection.kt`
7. `app/src/main/java/com/arm/threatassistant/presentation/components/UrlDetectionSection.kt`
8. `app/src/main/java/com/arm/threatassistant/presentation/screens/ThreatAssistantScreen.kt`

### Tests
9. `app/src/test/java/com/arm/threatassistant/domain/urldetection/UrlSpecialistDetectorTest.kt`
10. `app/src/test/java/com/arm/threatassistant/domain/riskpolicy/RiskPolicyEngineTest.kt`

### Documentation
11. `docs/EXECUTORCH_EVALUATION.md`
12. `docs/PRIVACY_SECURITY.md`
13. `docs/TESTING_BENCHMARKING.md`

### Files Modified
- `app/src/main/java/com/arm/threatassistant/presentation/viewmodel/ThreatAnalysisViewModel.kt` — integrated URL detector + RiskPolicyEngine
- `app/src/main/java/com/arm/threatassistant/MainActivity.kt` — uses ThreatAssistantScreen
- `app/src/main/res/values/strings.xml` — added new strings
- `README.md` — updated project status
- `ARCHITECTURE.md` — comprehensive rewrite with all phases
- `docs/IMPLEMENTATION_STATUS.md` — comprehensive rewrite

## Build Configuration Status

- `build.gradle.kts` (root): AGP 8.6.0, Kotlin 2.0.0 plugins — configured correctly
- `settings.gradle.kts`: includes `:app`, repositories configured — correct
- `gradle/libs.versions.toml`: versions pinned; Compose artifacts aligned via the Compose BOM — correct
- `app/build.gradle.kts`: Compose enabled, SDK 35, minSdk 26, Java/Kotlin target 17 — correct
- `AndroidManifest.xml`: no permissions declared, share sheet + process text filters — correct

**Build executes successfully** with JDK 21 (Android Studio JBR) and Android SDK 35:

```bash
export JAVA_HOME='C:/Program Files/Android/Android Studio/jbr'   # Windows bash
./gradlew assembleDebug        # -> app/build/outputs/apk/debug/app-debug.apk
./gradlew testDebugUnitTest    # -> 144 tests, 0 failures
```

## Recommendations for Challenge Submission

1. **Obtain production dataset**: UCI SMS Spam Collection or Mendeley smishing dataset
2. **Train production model**: `python tools/sms_classifier/train.py --data data/labeled.csv --output app/src/main/assets/sms_classifier_model.json`
3. **Replace test fixture**: Update ViewModel to load production model asset
4. **Test on device**: Install debug APK on ARM Android device, verify offline functionality
5. **Benchmark**: Measure end-to-end latency, memory, CPU on target device

## Challenge Submission Readiness

**Code**: Complete — all 9 phases addressed, detection pipeline functional
**Build**: Working — debug APK builds
**Tests**: 144 JVM unit tests, all passing
**APK**: Generated — `app/build/outputs/apk/debug/app-debug.apk`
**Documentation**: Complete
