# Architecture

ARM Digital Safety Guardian is built in phases. Each phase delivers a vertically
sliced capability. Threat detection begins at Phase 3 and the authoritative
verdict is produced by the RiskPolicyEngine at Phase 4.

## Detection Pipeline

```
AnalysisInput → InputNormalizer → FastRuleEngine → UrlSpecialistDetector → SmsSpecialistClassifier → RiskPolicyEngine → Verdict
```

All stages run offline on the device. No network access, no DNS lookups, no
HTTP requests. The LLM never participates in the security decision.

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

## Phase 1 — Foundation (complete)

Domain models and a placeholder analysis action.

- `AnalysisInput` — user-supplied text.
- `AnalysisResult` — outcome of an analysis run (verdict nullable).
- `AnalysisStatus` — IDLE / ANALYZING / COMPLETED / ERROR.
- `ThreatVerdict` — SAFE_UNVERIFIED / SUSPICIOUS / HIGH_RISK / INCONCLUSIVE / UNSUPPORTED_INPUT.
- `ThreatAnalysisViewModel` — orchestrates the detection pipeline and holds UI state.

## Phase 2 — Input Ingestion and Normalization (complete)

Ingests input from multiple sources and normalizes it for subsequent analysis.
No threat verdict or risk scoring is produced.

### Ingestion path

1. User enters/pastes text in `MessageInput`, or content arrives via
   `ACTION_SEND` (share sheet) or `ACTION_PROCESS_TEXT` (process text).
2. `MainActivity` extracts intent-sourced text using `ShareSheetAdapter` or
   `ProcessTextAdapter`, producing an `AnalysisInput` tagged with the
   `InputSource`.
3. `ThreatAnalysisViewModel.onAnalyze()` (manual) validates input via
   `ManualInputAdapter`; `onIngestedInput()` (intent) receives text already
   adapted by `ShareSheetAdapter` / `ProcessTextAdapter`. Both then pass the
   `AnalysisInput` to `InputNormalizer`.
4. The UI renders the normalized preview, extracted URLs, extracted phone
   numbers, and normalization warnings.

### InputNormalizer responsibilities

- Preserves the original input (`AnalysisInput.messageText`).
- Applies Unicode NFC normalization.
- Detects (records only) zero-width / invisible Unicode characters; never
  removes them silently.
- Extracts URLs and parses them with `java.net.URI`; extracts hostnames
  separately.
- Extracts phone numbers (best effort).
- Handles malformed URLs and extremely long text without crashing.
- Never truncates inside a UTF-8 multi-byte sequence.
- Performs no classification, no network access, and no link execution.

### Adapters

- `ManualInputAdapter` — manual/paste input, rejects blank input, 5000 code-point limit.
- `ShareSheetAdapter` — `ACTION_SEND` text/plain ingestion.
- `ProcessTextAdapter` — `ACTION_PROCESS_TEXT` text/plain ingestion.

## Phase 3A — Deterministic Rule Detection (FastRuleEngine) (complete)

Package: `com.arm.threatassistant.domain.detection.ruleengine`

`FastRuleEngine` is a deterministic, offline rule engine that detects suspicious
SMS patterns across five categories and returns structured detection signals.
It does NOT produce a security verdict.

37 rules are defined as data in a single `RULES` list.

### Rule categories

| Category | Rule IDs | Severity | Description |
|----------|----------|----------|-------------|
| URGENCY_AND_COERCION | urg_001 – urg_007 | HIGH / MEDIUM | Immediate action, account blocked, urgent verification, 24-hour deadline, time pressure. |
| CREDENTIAL_REQUEST | cred_001 – cred_008 | HIGH / MEDIUM | Password entry, credential verification, OTP sharing, PIN confirmation, login detail updates. |
| FINANCIAL_IMPERSONATION | fin_001 – fin_007 | MEDIUM | Bank impersonation, payment service team, government payment, customer support, financial institution. |
| PAYMENT_DEMAND | pay_001 – pay_008 | HIGH / MEDIUM | Immediate payment, transfer to avoid penalties, processing fees, outstanding payments, refund fees. |
| ACCOUNT_SUSPENSION | susp_001 – susp_007 | HIGH | Account suspension/deactivation, KYC expiration, SIM blocking, service termination. |

### Design principles

- Rules are defined as data (not hardcoded conditionals).
- Matching is case-insensitive and tolerant of punctuation/whitespace variations.
- Broad single-word terms never fire alone; only multi-word phrases match.
- All relevant matches are returned; never stops at the first match.
- Duplicate signals for the same rule and matched span are suppressed.

## Phase 3B — SMS Specialist Classifier (complete, test fixture model)

Package: `com.arm.threatassistant.domain.detection.smsclassifier`

`SmsSpecialistClassifier` is a pure-Kotlin, CPU-only, fully offline logistic
regression classifier with TF-IDF features. It runs alongside `FastRuleEngine`
and produces structured evidence without producing a security verdict.

### Components

- `SmsClassifierStatus` — AVAILABLE / UNAVAILABLE / ERROR / UNSUPPORTED_INPUT.
- `SmsClassifierResult` — evidence container (label, score, model version, contributing features, error info).
- `SmsTextPreprocessor` — NFC normalization, lowercasing, tokenization, unigram + bigram generation.
- `TfIdfVectorizer` — raw-count TF × pre-computed IDF, L2-normalized, aligned to model vocabulary; out-of-vocabulary single words fall back to simple suffix stripping (`ies`, `ing`, `ed`, `es`, `s`).
- `SmsClassifierModel` — in-memory model with validation on load.
- `SmsClassifierModelLoader` — loads model from JSON asset using `org.json`.
- `SmsSpecialistClassifier` — inference entry point. Sigmoid output mapped to [0.0, 1.0].

### Inference math

- TF = raw term frequency
- IDF = smooth_idf = log((n_docs + 1) / (df + 1)) + 1
- TF-IDF = TF × IDF, L2-normalized
- Score = w · x + b; probability = sigmoid(score)
- Label = THREAT if probability >= threshold else SAFE

### Model artifact

JSON format stored in `app/src/main/assets/`. A synthetic test fixture model
(`sms_classifier_model_test_fixture.json`) is shipped for development and
testing. It is explicitly **NOT FOR PRODUCTION USE**. A production model must
be generated by `tools/sms_classifier/train.py` using real, licensed data.

## Phase 3B+ — URL Specialist Detector (complete)

Package: `com.arm.threatassistant.domain.detection.urldetection`

`UrlSpecialistDetector` inspects URLs extracted from input text and produces
structured detection signals. Operates entirely offline — no DNS lookups, no
HTTP requests, no URL visits.

### Detection categories

| Category | Severity | Description |
|----------|----------|-------------|
| IP_BASED_URL | HIGH | URL uses an IP address literal instead of a domain name. |
| URL_SHORTENER | MEDIUM | Domain is a known URL shortener (bit.ly, tinyurl.com, etc.). |
| SUSPICIOUS_TLD | MEDIUM | TLD commonly abused in phishing (e.g. xyz, top, club, cf, ga, gq, ml, tk). |
| HOMOGRAPH_ATTACK | HIGH | Domain mixes scripts (Latin + Cyrillic/Greek) or uses look-alike characters. |
| SUSPICIOUS_SUBDOMAIN | MEDIUM | Excessive subdomain depth used to mimic legitimate brands. |
| MISLEADING_STRUCTURE | HIGH | URL structure designed to confuse (e.g. @ in userinfo). |
| UNUSUAL_PORT | MEDIUM | Non-standard port for the scheme. |
| ENCODED_CHARACTERS | LOW | Percent-encoded characters that may obfuscate the destination. |
| SUSPICIOUS_DOMAIN | MEDIUM | Domain contains suspicious keywords (secure, verify, account, etc.). |
| EXCESSIVE_LENGTH | LOW | Unusually long URL. |

## Phase 4 — Risk Policy Engine (complete)

Package: `com.arm.threatassistant.domain.detection.riskpolicy`

`RiskPolicyEngine` is the authoritative decision-making component. It combines
rule detection evidence, SMS classifier score, and URL specialist evidence into
a deterministic threat verdict.

### Verdict levels

| Verdict | Meaning |
|---------|---------|
| SAFE | Some evidence exists but below all risk thresholds. |
| SUSPICIOUS | Moderate aggregate score or single high-severity signal. |
| HIGH_RISK | High aggregate score (>= 0.65) or 3+ high-severity rule signals. |
| INSUFFICIENT_EVIDENCE | No meaningful evidence or input error. |

### Decision principles

- No single keyword is sufficient proof of fraud.
- Classifier confidence must reach 0.60 to influence the verdict.
- Conflicting evidence is resolved conservatively (lean toward SUSPICIOUS).
- Every verdict is accompanied by an explainable evidence summary.
- Decisions are deterministic and reproducible.
- The LLM never overrides this engine.

### Contribution weights

| Evidence Type | Weight |
|--------------|--------|
| Rule HIGH severity | 0.25 per signal |
| Rule MEDIUM severity | 0.12 per signal |
| Rule LOW severity | 0.05 per signal |
| Classifier threat score | 0.40 × score (if >= 0.60) |
| URL HIGH severity | 0.20 per signal |
| URL MEDIUM severity | 0.10 per signal |
| URL LOW severity | 0.05 per signal |

### Thresholds

| Threshold | Value | Meaning |
|-----------|-------|---------|
| HIGH_RISK | 0.65 | Score at or above = HIGH_RISK |
| SUSPICIOUS | 0.30 | Score at or above = SUSPICIOUS |
| SAFE | 0.05 | Score at or above = SAFE |
| Classifier min confidence | 0.60 | Minimum classifier score to influence verdict |
| Min rule signals | 1 | Any evidence (rule signal, URL signal, or confident classifier score) is required; otherwise INSUFFICIENT_EVIDENCE |

## Phase 5 — ExecuTorch Integration (evaluated, deferred)

Evaluated and deferred. The pure-Kotlin logistic regression classifier meets all
requirements (offline, deterministic, explainable, minimal binary size).
ExecuTorch is designed for PyTorch models (transformers, CNNs) and would add
~30-50MB runtime overhead without benefit for this lightweight model.

See `docs/EXECUTORCH_EVALUATION.md` for full evaluation.

## Phase 6 — UI (complete)

Package: `com.arm.threatassistant.presentation`

Seven UI areas delivered via `ThreatAssistantScreen` (with `SettingsScreen`
reachable from the top app bar):

1. **Home** — App title and navigation
2. **SMS/Message input** — `MessageInput` + `AnalyzeButton`
3. **Threat analysis** — `ResultArea`, `NormalizedInputPreview`, `ExtractedEntitiesSection`
4. **Threat verdict** — `RiskVerdictSection` (verdict level + risk score)
5. **Evidence and explanation** — `EvidenceSection` (detection evidence summary)
6. **Recommended actions** — `RecommendedActionsSection` (verdict-specific guidance)
7. **Settings and privacy** — `SettingsScreen` (privacy architecture, permissions)

Additional development components: `RuleDetectionSection`, `SmsClassifierSection`,
`UrlDetectionSection`.

## Privacy & Security

See `docs/PRIVACY_SECURITY.md`.

Key guarantees:
- No permissions declared in `AndroidManifest.xml` (no `INTERNET`, no SMS, no storage)
- No network requests
- No analytics, no message-content logging
- URLs never opened automatically
- Original message always preserved

## Versioned Evidence Schema

`AnalysisInput` is a plain, serializable Kotlin data class suitable for
embedding in a versioned evidence schema without Android-specific types.
The `AnalysisResult.verdict` field is populated by `RiskPolicyEngine`.
