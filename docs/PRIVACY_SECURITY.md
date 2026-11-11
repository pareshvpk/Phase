# Privacy & Security Architecture

## Privacy Principles

1. **Zero network access**: All detection runs entirely on-device. No SMS content, URLs, or user data is ever transmitted.
2. **No SMS permissions**: The app does not request `READ_SMS` or `RECEIVE_SMS`. Messages are only analyzed when the user manually enters them or shares them via the Android share sheet / process text.
3. **No analytics**: No analytics SDKs, no telemetry, no message-content logging.
4. **No automatic URL execution**: Extracted URLs are displayed for inspection only. They are never clicked, opened, or visited.
5. **Original message preservation**: The original input is always preserved unchanged in `AnalysisInput.messageText`. Normalization produces a separate representation for analysis.
6. **Local model only**: The SMS classifier model is loaded from app assets (bundled APK), not downloaded.

## Permission Audit

| Permission | Declared? | Used? | Required? | Rationale |
|------------|-----------|-------|-----------|-----------|
| `INTERNET` | Yes (`android:required="false"`) | No | No | Declared but unused; retained for future optional features. Never used for detection. |
| `READ_SMS` | No | No | No | Not requested. SMS content only enters via manual entry or share sheet. |
| `RECEIVE_SMS` | No | No | No | Not requested. No background SMS collection. |
| `SEND_SMS` | No | No | No | Not requested. |

## Data Flow

```
User input (manual / share sheet / process text)
        ↓
InputAdapter (validates, truncates by code points)
        ↓
InputNormalizer (NFC normalize, extract URLs/phones, detect invisible chars)
        ↓
FastRuleEngine (deterministic pattern matching, offline)
        ↓
UrlSpecialistDetector (offline URL heuristics, no DNS/HTTP)
        ↓
SmsSpecialistClassifier (pure Kotlin logistic regression, model from assets)
        ↓
RiskPolicyEngine (authoritative verdict, deterministic scoring)
        ↓
UI (verdict, evidence, recommended actions)
```

All steps execute in-process on the Android device. No data leaves the device.

## Data Storage

- No message persistence: Input is held in memory only (ViewModel state). No database, no file storage, no SharedPreferences for message content.
- Model asset: `sms_classifier_model_test_fixture.json` is bundled in the APK. It is a synthetic test fixture, not trained on real user data.
- No caching of analyzed messages across app restarts.

## URL Safety

- URLs are extracted via `java.net.URI` parsing (offline).
- Extracted URLs are displayed as plain text only — not clickable links.
- No DNS resolution, no HTTP requests, no URL following.
- URL specialist detection is purely heuristic (IP-based, shorteners, suspicious TLDs, homographs, etc.).

## Model Safety

- The shipped model is a **synthetic test fixture** explicitly labeled `NOT FOR PRODUCTION USE`.
- It was generated from a 30-row sample dataset for development and testing only.
- No real user data was used in training the fixture model.
- Production models must be generated via `tools/sms_classifier/train.py` with properly licensed data.

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Network exfiltration of SMS content | No INTERNET usage; no networking code in detection pipeline |
| SMS interception | No SMS permissions; no background SMS receiver |
| Malicious URL execution | URLs never made clickable; never opened automatically |
| Data persistence | No local storage of message content |
| Model supply chain attack | Model loaded from app assets only; signature-verified APK installation |

## Compliance

- GDPR: No personal data collected or transmitted
- No third-party SDKs
- No advertising ID access
- No Firebase/Google Analytics integration
