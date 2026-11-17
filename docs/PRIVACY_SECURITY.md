# Privacy & Security Architecture

## Privacy Principles

1. **Zero network access**: All detection runs entirely on-device. No SMS content, URLs, or user data is ever transmitted.
2. **Optional, opt-in SMS protection**: The app does not read the SMS inbox. `RECEIVE_SMS` is requested only when the user turns on "Protect incoming SMS" and may be revoked at any time. When enabled, newly received SMS is analyzed on-device only and message text is never logged. With the feature off, messages are only analyzed when the user manually enters them or shares them via the Android share sheet / process text. OTP, transaction and login-credential messages are recognised by a small local pattern check and dropped before analysis; they are not analyzed, shown, stored or logged. There are two exceptions, both still analyzed: a message that asks the user to share or send a code, PIN or password, and a message that combines a link with reward wording (receive, claim, win, prize and similar).
3. **No analytics**: No analytics SDKs, no telemetry, no message-content logging.
4. **No automatic URL execution**: Extracted URLs are displayed for inspection only. They are never clicked, opened, or visited.
5. **Original message preservation**: The original input is always preserved unchanged in `AnalysisInput.messageText`. Normalization produces a separate representation for analysis.
6. **Local model only**: The SMS classifier model is loaded from app assets (bundled APK), not downloaded.

## Permission Audit

The manifest declares only two permissions, both used solely by the optional SMS protection feature.

| Permission | Declared? | Used? | Required? | Rationale |
|------------|-----------|-------|-----------|-----------|
| `INTERNET` | No | No | No | Not requested — the app makes no network calls of any kind. |
| `RECEIVE_SMS` | Yes | Opt-in | No | Only used when the user enables "Protect incoming SMS". The receiver exits immediately when the preference is off. |
| `POST_NOTIFICATIONS` | Yes | Opt-in | No | Used only to post local alerts for suspicious or high-risk SMS when SMS protection is enabled. |
| `READ_SMS` | No | No | No | Not requested. The app never reads the SMS inbox or message history. |
| `SEND_SMS` | No | No | No | Not requested. |
| Storage | No | No | No | Only the `sms_protection_enabled` boolean in `SharedPreferences` and the app-private same-day `today_alerts.json` file (flagged messages only, deleted after the local day ends) are written. No database is used. |

## Data Flow

```
User input (manual / share sheet / process text)
        ↓
InputAdapter (validates, truncates by code points)
        ↓
ThreatAnalyzer (shared, reusable pipeline)
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

Incoming SMS (only when opt-in is enabled)
        ↓
IncomingSmsReceiver (multipart bodies joined per sender, goAsync)
        ↓
ThreatAnalyzer (same pipeline, background single-thread executor)
        ↓
SmsAlertPolicy (HIGH_RISK / SUSPICIOUS only; SAFE and INSUFFICIENT_EVIDENCE are silent)
        ↓
Local high-importance notification (title contains sender; body contains no message text)
```

All steps execute in-process on the Android device. No data leaves the device.

## Data Storage

- Manual, shared and pasted input is held in memory only (ViewModel state). It is never written to disk.
- The single persisted setting is the boolean `sms_protection_enabled` in the `sms_protection` preferences file.
- **Same-day flagged SMS list**: when SMS protection is enabled and an incoming message is flagged as SUSPICIOUS or HIGH_RISK, its sender, text (truncated to 1,000 characters) and plain-language reason ids are written to the app-private file `filesDir/today_alerts.json`. This file feeds the "Today" tab. It is excluded from cloud backup and device transfer, never leaves the device, and is deleted automatically once the local day ends (the store prunes expired entries on every read or change). Safe messages and skipped OTP/bank/login messages are never written to this file.
- Model asset: `sms_classifier_model.json` is bundled in the APK. It is trained only on public, licence-compatible datasets (sources and licences in its `training_info.note`), never on user messages.
- No caching of analyzed messages across app restarts beyond the same-day flagged list described above.

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
| SMS interception | SMS protection is opt-in and off by default; the receiver exits immediately when disabled. No SMS content is logged or transmitted. Only flagged messages are kept in app-private storage until the local day ends. |
| Malicious URL execution | URLs never made clickable; never opened automatically |
| Data persistence | Message content is held in memory, except flagged SMS needed for the Today tab, which is app-private, excluded from backup and deleted after the local day ends. |
| Model supply chain attack | Model loaded from app assets only; signature-verified APK installation |

## Compliance

- GDPR: No personal data collected or transmitted
- No third-party SDKs
- No advertising ID access
- No Firebase/Google Analytics integration
