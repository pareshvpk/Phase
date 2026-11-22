# Technical report — ARM Digital Safety Guardian

Updated 20 November 2026. Hackathon theme: Cybersecurity & Digital Safety —
on-device AI on Arm hardware, no cloud, with a Llama-family model running through ExecuTorch.

## 1. What ARM does

ARM is an offline Android app (Kotlin + Jetpack Compose, `com.arm.threatassistant`, minSdk 26, targetSdk 35)
that protects non-expert users from scams and digital threats:

| Capability | Where | How |
|---|---|---|
| Scam SMS detection | Check tab, incoming-SMS alerts, Today tab | Rules + TF-IDF/logistic-regression SMS model + risk policy |
| Phishing URL detection | Inside every check | URL rules + on-device host model (char n-grams) |
| Plain-language explanation + safe steps | Result screen | **Llama 3.2 1B Instruct, SpinQuant INT4, via ExecuTorch on the Arm CPU**, behind an advice guard; fixed localized text as fallback |
| Risky-word highlighting | Result screen | Rule matches and flagged links highlighted in the message |
| App access review | Protection tab | Explicit local checks of enabled accessibility providers, capability changes and granted SMS access |
| Network intrusion classification | Raspberry Pi 5 / PC companion (`tools/network_ids`) | NSL-KDD MLP, per-flow plain-language explanation, optional Llama runner |
| Languages / themes | Settings | English, Hindi, Tamil; light/dark/system |

Android detection and explanation run on the phone. The network companion runs on a separate host. The Android app uses internet access only for an optional one-time download of the Llama model
(the download URL is not configured yet; the model is copied by adb for now).

## 2. Architecture

```
SMS / share sheet / paste / process-text
        │
        ▼
InputNormalizer (NFC, invisible chars, URL/host/phone extraction)
        │
        ├─► FastRuleEngine ──────────────┐  ~100 regex rules in 5 categories (urgency, credentials,
        │                                │  bank impersonation, payment demand, account suspension)
        ├─► UrlSpecialistDetector ───────┤  10 URL rule categories + ML_PHISHING_HOST (host model)
        ├─► SmsSpecialistClassifier ─────┤  TF-IDF (1–2 grams, 10k vocab) + logistic regression
        ▼                                ▼
                 RiskPolicyEngine  →  SAFE / SUSPICIOUS / HIGH_RISK / INSUFFICIENT_EVIDENCE
                          │
           ┌──────────────┼──────────────────────────┐
           ▼              ▼                          ▼
   ReasonMapper     RiskHighlighter        ExplanationPromptBuilder → Llama (ExecuTorch) → AdviceGuard
   (plain reasons)  (highlight spans)      (verdict-aware prompt)      streamed, 70-token cap
```

- `ThreatAnalyzer` is the single entry point for the UI and the SMS receiver. The SMS and URL models are loaded
  once (synchronized, lazy) and **preloaded on a background thread at app start**, so the first check is fast.
- `SmsAlertPolicy` decides notifications. Registered TRAI DLT business senders (`AX-HDFCBK`, `JD-AMAZON-T`) only
  alert on a high-severity rule or a confident model scam verdict, never on links alone.
- `SensitiveSmsFilter` skips OTP/bank messages that are private and harmless, but never prize/lottery or
  "credited… join" link scams.

## 3. Llama on ExecuTorch

| Item | Value |
|---|---|
| Model | Llama 3.2 1B Instruct, SpinQuant INT4 weights, 8-bit embeddings (EO8), from `executorch-community` |
| File | `llama3_2_1b.pte` 1,135,951,488 bytes (size and SHA-256 are pinned in `gradle.properties`) |
| Runtime | `executorch-android` 1.5.1 AAR, `LlmModule`, XNNPACK kernels on the Arm CPU |
| Context | 2048 tokens. The fixed system prompt (prefix) is prefilled once and kept in the KV cache; each message only processes its own tail, then the prefix is restored in the background (`resetContext` + `prefillPrompt`). Falls back to the full prompt if prefill fails. Loaded with `LOAD_MODE_MMAP` |
| Preload | `LlmExplainerProvider.warmUp` from `Application.onCreate` (after 2 s, only on phones with ≥ 6 GB RAM); released on `onTrimMemory` RUNNING_CRITICAL/COMPLETE |
| Output limit | Greedy (temperature 0), at most 70 new tokens, stops after 2 sentences (`SentenceLimiter`); the 3 fixed safe steps are added by the app, not the model. Per-call stats logged under `ARMLLM` |
| Gatekeeping | `CpuSupport` (64-bit process + Armv8.1 LSE atomics in `/proc/cpuinfo`); otherwise the fixed localized explanation |
| Safety | `AdviceGuard` removes click/call/reply/share advice and "type/open/copy the link" advice unless negated, URLs, phone numbers, refusals and verdict contradictions; softens absolute claims; caps at 6 sentences; always appends the 3 safe steps |

Why SpinQuant INT4: our own fp32-embedding export was 1.7 GB. SpinQuant is 1.14 GB, keeps answer quality on
these short prompts and runs at 9–13 tok/s on mid-range phones. The default APK uses separate model files because
ExecuTorch needs a real file and bundling stored it twice (APK + extracted copy, 3.5 GB). The submission checklist describes separate model provisioning.

Hindi/Tamil Llama output is experimental (switch off by default). Llama always passes through the advice guard,
and the localized fixed text is used whenever the guard rejects an answer.

## 4. Detection models and data

### 4.1 SMS model (v2.0.0)
- Data: 8 public sources (UCI SMS Spam, Mendeley smishing, carnageiron, CloveAI sample, anmolshrivastav
  14-language, Ridham115 and others; licences in `tools/sms_classifier/data/manifest.json`), de-duplicated,
  template-grouped split (`tools/sms_classifier/build_dataset.py`).
- Model: TF-IDF (min-df 2, 10k features) + L2 logistic regression (L-BFGS), 490 KB JSON, pure-Kotlin inference.
- Test F1 0.96. Real-message-only: recall 0.91, false-alarm rate 0.7 % at the 0.60 confidence policy threshold.
- Weak spot: Tamil/Tanglish (about 90 synthetic rows).

### 4.2 Rules
Roadmap 2.5 added nine groups: OTP/PIN sharing without "your/the", UPI collect requests, APK installs, digital
arrest / fake police, refund lures, task/profit jobs, electricity disconnection, courier/customs, and Hinglish
urgency. Two false-alarm traps were found and fixed with the held-out set:
- a bare `apk` substring matched the Hinglish word "aapka" in 25 normal messages, so the rule is now word-bounded;
- "never / do not share OTP", found in nearly every real bank OTP, is excluded by a negative look-behind.

### 4.3 Phishing URL host model (roadmap 2.4)
- Data: PhiUSIIL (UCI, CC BY 4.0, 235,795 URLs; **label 1 = legitimate**) plus Tranco top-30k domains and a
  list of Indian bank/government/shopping sites as benign. Free-hosting/CDN/shortener parents are excluded.
- Host-only: PhiUSIIL's benign URLs are bare homepages, so a model that sees paths learns "has a path = phishing".
- Char 3–5-grams of `^host$`, TF-IDF (20k vocab), logistic regression; threshold set for precision ≥ 0.98 on val.
- Test (36,758 hosts): precision 0.980, recall 0.609, FPR 0.64 %. On held-out SMS links: 1/56 normal hosts flagged,
  37/268 scam hosts flagged. Used as a MEDIUM supporting signal, never alone.
- Kotlin port (`UrlHostModel.kt`) matches Python within 1e-4 on 40 parity hosts (unit test).
- **ExecuTorch for this model was planned (char-CNN `.pte`) but not possible this round**: Windows Application
  Control now blocks the torch DLLs on the development PC, so no local `.pte` export can run. Llama remains the
  ExecuTorch workload.

### 4.4 Network intrusion companion (roadmap 3.2 A)
- `tools/network_ids`: numpy/scipy only, for CPU inference on a PC or Raspberry Pi 5. Input is NSL-KDD 41-feature flows.
- One-hot protocol/service/flag, log1p on heavy columns, z-score, MLP 122 → 64 → 5 (normal, dos, probe, r2l, u2r),
  class-weighted cross-entropy, L-BFGS.
- KDDTest+ (the harder official test set): accuracy 78.0 %, attack detection 70.9 %, false alarms 7.2 %;
  DoS recall 0.86, probe 0.64, r2l 0.20, u2r 0.52. Inference 0.03 ms per flow.
- `detect.py` prints a verdict, a plain-language meaning, the top 3 features (gradient × input) and 3 remediation
  steps for each flow. `--llama-cmd` pipes a short prompt to an ExecuTorch `llama_main` runner on the Pi.
- The passive monitor reads Ethernet classic PCAP files or captures on a Linux AF_PACKET interface. It aggregates IPv4 TCP/UDP packets into bounded flows. Some NSL-KDD features cannot be observed and are imputed. The monitor independently flags a source contacting at least 10 ports on one device within 60 seconds and flows reaching 1,000 packets/s over at least one second. The output explains the observation and suggests checks. Host checks use synthetic traffic. KDDTest+ metrics above apply only to benchmark rows. Accuracy on current networks and operation on Pi hardware await measurement.

## 5. On-phone network check (removed)
An on-phone network check (Wi-Fi security, captive portal, DNS, USB debugging, VPN) was built and device-tested on
2026-11-18 (commit e5e914f) and removed on 2026-11-19 because the competition does not require it. Network intrusion
detection is covered by the Pi/PC companion in section 4.4. The app no longer asks for ACCESS_NETWORK_STATE or
ACCESS_WIFI_STATE.

## 6. Measurements (from `benchmarks/DEVICE_REPORT_2026-11-17.md`)

| Phone | SoC | Result |
|---|---|---|
| vivo V2338 (Android 16) | Snapdragon, 64-bit | 17/17 instrumented tests pass; Llama 9–13 tok/s, first token ~5 s, PSS 1.31 GB |
| Samsung Galaxy M13 5G | Dimensity 700, 32-bit-only userspace | 15 pass / 2 skipped (no Llama: ExecuTorch has no armeabi-v7a); monkey 5k events, 0 crash |
| vivo I2605 (Android 16, 8 GB) | Dimensity 7300 | 17/17 pass; Llama 12–13 tok/s, first token 3.5–4.4 s; monkey 15k events, 0 crash/ANR |

- End to end on real messages: 90.1 % of scams caught, 0.7 % false alerts.
- Detection latency: median 2.2 ms (vivo V2338), 3.5 ms (Samsung). Release cold start ~285–330 ms.
- Thermal: continuous Llama generation pushed skin temperature to 46 °C (thermal status 3). Explanations are
  short and one at a time for this reason.
- These measurements are from v2.0.0. The features added on 2026-11-18 (sections 4.2–5) have unit tests only and
  still need a device run.

### Llama speed after the prefix cache (vivo V2338, 2026-11-19, `LlmDeviceTest`)

| | Before (2026-11-17) | After | PS3 Sentinel (same phone) |
|---|---|---|---|
| First token (model loaded, prefix cached) | 4.1–5.3 s | 2.0 s | 1.27 s (median) |
| Full answer | 12–14 s | 4.3 s | 6.3 s (median) |
| Decode | 9.7–11 tok/s | 10.7–11.9 tok/s | 14.4–14.8 tok/s |
| Prefill | ~55 tok/s | 58–68 tok/s | – |

Cold first call in a fresh process (model still loading): ~9 s to first token. The XNNPACK pool is resized to the
big-core count (4 on this phone) between `LlmModule` creation and `load()`; resizing after `load()` hung generation.
All 18 instrumented tests pass on the vivo after the change.

## 7. App review and message privacy

Protection opens a local review of enabled accessibility services. It inspects service capabilities and granted SMS access for combinations worth checking. A legitimate assistive app can need these capabilities. The findings describe access and offer a route to Android settings. They do not establish malware infection. The user selects Check now to record a local baseline or compare changes. Reset clears that baseline. Package visibility is scoped to accessibility service providers.

Incoming protection is opt-in. SMS comes from delivery broadcasts. MMS processing uses the local provider to retrieve text parts. Flagged incoming content can appear in the app-private Today list. Manual checks, URL analysis and Llama explanations work offline. See [Privacy and security](PRIVACY_SECURITY.md).

## 8. Validation and limitations

Release 2.1.0 host validation on 21 November passed 362 JVM tests and 19 Python
tests, debug/instrumentation/release builds and lint (0 errors, 30 warnings).
The release signing certificate was verified. See the
[exact release validation record](VALIDATION_2026-11-21.md).

The 19 November vivo V2338 debug run passed 18 instrumented tests and generated Llama output with airplane mode on and Wi-Fi off. Across 56 deliberately balanced examples, ARM warned on 24 of 28 risky messages and two of 28 routine messages. A separate receiver-policy evaluation warned on 292 of 324 scams and seven of 955 safe messages among rows marked real. These samples measure different paths. The notification check used a synthetic publisher event. See the [device report and raw evidence](../benchmarks/vivo_comparison_2026-11-19/REPORT.md).

The historical results predate the latest app review, onboarding and MMS changes. Current release installation, genuine SMS/MMS delivery, permission changes, accessibility review and recording remain device gates. The local provisioning helper checks model size and both SHA-256 pins before transfer. See the [submission checklist](SUBMISSION_CHECKLIST.md).

Tamil/Tanglish data is sparse. Hindi/Tamil generation and the Armv8.0 fallback still need device review. The URL classifier prioritizes precision and misses many phishing hosts. The companion model was trained on historical NSL-KDD records and its rare attack classes have low recall. Packet-derived inputs have additional feature gaps. There is no current-device field accuracy estimate.
