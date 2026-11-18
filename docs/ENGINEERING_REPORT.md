# Technical report — ARM Digital Safety Guardian

Last updated 2026-11-18 (v2.0.0 + roadmap phases 2–4). Hackathon theme: Cybersecurity & Digital Safety —
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
| Malware / risky-app behaviour | Apps tab | Installed-app scan: sideloading, SMS + accessibility + overlay combos, device admin, hidden icon |
| Network safety (planned) | Protection tab | Wi-Fi security, captive portal, DNS, VPN, USB debugging — designed, not built |
| Network intrusion classification | Raspberry Pi 5 / PC companion (`tools/network_ids`) | NSL-KDD MLP, per-flow plain-language explanation, optional Llama runner |
| Languages / themes | Settings | English, Hindi, Tamil; light/dark/system |

Everything runs on the device. The only network use is the optional one-time download of the Llama model
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
   (plain reasons)  (highlight spans)      (verdict-aware prompt)      streamed, 150-token cap
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
| Context | 2048 tokens; fresh context per explanation (`resetContext`) |
| Output limit | 150 new tokens, streamed to the UI |
| Gatekeeping | `CpuSupport` (64-bit process + Armv8.1 LSE atomics in `/proc/cpuinfo`); otherwise the fixed localized explanation |
| Safety | `AdviceGuard` removes click/call/reply/share advice unless negated, URLs, phone numbers, refusals and verdict contradictions; softens absolute claims; caps at 6 sentences; always appends the 3 safe steps |

Why SpinQuant INT4: our own fp32-embedding export was 1.7 GB. SpinQuant is 1.14 GB, keeps answer quality on
these short prompts and runs at 9–13 tok/s on mid-range phones. The model is **not bundled** in the APK because
ExecuTorch needs a real file and bundling stored it twice (APK + extracted copy, 3.5 GB). The release APK is 13.5 MB.

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
- `tools/network_ids`: numpy/scipy only, so it runs on a Raspberry Pi 5 CPU. Input is NSL-KDD 41-feature flows.
- One-hot protocol/service/flag, log1p on heavy columns, z-score, MLP 122 → 64 → 5 (normal, dos, probe, r2l, u2r),
  class-weighted cross-entropy, L-BFGS.
- KDDTest+ (the harder official test set): accuracy 78.0 %, attack detection 70.9 %, false alarms 7.2 %;
  DoS recall 0.86, probe 0.64, r2l 0.20, u2r 0.52. Inference 0.03 ms per flow.
- `detect.py` prints a verdict, a plain-language meaning, the top 3 features (gradient × input) and 3 remediation
  steps for each flow. `--llama-cmd` pipes a short prompt to an ExecuTorch `llama_main` runner on the Pi.
- Not implemented: live capture → NSL-KDD feature extraction (would use Zeek/argus connection logs).

## 5. On-phone app and network checks (roadmap 3.1, 3.2 B)
**Apps tab (done).** `InstalledAppsCollector` reads installed packages, installer, requested permissions,
launcher icon, active device admins, enabled accessibility services and notification listeners. Nothing leaves the phone.
`AppRiskScorer` is pure Kotlin and unit tested:
- Findings: SIDELOADED (installer not Play or a known OEM store), READS_SMS, ACCESSIBILITY_CONTROL, SCREEN_OVERLAY,
  DEVICE_ADMIN, HIDDEN_ICON, INSTALLS_APPS, READS_NOTIFICATIONS.
- Combinations: SMS + accessibility (banking trojan) and accessibility + overlay (remote-access scam).
- Levels: Dangerous / Check this app / Safe. System apps and ARM itself are always Safe.
- Each finding has one plain sentence (en/hi/ta) and two actions: App settings and Uninstall.
- Not device-tested yet.

**On-phone network check (not done).** Designed in `models/TASK_G2_NETWORK_CHECK.md`: open/WEP Wi-Fi, captive
portal, unvalidated network, non-standard public DNS, USB debugging, unknown VPN. The implementation run was stopped
when the PC ran low on memory, and nothing was written.

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

## 7. Privacy
- No message leaves the phone. No analytics, no accounts.
- Only risky SMS alerts of the current day are stored (Today tab); everything else stays in memory.
- The app scan reads only local system state (package manager, secure settings).
- `INTERNET` is used only for the optional model download.
- Release builds are signed with a private key kept outside the repository (`keystore.properties`, git-ignored).

## 8. Testing
- JVM unit tests: 321 tests, 0 failures (`./gradlew testDebugUnitTest --offline`).
- Instrumented tests: 17 (intent ingestion, device benchmark, stress/accuracy, Llama) — run on 3 phones on 2026-11-17.
- Python: SMS evaluation (`tools/eval/evaluate.py`), URL parity file, NIDS metrics (`tools/network_ids/out/metrics.json`).

## 9. Known limits
- Tamil/Tanglish SMS data is thin; Hindi/Tamil Llama is experimental and has not had the 20-message check (roadmap 1.5).
- Not yet run on an Armv8.0 phone (roadmap 1.6); such phones get the fixed explanation.
- The URL model's recall is modest (0.61); it is tuned for few false alarms. There is no ExecuTorch variant yet (see 4.3).
- NIDS trained on NSL-KDD (1999-era traffic); r2l/u2r recall is low; no live capture yet.
- The app scanner relies on `QUERY_ALL_PACKAGES`, which Google Play restricts. Sideloaded distribution is fine.
- The public model download URL is not configured (owner's choice).
