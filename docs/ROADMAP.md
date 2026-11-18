# ARM roadmap

Last updated 2026-11-18 (see "Status 2026-11-18" at the end). Based on the hackathon brief (Cybersecurity & Digital Safety: Llama via ExecuTorch on
Arm, no cloud) and a comparison with PS3 Sentinel (github.com/Vishnu-3727/ps3-sentinel, Apache-2.0 — credit it
in NOTICE/README if any code or rules are reused).

Goal: keep ARM's clean consumer app (plain verdicts, Hindi/Tamil, Today tab, themes) and match or beat
Sentinel on detection quality, Llama/ExecuTorch depth, measurements and documentation, then add the
capability neither project has: network / malware detection.

Legend: **You** = needs the owner (accounts, phones, real messages, hardware). **Dev** = coding (opencode).

---

## Phase 1 — Llama: smaller, safer, always visible

| # | Task | Who | Done when |
|---|---|---|---|
| 1.1 | Switch to the ready-made ExecuTorch-community **Llama 3.2 1B SpinQuant INT4 (EO8)** `.pte` (~1.14 GB) instead of our 1.7 GB export. Download from Hugging Face with your token (repo `executorch-community/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8-ET` — confirm the name), put it in `models/` as `llama3_2_1b.pte`. No Colab needed. | You (download) + Dev | **Done (v2.0.0, 2026-11-17)** — SpinQuant INT4 EO8 `.pte` (1,135,951,488 B) runs on the vivo: max context 2048, ~9 tok/s, first token 5–10 s, PSS ~1.27 GB. Not bundled: APK 12.3 MB (release), model is the only data (~1.14 GB). App accepts only this size (`armLlmModelBytes`). Public download host still to be chosen (`armLlmModelUrl`). |
| 1.2 | Confirm Llama generates from the **APK-bundled** copy (USB copy already deleted). | Dev (phone free) | **Done (2026-11-17)** — generation verified from the app-stored copy (LlmDeviceTest on vivo, old and SpinQuant models); fixed KV-cache carry-over between explanations (`resetContext`). |
| 1.3 | **Advice guard** post-filter on Llama output: drop click/call/reply/share sentences (unless negated), drop URLs/phone numbers, replace refusals and verdict contradictions with the fixed localized explanation, soften absolute claims, cap at 6 sentences, always append the 3 safe steps. Unit tests with bad outputs. | Dev | **Done in code** — `llm/AdviceGuard.kt` + `AdviceGuardTest`; tests pass; wrong Hindi output now replaced by the template. |
| 1.4 | **Auto-explain**: run Llama automatically for HIGH_RISK / SUSPICIOUS (INSUFFICIENT_EVIDENCE shows "Be careful" too) when the model is Ready (streaming, progress indicator, 150-token cap, off main thread, one generation at a time); keep the button for SAFE results; cancel on new input / new result / leaving the Check tab. Settings switch "Explain scams automatically" (default ON). Starts automatically once Ready after install. | Dev | **Done in code** — `ThreatAnalysisViewModel.startAutoExplanation`, `CheckScreen` LaunchedEffects, AppSettings switch; UI stays responsive. |
| 1.5 | Retry **Hindi/Tamil Llama** behind the advice guard; keep the fixed text as fallback. Ship only if a 20-message check per language has 0 contradictions. | Dev + You (judge quality) | **Code done** — settings switch "AI explanations in Hindi/Tamil (experimental)" (default OFF, shown only for hi/ta), Llama with languageName Hindi/Tamil always passes through AdviceGuard with the localized fallback. **Not done** — 20-message quality check per language on a phone; pass/fail to be recorded in `docs/` (`tools/llm/eval_prompts.md` has the 60 messages). |
| 1.6 | **Older phones**: the stock `executorch-android` AAR uses Armv8.1 LSE atomics and SIGILLs on Armv8.0 CPUs. `llm/CpuSupport.kt` parses `/proc/cpuinfo`; unsupported devices get a new `LlmInstallStatus.Unsupported` state, skip the model install (saves storage), never load ExecuTorch native libs, and show the fixed localized explanation silently. | You (phone) + Dev | **Code done** — `CpuSupport.kt` (unit-tested with Armv8.0/Armv8.2 cpuinfo samples), `Unsupported` state wired into `LlmInstallState` and `LlmExplanationSection`. **Not done** — verify on an actual Armv8.0 phone; document the limit if it still fails. |

## Phase 2 — Detection quality (data + models)

| # | Task | Who | Done when |
|---|---|---|---|
| 2.1 | Collect **real messages from other phones** (scam + normal, incl. Hindi/Tamil/Hinglish/Tanglish), anonymise numbers/names, label safe/scam. Target ≥ 300, kept **test-only**. | You | CSV in a gitignored folder + labelling notes |
| 2.2 | Build the training set from `docs/DATASET_RESEARCH.md` (UCI, Mendeley smishing, carnageiron, CloveAI sample, anmolshrivastav 14-lang, Ridham115), de-duplicate, template-grouped split. | Dev | `tools/sms_classifier` produces a dataset manifest with licences |
| 2.3 | **SMS model**: (a) retrain the current TF-IDF + logistic regression on 2.2 (quick win), then (b) a small **multilingual transformer (e.g. MiniLM) exported to ExecuTorch int8** so ExecuTorch runs the detector too. Keep the one that wins on the real-message test set. | Dev | Report: F1, scam recall, false-alarm rate on 2.1, per language |
| 2.4 | **Phishing URL model**: character-CNN on PhiLegit-100K / PhiUSIIL + PhishTank, exported to **ExecuTorch**; wire into `UrlSpecialistDetector` alongside the rules. | Dev | Precision/recall on a held-out set; URL verdict used in the result |
| 2.5 | **Rule gaps**: "share OTP/PIN" → credential request; add UPI collect, APK install, digital arrest, refund, task/profit-group, electricity disconnection, courier/customs, Hinglish phrases. | Dev | Unit tests per rule; the SBI KYC sample shows "Asks for an OTP" |
| 2.6 | **Registered-sender rule**: for DLT business headers (e.g. `AX-HDFCBK`), don't alert on links alone; alert only on a model scam verdict or a high-risk rule. | Dev | Lower alert rate on real inboxes, recall unchanged on 2.1 |
| 2.7 | **Highlight risky words** in the message (clean style, no scores). | Dev | Highlights shown on the result screen |
| 2.8 | Test the **Today tab with a real incoming SMS** from another phone. | You (send SMS) + Dev | Alert + Today entry + tap-through verified |

## Phase 3 — New capability (neither project has it)

| # | Task | Who | Done when |
|---|---|---|---|
| 3.1 | **App / malware-behaviour scanner** (on phone, no root): sideloaded apps, risky permission combos (SMS + accessibility + overlay, device admin, hidden icon), Llama explains each finding, remediation (open settings / uninstall). New "Apps" area. | Dev | Scan runs offline; findings explained |
| 3.2 | **Network intrusion detection** — choose one: **A)** Raspberry Pi 5 companion (Scapy capture → flow features → model trained on CICIDS2017/UNSW-NB15 → Llama via ExecuTorch on the Pi explains), or **B)** on-phone local `VpnService` monitor of app connections (bad domains, unusual ports/volumes). | You (decide; Pi?) + Dev | Demo of a detected attack/anomaly with a Llama explanation |

## Phase 4 — Measure, polish, deliver

| # | Task | Who | Done when |
|---|---|---|---|
| 4.1 | **Benchmarks** on 2–3 phones: detection latency, Llama load / first token / tok/s, memory, energy per message, cold start; raw logs in `benchmarks/`. | Dev + You (phones) | Tables with sources |
| 4.2 | **Onboarding** (first launch: what ARM checks, privacy, turn on protection) and a privacy screen. | Dev | Shown once, skippable |
| 4.3 | **Release keystore + signed release APK** (also stops AVG "suspicious app" warnings). | You (keep the key safe) + Dev | Signed APK installs; no debug-key signing |
| 4.4 | **Technical report** update: architecture, ExecuTorch/Llama pipeline, quantization choices, datasets + licences, results, privacy, limits. | Dev | `docs/ENGINEERING_REPORT.md` current |
| 4.5 | **Demo video** script + recording (scam SMS arrives → alert → result → Llama explanation → Today tab → language/theme → network/malware demo). | Dev (script) + You (record) | Video file |
| 4.6 | Native-speaker review of Hindi/Tamil strings. | You | Corrections applied |

---

## Suggested order
1.1 → 1.2 → 2.5 → 1.3 → 1.4 → 2.1 (in parallel, owner) → 2.2 → 2.3 → 2.4 → 2.6 → 2.7 → 3.1 → 3.2 → 4.x.
Phase 1 and the rule fixes are small and visible; Phase 2 needs the real messages; Phase 3 is the differentiator.

---

## Status 2026-11-18

| # | Status |
|---|---|
| 2.4 | **Done, with a different model**: char n-gram TF-IDF + logistic-regression *host* model (PhiUSIIL + Tranco top-30k + Indian sites), test precision 0.98 / recall 0.61 / FPR 0.64 %, wired into `UrlSpecialistDetector` as `ML_PHISHING_HOST`. The ExecuTorch char-CNN was not possible: Windows Application Control now blocks the torch DLLs on the dev PC. |
| 2.5 | **Done**: 9 rule groups + unit tests; fixed `apk`→"aapka" and "never share OTP" false alarms. |
| 2.6 | **Done**: DLT business headers alert only on a high-severity rule or a confident model scam verdict. |
| 2.7 | **Done**: "What looks risky" card highlights rule matches and flagged links. |
| 3.1 | **Done in code**: Apps tab scanner (not device-tested yet). Llama explanation per finding not added (fixed plain sentences instead). |
| 3.2 | **Part A done**: `tools/network_ids` NSL-KDD MLP companion for Raspberry Pi 5/PC (KDDTest+ acc 78 %, detection 71 %, false alarms 7.2 %), plain-language + optional Llama runner. **Part B (on-phone network check) not built**: the run was stopped when the PC ran low on memory; the brief is `models/TASK_G2_NETWORK_CHECK.md`. |
| 4.2 | **Not done**: brief ready in `models/TASK_H_ONBOARDING.md`. |
| 4.3 | **Done**: release key at `D:\ARM-release-key\arm-release.jks` (outside the repo, password backup next to it); `keystore.properties` is git-ignored; the release APK is verified to be signed with it. |
| 4.4 | **Done**: `docs/ENGINEERING_REPORT.md` rewritten. |
| 4.5 | **Script done**: `docs/DEMO_SCRIPT.md`; recording is the owner's job. |
| Also | Classifier preload at app start (done). Phone-only items 1.5, 1.6, 2.1, 2.8, 4.1 (new features), 4.6 still open: no phone was connected. |
