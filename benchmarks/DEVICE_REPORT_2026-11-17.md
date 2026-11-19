# ARM v2.0.0 — on-device test, benchmark and stress report (3 phones)

**Date:** 2026-11-17 · **Device:** vivo V2338 (Android 16, arm64, 8 cores; 4 efficiency cores, ExecuTorch uses 3 threads) · **Build:** debug for instrumented tests, release (R8) for start-up and size
**Model:** SMS classifier v2.0.0 (TF-IDF + logistic regression, 10k terms) · Llama 3.2 1B Instruct SpinQuant INT4 EO8 (ExecuTorch 1.5.1, XNNPACK)
**Raw logs:** [`raw_2026-11-17/`](raw_2026-11-17/) (run 1 = before fixes, run 2 = after fixes)

Reproduce:
```bash
adb push tools/sms_classifier/data/test.csv /data/local/tmp/arm_eval/test.csv
adb shell cmd deviceidle whitelist +com.arm.threatassistant   # vivo freezes test processes otherwise
adb shell am instrument -w -r com.arm.threatassistant.test/androidx.test.runner.AndroidJUnitRunner
adb logcat -v brief | grep -E "ARMSTRESS|ARMBENCH|ARMLLM"       # stream during the run; the buffer is small
```

## 1. Summary

| Area | Result |
|---|---|
| Instrumented tests | **17 / 17 pass** (UI intents, benchmark, end-to-end accuracy, soak, concurrency, hostile input, Llama) |
| Unit tests | **all pass** (incl. 6 new regression tests from this report) |
| Scam detection, real messages (end to end, as an SMS alert) | **90.1 % caught, 0.7 % false alerts** (324 scams / 955 safe) |
| Hindi / Hinglish | 93.3 % / 83.2 % caught, 0.0 % / 3.0 % false alerts |
| Analysis latency | median **2.2 ms**, p95 3.0 ms, p99 3.7 ms per message |
| Throughput | 393 msg/s single thread, **1,058 msg/s on 8 threads**, 0 verdict mismatches |
| Memory (10,000-message soak) | Java heap **+80 KB** (no leak), PSS −11 MB |
| Hostile inputs (20 cases, up to 50,000 chars) | **no crash**, worst case 140 ms (500 URLs) |
| Llama explanation | first token **4.3–5.3 s** (7.8 s cold), **9.4–12.9 tok/s**, PSS ~1.31 GB, stable over 10 runs |
| Llama cancel | stop returns in **47 ms**; model usable afterwards |
| Cold start (release) | **276–324 ms** (median 285 ms) |
| Size | release APK **12.5 MB**; installed app 12 MB; data = model 1.14 GB |

## 2. Detection accuracy (end to end, on the phone)

Pipeline exactly as the SMS receiver runs it: `SensitiveSmsFilter` → `ThreatAnalyzer` (rules + URL + classifier + risk policy) → `SmsAlertPolicy`.
Test set: 2,292 held-out messages from `tools/sms_classifier/build_dataset.py` (no template shared with training; 1,279 real, 1,013 synthetic).

| Slice | Scams | Caught (alert) | Skipped by privacy filter | Safe msgs | False alerts |
|---|---:|---:|---:|---:|---:|
| **Real messages** | 324 | **90.1 %** (was 88.6 %) | 3 (was 8) | 955 | **0.7 %** |
| All | 625 | 90.4 % (was 89.6 %) | 22 (was 27) | 1,667 | 2.5 % |
| English | 443 | 91.9 % | 7 | 1,464 | 2.3 % |
| Hindi | 60 | 93.3 % | 3 | 57 | 0.0 % |
| Hinglish | 113 | 83.2 % | 12 | 132 | 3.0 % |
| Tamil (script) | 5 | 100 % | 0 | 8 | 25 % (2 of 8) |
| Tanglish | 4 | 75 % | 0 | 6 | 17 % (1 of 6) |

Built-in 10-sample corpus (`DeviceBenchmarkTest`): **10/10 scams alerted** (was 6/10 on 2026-11-14 with the placeholder model), 0/6 benign alerted, 8/8 OTP/bank messages kept private.

Verdict mix: scams → SUSPICIOUS 564, HIGH_RISK 1, INSUFFICIENT_EVIDENCE 38, skipped 22. HIGH_RISK is almost never reached by the classifier alone; it needs a high-severity rule.

Remaining errors (real messages):
- **False alerts (7):** customer-feedback SMS ("You just spoke to DEEPAK… Reply Toll Free…") and short chat ("Service now ?", "Logged in with desktop now").
- **Missed:** UK premium-rate prize texts, loan offers, and Hinglish scams the privacy filter treats as bank alerts (12 Hinglish scams still skipped).
- Tamil/Tanglish numbers rest on 23 test rows; treat as indicative only.

## 3. Performance

| Measurement | n | mean | median | p95 | p99 | max |
|---|---:|---:|---:|---:|---:|---:|
| Full analysis (`ThreatAnalyzer.analyze`) | 2,000 | 2.33 ms | 2.24 ms | 3.04 ms | 3.66 ms | 14.4 ms |
| SMS receiver path (filter + analysis + alert decision) | 2,000 | 1.81 ms | 2.14 ms | 3.10 ms | 9.08 ms | 23.1 ms |
| 10k soak over the real test set | 10,000 | 2.54 ms | 2.27 ms | 3.75 ms | 10.7 ms | 312 ms |
| 1,600-character message | 200 | 10.1 ms | 7.97 ms | 19.0 ms | 28.7 ms | 136 ms |
| First analysis in a fresh process (loads 490 KB model) | 1 | 820 ms | | | | |

Compared with 2026-11-14 (25-term placeholder model): median analysis 1.73 → 2.24 ms; first analysis 34 → 230–820 ms (model JSON parse).

## 4. Stress and robustness

- **Soak:** 10,000 analyses in 25.4 s; Java heap 6,779 → 6,859 KB, native heap flat. No leak.
- **Concurrency:** 8 threads × 500 analyses, 3.78 s, **0 verdict differences** vs single-threaded.
- **Hostile input** (all pass, < 3 s): empty, whitespace, 50k letters (80 ms), 20k-char token, 5k emoji, zero-width only, RTL Arabic, mixed scripts, unpaired surrogates, NUL bytes, 500 URLs (140 ms), 20k-char URL, HTML/script, SQL-like, 5,000 digits (**8 ms, was 1,269 ms**), 18k punctuation, combining marks, 13k-char Tamil, 9k-char Devanagari.
- **Llama:** 10 consecutive explanations, no slowdown or memory growth (PSS 1.30–1.40 GB); cancel mid-generation 47 ms; next generation works. 1 of 10 answers replaced by the safe fallback (answer cut off at the 150-token cap).
- **Thermal:** skin 41.0 °C → **46.4 °C (Android thermal status 3, "severe")** after ~4 minutes of continuous Llama + soak while charging over USB. Normal use (one explanation per scam) is far lighter, but back-to-back explanations heat the phone.

## 5. Problems found by this run and fixed

| # | Problem | Fix | Effect |
|---|---|---|---|
| 1 | Privacy filter skipped scams that look like alerts: prize texts without a link, "Rs 15,000 credited… Join now: sr3.in/…" | `SensitiveSmsFilter`: prize/lottery words, or a link plus join/activate/withdraw/claim, are never skipped | real scams skipped 8 → 3; genuine bank alert with a "Report at" link still private |
| 2 | Zero-width characters inside words hid scams ("Sh​are your O‍TP") → no warning | `FastRuleEngine` matches both readings (invisible as space and removed) | now SUSPICIOUS |
| 3 | Money regex was quadratic: 5,000 digits took 1.27 s on the phone (receiver thread) | possessive quantifier + lookbehind | 1.27 s → 8 ms (PC: 825 → 1.4 ms) |
| 4 | Prompt asked "why this message is or is not dangerous" → Llama wrote "not dangerous because it is a scam", guard fell back | verdict-aware prompt ("explain why this message is likely a scam") | fallbacks 6/10 and 1/10 in two earlier runs → 1/10 (cut-off answer, correct fallback) |

Earlier the same day (already committed): Llama KV cache carried over between explanations (fixed with `resetContext()`), and the CPU check marked every phone unsupported.

## 6. Not measured / open

- **Battery drain:** phone was on USB power (drain 0); measure with `dumpsys batterystats` on battery.
- **Monkey (random UI) test on the vivo:** skipped (PIN lock screen). Done on the Samsung (section 8). To repeat with the phone unlocked:
  `adb shell monkey -p com.arm.threatassistant --throttle 80 --pct-syskeys 0 -v 5000`
- **Real incoming SMS** end-to-end (roadmap 2.8) and **Armv8.0 phones** (roadmap 1.6).
- **Two devices so far** (section 8). A third, e.g. a mid-range Snapdragon, would complete roadmap 4.1.

## 7. Recommended next steps

1. Pre-load the classifier at app start, off the main thread, so the first SMS after boot doesn't pay the 0.2–0.8 s model load.
2. Registered-sender rule (roadmap 2.6) for feedback/service SMS from DLT headers: removes most real false alerts.
3. Hinglish: 12 scams still skipped by the privacy filter; add Hinglish lure words ("jeeta", "inaam", "paise milenge").
4. Collect ~300 real messages from other phones (roadmap 2.1), especially Tamil/Tanglish, and re-run section 2.
5. Limit back-to-back Llama runs (e.g. auto-explain only the newest alert) to keep the phone cool.

## 8. Second phone: Samsung Galaxy M13 5G (32-bit Android)

**Device:** Samsung SM-M136B, MediaTek Dimensity 700 (2× Cortex-A76 + 6× A55), 6 GB RAM, Android 13.
It runs a **32-bit-only Android** (`ro.zygote=zygote32`, ABI list `armeabi-v7a,armeabi`) even though the CPU is 64-bit. Samsung ships many budget models this way.

**Critical finding:** v2.0.0 could not be installed at all on this phone: `INSTALL_FAILED_NO_MATCHING_ABIS`. The APK only had 64-bit native libraries, and ExecuTorch 1.5.1 has no `armeabi-v7a` build.

**Fix (this commit):**
- `abiFilters` now `arm64-v8a` + `armeabi-v7a`: the 32-bit phone gets the small 32-bit helper libraries (fbjni, libc++), so it installs. ExecuTorch stays 64-bit only. Release APK 12.5 → **13.5 MB**.
- `CpuSupport.isSupported()` also requires a 64-bit process, and `LlmExplainerProvider.get()` checks it first. ExecuTorch native code is never loaded on 32-bit or Armv8.0 phones; the app shows the fixed explanation instead (the existing "Unsupported" state).
- Llama device tests skip (instead of failing) on unsupported phones.

**Results after the fix** (raw: `raw_2026-11-17/samsung_m13_*`):

| | vivo V2338 (64-bit) | Samsung M13 5G (32-bit) |
|---|---|---|
| Installs | yes | **yes (was: fails)** |
| Instrumented tests | 17 / 17 pass | **15 pass, 2 skipped (Llama, unsupported), 0 fail** |
| Real scams caught / false alerts | 90.1 % / 0.7 % | **90.1 % / 0.7 %** (identical, detection is deterministic) |
| 10-sample corpus | 10/10 scams, 0/6 benign | 10/10, 0/6 |
| Analysis median / p95 / p99 | 2.24 / 3.04 / 3.66 ms | 3.54 / 4.91 / 6.62 ms |
| SMS receiver path throughput | 551 msg/s | 413 msg/s |
| 10k soak | 393 msg/s, heap +80 KB | 304 msg/s, heap +80 KB, PSS +0.7 MB |
| 8-thread concurrency | 1,058 msg/s, 0 mismatches | 848 msg/s, 0 mismatches |
| Hostile inputs (20) | all pass, worst 140 ms | all pass, worst 149 ms (50k letters) |
| First analysis (cold process) | 820 ms | 469 ms |
| Llama | ~10 tok/s, first token ~5 s | not available (32-bit), fixed explanation shown |
| Monkey UI stress (5,000 random events, seed 42) | not run (PIN lock screen) | **5,000 events, 0 crashes, 0 ANRs** |
| Temperature during tests | skin 41.0 → 46.4 °C (Llama) | AP 40.2 → 42.0 °C (no Llama) |

Not completed on the Samsung: a second, faster monkey pass (10,000 events) and release cold-start timing. The phone disconnected from the PC before they ran.

## 9. Third phone: vivo I2605 (Dimensity 7300, 64-bit)

**Device:** vivo I2605, MediaTek Dimensity 7300 (MT6878: 4× Cortex-A78 + 4× A55), 8 GB RAM, Android 16, 64-bit (`zygote64`, Armv8.2 with atomics), so Llama is supported.
Model copied once into app storage (1.14 GB SpinQuant + tokenizer). Raw: `raw_2026-11-17/vivo_i2605_*`.

| | vivo V2338 | Samsung M13 5G (32-bit) | **vivo I2605** |
|---|---|---|---|
| Instrumented tests | 17/17 | 15 pass, 2 skipped | **17/17 pass** |
| Real scams caught / false alerts | 90.1 % / 0.7 % | 90.1 % / 0.7 % | **90.1 % / 0.7 %** |
| Analysis median / p95 / p99 | 2.24 / 3.04 / 3.66 ms | 3.54 / 4.91 / 6.62 ms | **2.03 / 2.63 / 3.30 ms** |
| Receiver path throughput | 551 msg/s | 413 msg/s | **692 msg/s** |
| 10k soak | 393 msg/s, heap +80 KB | 304 msg/s, +80 KB | **472 msg/s, +80 KB** |
| 8-thread concurrency | 1,058 msg/s, 0 mismatches | 848 msg/s, 0 | 962 msg/s, 0 |
| Hostile inputs | 20/20 | 20/20 | 20/20 (worst 83 ms) |
| First analysis (cold process) | 820 ms | 469 ms | 190 ms |
| Llama first token (warm) | 4.3–5.3 s | n/a | **3.5–4.4 s** |
| Llama speed | 8.8–12.9 tok/s | n/a | **12.0–13.4 tok/s** |
| Llama memory (PSS) | ~1.31 GB | n/a | ~1.33 GB (RSS after load 1.57 GB) |
| Guard fallbacks (10 runs) | 1 | n/a | **0** |
| Cancel → return | 47 ms | n/a | 25 ms |
| Monkey UI stress | not run (PIN) | 5,000 events, 0 crash/ANR | **5,000 + 10,000 events, 0 crashes, 0 ANRs** |
| Release cold start (5 runs) | 276–324 ms | not measured | **316–397 ms** (median 330 ms) |
| Installed app size | 12 MB | 13.5 MB APK | 13 MB |
| Temperature (full suite) | skin 41.0 → 46.4 °C (status 3) | AP 40.2 → 42.0 °C | CPU 46.2 → 51.1 °C, skin 39.1 → 44.4 °C (status 3) |

**Conclusion across 3 phones:** detection results are identical on every device (deterministic pipeline). Latency stays under 7 ms at p99 even on the 32-bit budget phone. There are no leaks, no thread-safety problems and no UI crashes in 15,000 random events. Llama runs at 9–13 tok/s on 64-bit Dimensity/Snapdragon-class phones and is cleanly disabled where it can't run. The one consistent concern is heat under back-to-back Llama runs (thermal status 3 on both 64-bit phones).

## 10. Re-test on vivo V2338, 2026-11-18 (after network check added, Apps tab removed)

- Instrumented suite: **17/17 pass** (274 s). Real scams 90.1 % caught, 0.7 % false alerts; demo set 10/10 scams alerted, 0/6 benign, 8/8 OTP/bank skipped.
  Detection median 3.1 ms; Llama first token 4.1–5.3 s, 9.7–11 tok/s, PSS ~1.28 GB.
- Monkey (seed 42, 5,000 events) **crashed at event 3,479** on Compose UI 1.7.0:
  `IllegalStateException: Dispatching intercepted soft keyboard event while focus system is invalidated` (framework bug).
  Fixed by Compose BOM 2024.09.00 → 2024.12.01 (UI 1.7.6). After: seeds 42 and 7, 5,000 events each, **0 crashes, 0 ANRs**; 17/17 still pass.
- Network check: home WPA2 Wi-Fi + USB debugging on → "Be careful on this network" with only the USB-debugging finding (correct). (The network check was removed from the app on 2026-11-19.)
  Checked in English, Hindi and Tamil on Wi-Fi and mobile data; text renders correctly.
