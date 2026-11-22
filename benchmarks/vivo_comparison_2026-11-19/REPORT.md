# ARM and PS3 Sentinel on vivo V2338

19 November 2026 · Android 16 · debug APKs · USB ADB

**ARM is the better scam-warning app on this phone with the available files.** It warned on 24 of 28 risky messages, compared with 8 for Sentinel. ARM also warned on two legitimate messages. Sentinel produced zero false warnings in this sample. Both projects' Llama models were installed. Sentinel's MiniLM SMS and URL CNN model files were absent from both its Android model directories and the supplied ZIP. Its results describe its fallback detector. A configuration with those weights could produce different verdicts.

## Detection results

A warning means the visible result said “Be careful”, “Likely scam” or “High risk”. Both apps received identical text through the same Android action. The runner required the screen to show the submitted message and a verdict. All 56 pairs met that check. These counts describe this deliberately balanced sample.

| Sample | Risky / routine | ARM warnings on risky | Sentinel warnings on risky | ARM warnings on routine | Sentinel warnings on routine |
|---|---:|---:|---:|---:|---:|
| Newly authored multilingual cases | 12 / 12 | 9 | 4 | 2 | 0 |
| English real-message rows from ARM's held-out file | 8 / 8 | 7 | 1 | 0 | 0 |
| English rows from Sentinel's held-out file | 8 / 8 | 8 | 3 | 0 | 0 |
| **Total** | **28 / 28** | **24 (85.7%)** | **8 (28.6%)** | **2 (7.1%)** | **0 (0%)** |

ARM showed its strongest verdict on one of the 24 risky messages it flagged. Sentinel showed its strongest verdict on six of the eight it flagged. The remaining positive results were caution-level warnings.

- **Fake bank verification.** ARM called the KYC suspension message with a sign-in link “Likely scam”. Sentinel showed “Looks safe”.
- **OTP theft.** Both warned on a request to send an OTP and PIN to block a transaction. Sentinel showed its strongest warning. ARM also warned on a legitimate office reminder *never* to share those credentials.
- **Impersonation.** Both missed the fake manager requesting gift-card codes and the supposed family member asking for a transfer after breaking their phone.
- **Languages.** ARM caught the authored Hindi and Hinglish scams. Both missed the Tamil scam. ARM warned on the routine Tamil school reminder. There was just one scam and one routine message for each of these languages in the authored set.

[All paired results](paired-results.csv) · [Authored messages](cases.json) · [Held-out row indices](heldout-rows.csv)

## How the apps worked

| On-device check | ARM | PS3 Sentinel |
|---|---|---|
| Manual entry, shared text and selected text | Produced a verdict on all three paths | Produced a verdict on all three paths |
| Offline scam check, airplane mode on and Wi-Fi off | Warned on the OTP/PIN request. A separate instrumented test generated nonempty Llama output offline | Rated the same request high risk and displayed advice. Its native Llama log confirmed generation |
| Automatic SMS on this phone | SMS permission and the protection toggle were enabled. Android delivered the synthetic notification from the app's notification publisher. Its visible text omitted the test body, and it included a tap action | SMS permission was denied. A foreground debug injection exercised the alert logic and logged a high-risk alert after 95 ms. The OTP test added no notification |
| Cold activity launch, median of three | **920 ms**, range 914–953 ms | **1,056 ms**, range 999–1,242 ms |
| Idle memory, proportional set size | **1.24 GiB** | **1.22 GiB** |
| Debug APK, model files on disk excluded | **23.83 MiB** | **16.89 MiB** |
| JVM regression tests on the PC | **323 passed** | **473 passed, 1 failed, 1 skipped**. The failure cited missing `id_map.json`. The skipped test uses the optional URL vocabulary |
| Hardware regression coverage in this session | All **18** project instrumented tests passed, including 10,000 analyses, concurrency, long inputs, Llama generation and cancellation. The dedicated notification check also passed | Both UI test sets, the offline explanation and the synthetic debug alert ran on the phone |

Cold launch measures Android activity startup following a process stop. The three runs per app share the OS filesystem cache. Memory was sampled once, about 11 seconds after the third launch, with the Llama files present. ARM warms its explainer on startup in this build. The APK hashes on the phone matched the two local APKs.

The offline OTP/PIN example produced a Sentinel first token in **2.74 seconds** from native inference start and approximately **15 tokens/s**. ARM’s separate prompt-cache test measured **4.92 seconds cold** and **1.90 seconds warm** to the first callback. The prompts and timing boundaries differ, so these runs do not establish an explanation-speed winner. The Sentinel output speculated that the card details might already have been obtained. That detail went beyond what the test message established.

[Offline UI results](offline.json) · [ARM offline generation test](arm-offline-llama.txt) · [Sentinel generation timings](sentinel-explanation-timing.txt) · [ARM notification check](arm-notification-test.txt) · [Sentinel debug notification](sentinel-notification.json)

## Additional ARM results

ARM’s instrumented suite also ran its incoming-message filter, detector and alert policy on a 2,292-row test file. It warned on **566 of 625 scams** and **41 of 1,667 safe messages**. On rows the dataset marks real, it warned on **292 of 324 scams** and **7 of 955 safe messages**. In a separate 24-case receiver-path check, all 10 scam examples alerted, the 6 benign examples stayed quiet, and all 8 sensitive examples were skipped.

The 10,000-analysis run finished in 32.94 seconds, about 304 messages/s. The earlier timing loop experienced a long pause before the app was foregrounded again. Its maximum and mean are unsuitable for a detector-speed comparison. Sentinel's built-in incoming-SMS batch benchmark requires its missing SMS model, so ARM's larger numbers are reported separately.

[ARM benchmark measurements](arm-suite-metrics.txt) · [ARM stress and generation measurements](arm-instrument-metrics.txt)

## Scope and reproducibility

The authored set includes 24 synthetic messages. The second set uses eight English positive and eight English negative rows from each project's local held-out file, using random seed 20261119. ARM's source was restricted to rows marked real. Sentinel's source labels spam or scam as risky and includes mixed or synthetic material. Each project's labels were retained. Training overlap across projects is unknown. The results support choosing between these installed builds and give a limited estimate of everyday accuracy.

Incoming carrier delivery was outside this test. The receiver-policy and notification results above use laboratory inputs. The clipboard paste button, notification tapping, long-term battery use, and the Pi CLI were outside the measured paths. Existing SMS permissions were preserved and no inbox or personal messages were accessed. The temporary ARM notification-test package was removed. Airplane mode, Wi-Fi, the USB stay-awake setting and the temporary idle exemption were restored. Sentinel's debug test may have left a synthetic alert visible. [Restored phone settings](restored-settings.json)
