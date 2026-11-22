# Submission checklist

## Source, app and model

- Package the Gradle wrapper, Android sources and assets, tools, dependency declarations, relevant documentation, licences and redistributable evidence. Exclude signing keys, passwords, keystore.properties, local.properties, build caches, personal traffic and private messages. Check the extracted source package before handoff.
- From the extracted project on Windows use `.\gradlew.bat testDebugUnitTest lintDebug assembleDebug assembleDebugAndroidTest`. Build the release with the owner's external signing configuration using `.\gradlew.bat assembleRelease`. Verify the actual release APK with `apksigner verify --verbose --print-certs path/to/app-release.apk` and record its SHA-256.
- To obtain an authorized copy, install the host dependency with `py -m pip install huggingface_hub`, configure HF_TOKEN in the environment for an account with model access, then run `py tools/llm/download_spinquant.py`. Verify the resulting llama3_2_1b.pte and tokenizer.model against gradle.properties before transfer. Record applicable model terms with the handoff. The default APK contains the small classifiers. The Llama files are separate.
- Place the two Llama files in models/ or pass `--models-dir`. From the project root run `py tools/llm/provision_android.py --verify-only`. With an authorized USB device, use `adb devices` to identify its serial and run `py tools/llm/provision_android.py --serial DEVICE_SERIAL --apk path/to/app-release.apk`. The helper verifies both local hashes and the transferred files. Local verification alone cannot certify device installation.

## Evidence before delivery

- [x] Record hashes for the exact source archive and signed APK, signature verification, final host test counts and the Android build environment. See `artifacts/submission/manifest.json` and [validation](VALIDATION_2026-11-21.md). The extracted source passed all 362 JVM tests and assembled a debug APK using cached dependencies.
- [ ] Install on the target phone, confirm the model is ready, disable networking and capture a genuine Llama explanation.
- [ ] Run the current instrumentation suite on the phone, record device identifiers, then verify SMS/MMS arrival, permissions and Today tap-through using a second handset.
- [ ] Exercise local app review and record a controlled change or explicitly record the observed empty state.
- [ ] Label network evidence as synthetic replay, captured PCAP or live Linux traffic. Retain capture parameters and observed results. A host fixture does not establish live accuracy.
- [ ] Record and review the demo video. Add its actual filename or link to the submission.
- [ ] Attach the [engineering report](ENGINEERING_REPORT.md), [device benchmark evidence](../benchmarks/vivo_comparison_2026-11-19/REPORT.md) and [demo script](DEMO_SCRIPT.md). Mark pending checks explicitly.

The Android workload runs on a supported Arm CPU. A Raspberry Pi can host the separate network companion. Hailo and other external accelerators are optional and require their own measurements for any performance claim.
