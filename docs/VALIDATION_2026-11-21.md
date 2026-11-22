# Release validation — 21 November 2026

Application 2.1.0, version code 3, package `com.arm.threatassistant`.
Validation ran on the Windows development host, with Android Studio JBR and
Android SDK 35. No Android phone or Raspberry Pi was connected for this release.

| Check | Result |
|---|---|
| `testDebugUnitTest` | 362 tests; 0 failed, errored or skipped |
| Network monitor Python suite | 15 tests passed, including synthetic PCAP parsing, bounds and scan observations |
| Offline provisioning Python suite | 4 tests passed, including local/remote corruption rejection |
| `assembleDebug` | Passed |
| `assembleDebugAndroidTest` | Passed; instrumentation tests compiled, not executed on a device |
| `lintDebug` | Passed: 0 errors, 30 warnings |
| `assembleRelease` including release lint and R8 | Passed |
| Release signature | APK Signature Scheme v2 verified, one 4096-bit RSA signer, project certificate |
| Local Llama files | Model and tokenizer matched the size/hash pins using `provision_android.py --verify-only` |
| Extracted source archive | `testDebugUnitTest assembleDebug --offline` passed from a fresh extraction using the installed SDK and cached dependencies; all 362 tests passed |

Release APK SHA-256:
`6191b8d83d264d29ad4bd24518df9c9749441d8763717c01c9ef7804d72a5ea8`

Signing certificate SHA-256:
`8a718ddfef0bf7f5f08c08cc2d3bb14cd1e05fe2a186ccb1f88a25a10cb80431`

The source package includes uncommitted changes intentionally. Its checksum and
APK checksum are recorded in `artifacts/submission/manifest.json` after packaging.
The archive is CRC-checked and required wrapper/model assets are checked by the
packager. Signing keys, passwords, local SDK configuration, Llama model files,
build caches and downloaded training datasets are excluded.
The extracted build used no copied `local.properties` or signing secrets;
`ANDROID_HOME` pointed to the host SDK. This verifies source completeness, not a
fresh-machine dependency download or a reproduced signed release.

## Changes covered

- Scoped accessibility-service review, explicit local comparison baseline and
  reset, 12 domain tests, and settings-based remediation.
- SMS/MMS permission refresh, cancellable bounded text reads, activation baseline,
  idempotent alert IDs, retryable provider failures and deferred empty MMS rows.
  Empty/media-only rows have a ten-minute retry window, with at most 128 pending
  IDs, so later messages are not blocked by an unfinished row. Queue overflow or
  text arriving after expiry can be missed; this needs OEM delivery testing.
- Share requests consumed once at the root, preserved request numbering across
  recreation, and explanation cancellation when leaving Check.
- Onboarding/intent and MMS lifecycle instrumentation regressions are included.
- Bounded Ethernet IPv4 TCP/UDP PCAP/live capture, explicit model feature gaps,
  deterministic traffic observations and synthetic scan replay.
- Verified USB model provisioning and a pinned tokenizer checksum for downloads.

## Not established by these checks

The current release has not been installed or exercised on hardware in this run.
Actual SMS/MMS delivery, notification tap-through, model transfer and inference,
OEM accessibility visibility, live capture on Arm Linux, contemporary-traffic
detection accuracy, native-speaker review and the final recording remain open.
Historical vivo results apply only to the builds and samples identified in their
reports. Capability changes are not evidence of confirmed malware infection.
