# ARM Digital Safety Guardian

An Android digital-safety assistant with offline SMS and phishing detection,
plain-language Llama advice through ExecuTorch, and a separate network-monitoring
companion for Arm Linux. Current application: **2.1.0**, package
`com.arm.threatassistant`, Android 8.0+ (API 26), target API 35.

## Application

- Check pasted, shared or selected messages using deterministic rules, a trained
  SMS classifier and a phishing-host classifier.
- Read highlighted evidence, guarded explanations and practical next steps.
- Enable optional incoming SMS/MMS text protection and view today's alerts.
  Sensitive-message filtering runs before analysis. MMS reads use bounded,
  cancellable jobs and retry incomplete provider rows for up to ten minutes.
- In Protection, choose **Review app access** and **Check now** to inspect enabled
  accessibility services and granted SMS access. Later explicit checks compare
  a private baseline; **Delete saved comparison** clears it. These are capability
  observations, not proof of malware or a complete antivirus scan.
- Use English, Hindi or Tamil, light/dark/system theme, first-launch introduction
  and a Settings privacy dialog. Hindi/Tamil Llama output remains experimental.

Detection and explanations run on the phone. Internet permission supports optional
model downloads and direct forwarding for opt-in network monitoring. No public
model download URL is configured. The approximately 1.14 GB Llama model is separate from the APK.
See [verified offline model installation](tools/llm/README.md).

## Network companion

Android 10+ builds also include **Protection → Network protection**: local VPN
capture, direct TCP/UDP forwarding, experimental flow classification and pattern
alerts. See the [Android network guide](tools/network_android/README.md) for scope,
privacy, dependency provenance and verification limits.

`tools/network_ids/monitor.py` accepts classic Ethernet PCAP or bounded passive
capture from a Linux interface. It groups IPv4 TCP/UDP traffic into flows, reports
experimental NSL-KDD model estimates, and observes port fanout and high packet
rates with plain-language verification steps. Unavailable model features are
explicitly imputed; historical dataset accuracy is not live-traffic accuracy.
IPv6, ICMP, IP fragment reassembly and PCAPNG are outside this implementation.

```sh
python3 -m pip install -r requirements.txt
python3 tools/network_ids/monitor.py --demo
python3 tools/network_ids/monitor.py --demo-scan
python3 tools/network_ids/monitor.py --pcap authorized-capture.pcap --max-packets 10000
```

Both demo modes create synthetic records in memory and send no packets.
Live capture requires Linux and packet-capture privileges; follow the
[network guide](tools/network_ids/README.md) on an authorized interface.
Pi execution and deployment accuracy still need hardware validation.

## Build and test

Use JDK 21 (Android Studio JBR), Android SDK 35 and the Gradle wrapper. Set
`ANDROID_HOME` or create an untracked `local.properties` with `sdk.dir`.

```powershell
$env:JAVA_HOME = 'C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat testDebugUnitTest assembleDebug assembleDebugAndroidTest lintDebug
py -m unittest discover -s tools/network_ids -v
py -m unittest discover -s tools/llm -p "test_*.py" -v
```

Add `--offline` to Gradle when dependencies are already cached. Release signing
uses an untracked `keystore.properties` containing `storeFile`, `storePassword`,
`keyAlias` and `keyPassword`. Keep the key outside this repository. The build
falls back to a debug key if release configuration is absent, so verify the
certificate before distributing any release.

```powershell
.\gradlew.bat assembleRelease
apksigner verify --verbose --print-certs app/build/outputs/apk/release/app-release.apk
py tools/release/package_submission.py
```

Latest host validation: **362 JVM tests and 19 Python tests passed**. Debug,
instrumentation and release APKs built. Lint: **0 errors, 30 warnings**. The
release APK's project certificate was verified. These results do not claim a
current device run. See [validation record](docs/VALIDATION_2026-11-21.md).

The packaging helper writes `artifacts/submission/`: current source archive,
signed APK copy, report, checklist, demo script and SHA-256 manifest. It excludes
keystores, machine configuration, caches, downloaded datasets and Llama blobs.

## Privacy and limitations

No analytics, cloud inference or automatic opening of extracted links. Optional
SMS/MMS permissions enable local protection. Today's flagged alerts are stored
privately and pruned when read or changed; app-access comparisons store only
package identifiers and capability flags. Android backup is disabled.
The network companion can expose addresses/ports in local output; only use
authorized traffic and synthetic examples in public evidence.

This is a research prototype. Detection can miss scams and produce false
alarms. App access review cannot establish malicious activity. Current-release
device testing, genuine SMS/MMS delivery, Arm Linux capture and the final video
remain pending. Earlier phone evidence is retained with its dates and scope.

## Documentation

- [Technical report](docs/ENGINEERING_REPORT.md)
- [Implementation status](docs/IMPLEMENTATION_STATUS.md)
- [Remaining work](docs/ROADMAP.md)
- [Privacy and security](docs/PRIVACY_SECURITY.md)
- [Submission checklist](docs/SUBMISSION_CHECKLIST.md)
- [Demo recording script](docs/DEMO_SCRIPT.md)
- [SMS dataset provenance snapshot](docs/DATASET_MANIFEST.json)
- [Earlier vivo measurements](benchmarks/vivo_comparison_2026-11-19/REPORT.md)

Llama through ExecuTorch is the advisory workload. The small SMS/URL models and
network classifier use Kotlin/NumPy. Hailo is not used; no accelerator performance
is claimed.
