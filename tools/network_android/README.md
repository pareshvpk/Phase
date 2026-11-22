# Android network monitoring

Enable **Protection → Network protection → Start monitoring**, read the disclosure,
and accept Android's VPN consent. Stop from that card or the ongoing notification.
Requires Android 10+; the rest of ARM retains Android 8 support.

`NetworkVpnService` captures this phone's IPv4/IPv6 TCP/UDP through Android's TUN
interface. Hev socks5 tunnel 2.20.0 handles the IP/TCP stack. An authenticated,
random-port loopback `LocalForwarder` protects outbound sockets from re-entering
the VPN and forwards directly to the original endpoints. No remote VPN server,
cloud inference, TLS interception or certificate installation is involved.
The current underlying network supplies DNS; ARM does not select a new provider.
Loss of that network stops monitoring; start again after changing networks.

The native stack permits 64 sessions. The relay permits 64 control sessions,
16 UDP destinations per association and 256 total UDP destinations. Stream buffers
are 16 KiB; UDP buffers are bounded. Idle TCP/UDP sessions expire after five/one
minutes. Unsupported traffic, including ICMP, is not forwarded. Other VPNs cannot
run concurrently. Existing connections may need to reconnect on start/stop.

Flow metadata feeds the same 122→64→5 NSL-KDD model as the Python companion.
Unavailable fields are zero in standardized space (training means). Five Python
parity fixtures verify Kotlin inference. Model classes are explicitly experimental;
benchmark accuracy must not be described as live phone detection accuracy.
Model outputs alone do not trigger threat notifications.

Local pattern alerts cover 10 distinct destination ports on one host/protocol
within 60 seconds, 100 flow starts within 10 seconds, and an observed UDP flow
averaging 1,000 datagrams/second over at least one second. TCP stream read sizes
are not treated as packet counts. Notifications are debounced per pattern for
one minute. Advice asks users to check legitimate activity first. ARM does not
automatically block destinations or establish that an intrusion occurred.

Payloads are transient forwarding buffers only, never recorded. Flow endpoints
are held in bounded memory; the UI keeps counters, pattern identifiers and the
latest model estimate, without endpoint history. Findings disappear on process
exit or explicit clear. The private temporary native config contains per-session
loopback credentials and is removed on shutdown. Android backup remains disabled.

## Verification

```powershell
py tools/network_android/generate_parity.py
.\gradlew.bat --offline testDebugUnitTest assembleDebug assembleDebugAndroidTest lintDebug
py tools/network_android/echo_fixture.py --bind <PC-LAN-IP> --seconds 600
adb shell am instrument -w -r -e class com.arm.threatassistant.network.NetworkVpnDeviceTest -e fixtureHost <PC-LAN-IP> com.arm.threatassistant.test/androidx.test.runner.AndroidJUnitRunner
```

Grant VPN consent before the device test. The fixture binds TCP 39080 and UDP
39090–39101 on the explicitly supplied local interface and echoes synthetic bytes.
Only use a controlled LAN; it stops after its configured time. The device test
checks pre-VPN reachability, TCP payload integrity/half-close, UDP payloads, fanout
alerts, model execution, stop, ordinary connectivity and restart. It finally
stops monitoring. This fixture is a functional test, not a detection-accuracy dataset.

## Pinned upstream dependency

Upstream: https://github.com/heiher/hev-socks5-tunnel/releases/tag/2.20.0

- `app/libs/hev-socks5-tunnel-2.20.0.aar`: SHA-256
  `ae8a2e96b80b4eccccd037805a4bb4a278090c89dbcae8bc6fcb7634e9a255b9`.
- `vendor/hev-socks5-tunnel-2.20.0.tar.xz`: source SHA-256
  `bc2ce746a0beeb71030d3ffe299f5a9d48e2895902d3883c2cac1a551ee128e9`.

Both were checked against release asset digests. Source is retained for inspection
and rebuild using upstream Android NDK instructions. The disposable extracted tree
is git-ignored. MIT/BSD component notices ship in
`app/src/main/assets/network_third_party_licenses.txt`. The AAR's API-29 minimum
is explicitly overridden for the app's older message-only support; all native
entry points are gated to API 29+. Gradle ships only Arm ABIs. Upstream consumer
ProGuard rules preserve its JNI binding in release builds.

API/lifecycle reference: https://developer.android.com/develop/connectivity/vpn

## Remaining deployment validation

Test IPv6, TLS/QUIC, DNS/private DNS, Wi-Fi/mobile handover, permission revocation,
OEM background restrictions and long-running battery/memory use. Measure false
alerts and recall using independently labelled modern traffic. AVG flagged the
debug application and instrumentation package as suspicious during this session;
its protection was left enabled. That warning remains unresolved and is not
claimed to be a false positive.
