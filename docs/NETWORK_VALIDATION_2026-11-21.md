# Android network validation — 21 November 2026

Implemented Android VPN capture and direct forwarding with opt-in controls,
foreground notification, VPN consent, stop/revoke cleanup, underlying-network-loss
handling, bounded local flow metadata, NSL-KDD inference and pattern alerts.
English/Hindi/Tamil controls and privacy disclosures are included.

## Evidence

- 377 JVM tests passed (364 existing plus 13 network tests); no failures.
- New tests cover byte-exact 256 KB TCP forwarding and half-close, UDP echo,
  SOCKS authentication, protection failure, loopback rejection, stop cleanup,
  bounded 10,000-flow processing, rule windows/cooldowns and five Python-to-Kotlin
  model parity cases (probability tolerance 1e-10).
- Debug app and instrumentation APKs built. Lint: 0 errors, 33 warnings.
- Final release APK built with R8 and its signature verified. The installed,
  phone-tested artifact is the debug APK; release-specific phone testing is pending.
- vivo V2338, Android API 36, connected over USB: controlled network instrumentation
  passed in 3.122 seconds. It checked LAN reachability before VPN start, byte-exact
  64 KB TCP echo/half-close through the VPN, UDP replies from 12 fixture ports,
  fanout alert, nonzero captured packets, completed-flow model estimate,
  stopping the VPN, connectivity without it, restarting and TCP forwarding again.
- No external detection service was used. The PC served only synthetic echo data;
  capture, forwarding and analysis ran on the Arm phone. Monitoring stopped in test cleanup.
- Phone testing found and fixed two real integration bugs: stop must release the
  TUN before waiting for service destruction, and TCP sockets must be bound before
  Android VPN protection to allocate their file descriptor.

Reproduction instructions and dependency SHA-256 pins are in the
[Android network guide](../tools/network_android/README.md).
Raw logs and the APK digest are retained under
`benchmarks/network_android_validation_2026-11-21/`.

## Limits and unresolved observations

The phone fixture verifies IPv4. IPv6 is implemented by the forwarding stack but
not established by this run. DNS/private DNS, TLS/QUIC, handover, consent revocation,
OEM background restrictions, long-running resource use and labelled deployment
accuracy need additional tests. The historical NSL-KDD metrics do not establish
modern phone detection accuracy. Model scores are explicitly experimental, and
alerts describe suspicious patterns rather than proven intrusions.

AVG flagged both the debug application and test package as suspicious. Its
protection stayed enabled; the uninstall prompts were dismissed to run the
authorized test. The warning has not been resolved or established as a false
positive. Review it before distributing the build.

This record covers the network increment, not completion of malware behaviour
detection, carrier SMS/MMS validation or the demonstration video.
