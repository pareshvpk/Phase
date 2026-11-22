# Remaining work · 20 November 2026

| Priority | Work | Acceptance evidence |
|---|---|---|
| Network validation | Android capture/forwarding and local analysis are implemented and the controlled vivo test passed. Validate IPv6, DNS/private DNS, TLS/QUIC, mobile handover, revocation, soak/battery and labelled modern traffic. | See [network validation](NETWORK_VALIDATION_2026-11-21.md). Resolve the observed AVG warning before distribution. |
| Submission | Release 2.1.0 built and signature verified; source packaged and successfully rebuilt after extraction. | See the validation record and generated SHA-256 manifest. Fresh-machine dependency setup remains a handoff check. |
| Hardware | Install the submitted APK on a supported Arm phone, provision both Llama files, disconnect networks and run an explanation. | Device/build identifiers and successful native inference. |
| Hardware | Enable incoming protection, deliver SMS and MMS from another handset, exercise permission denial and revocation, and inspect Today. | Genuine delivery, visible alert and tap-through, routine message stays quiet, delayed MMS processed once. |
| Hardware | Review accessibility services before and after a controlled permission or settings change. | Local observations agree with Android settings and changes are accurately described. |
| Hardware | Run bounded live capture on an authorized Linux interface. | Interface, platform, packet limits, observed flows and feature limitations recorded. Optional Pi or accelerator measurements require the corresponding hardware. |
| Demo | Record the delivered build following the demo script. | Playable recording, with fixture replays and genuine events identified. |
| Quality | Review Hindi/Tamil with native speakers, collect consented anonymized test-only cases and evaluate each language separately. | Counts and errors by language, with source and split provenance. |
| Quality | Verify Armv8.0 fallback, updated latency, memory, energy and cold starts. Evaluate the network model using independently labelled contemporary flows. | Device-specific measurements, sampling method and limitations. |

See the [implementation matrix](IMPLEMENTATION_STATUS.md) for completed engineering and the [submission checklist](SUBMISSION_CHECKLIST.md) for handoff.
