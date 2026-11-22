# Privacy and security

Android performs message classification, URL inspection and explanations locally. Pasted, shared and selected text is held in memory during analysis. Extracted links are inspected without fetching their destinations. The app has no analytics or account requirement.

| Manifest permission | Purpose |
|---|---|
| RECEIVE_SMS | Receive incoming SMS when the user enables protection. |
| RECEIVE_MMS | Receive a push event for incoming MMS. |
| READ_SMS | Read sender and text parts for incoming MMS through Android's message provider. This is a sensitive permission. |
| POST_NOTIFICATIONS | Display local warnings where notification permission is required. |
| INTERNET | Optional model download and direct forwarding when the user enables local VPN monitoring. |
| ACCESS_NETWORK_STATE | Obtain the underlying network and its DNS configuration. |
| FOREGROUND_SERVICE / FOREGROUND_SERVICE_SPECIAL_USE | Keep user-enabled VPN monitoring visible in an ongoing notification. |

Onboarding opens Protection for optional setup. The sensitive-message filter skips routine private messages such as many OTPs and transaction updates. Alert decisions also depend on sender and detector evidence. Where a message triggers an alert, the Today store keeps its sender, truncated text and reason identifiers in app-private storage. The store prunes older entries when accessed or changed. Notifications omit message bodies. Settings and the MMS scan position persist locally. Android backup is disabled.

The app review queries enabled accessibility services and visible provider packages, including granted SMS permissions relevant to a finding. Check now explicitly saves package identifiers and capability flags in an app-private AtomicFile under noBackupFilesDir. Reset clears the baseline. These signals can describe legitimate accessibility software. Android settings let users inspect the underlying access.

The APK contains the SMS and URL classifier assets. The separately provisioned Llama model and tokenizer have SHA-256 pins in gradle.properties. The default installation workflow checks local files before USB transfer. Guarded model text supplements the deterministic verdict.

The optional Android monitor uses system VPN consent, captures TCP/UDP on this phone and forwards directly to original endpoints. Detection runs locally. No remote VPN server, cloud analysis, TLS decryption or packet recording is used. Bounded flow metadata and findings remain in memory. Private temporary relay credentials are removed on shutdown. Stop from Protection or the ongoing notification. The separate Python companion still supports host capture. See the [network guide](../tools/network_android/README.md) for exclusions and retention details.
