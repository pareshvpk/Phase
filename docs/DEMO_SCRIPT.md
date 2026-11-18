# ARM demo video script (target 3–4 minutes)

Record the phone screen with `adb shell screenrecord /sdcard/arm_demo.mp4` (max 3 min per file) or scrcpy
(`scrcpy --record arm_demo.mp4`). Turn on Do Not Disturb and airplane mode first; airplane mode shows that
nothing needs the internet. Use a second phone to send the scam SMS in scene 3.

| # | Time | On screen | Voice-over (plain words) |
|---|---|---|---|
| 1 | 0:00–0:15 | Title card, then the app opening with airplane mode visible in the status bar | "ARM is a digital-safety assistant that runs completely on your phone. No cloud and no account. It even works in airplane mode." |
| 2 | 0:15–0:35 | First-launch introduction: three pages, then "Turn on SMS protection" | "On first launch ARM explains what it checks and promises that messages never leave the phone." |
| 3 | 0:35–1:10 | A second phone sends: *"Dear SBI customer, your KYC expires today. Share OTP to avoid account block: sbi-kyc-update.xyz"* → notification arrives → tap it | "A scam SMS arrives. Within milliseconds ARM's rules, its SMS model and its URL model flag it, and a notification warns the user." |
| 4 | 1:10–1:45 | Result screen: red "Dangerous" verdict, highlighted risky words, plain reasons, Llama explanation streaming | "The result shows why: it asks for an OTP, pushes urgency and links to a fake site, and the risky words are highlighted. Llama 3.2 1B, quantized to INT4 and running on the phone's Arm CPU through ExecuTorch, explains it in simple language and gives safe next steps." |
| 5 | 1:45–2:00 | Today tab with the alert | "Every warning from today is kept here, on the phone only." |
| 6 | 2:00–2:20 | Check tab: paste a phishing link alone (e.g. `http://hdfc-netbanking-verify.top/login`), then a safe bank OTP message | "Links can be checked on their own. A normal OTP message from the bank stays safe, so there are no false alarms." |
| 7 | 2:20–2:50 | Apps tab → "Scan my apps" → a sideloaded test app with SMS + accessibility shows "Dangerous" → "Uninstall" | "ARM also looks for malware behaviour: apps installed outside the store that can read OTPs or control the screen, the pattern used by banking trojans." |
| 8 | 2:50–3:10 | Protection tab → "Check my network" on an open Wi-Fi hotspot → "This network is not safe" | "It checks the network you are on: open Wi-Fi, a captive portal, unusual DNS or USB debugging left on." |
| 9 | 3:10–3:30 | PC/Raspberry Pi terminal: `py tools/network_ids/detect.py --demo` shows DoS/probe flows with explanations | "For the home network, a Raspberry Pi companion classifies traffic flows (trained on NSL-KDD) and explains attacks in plain words." |
| 10 | 3:30–3:45 | Settings: switch to Hindi, then Tamil, then dark theme | "ARM speaks English, Hindi and Tamil, with light and dark themes." |
| 11 | 3:45–4:00 | Closing card: on-device numbers from `benchmarks/DEVICE_REPORT_2026-11-17.md` (90 % of real scams caught, 0.7 % false alerts, 2–4 ms per message, Llama 9–13 tokens/s) | "Everything runs on Arm, on the phone, in milliseconds. Your messages stay yours." |

## Test app for scene 7
Use any harmless sideloaded APK that asks for SMS permission and an accessibility service (for example a
self-built debug app). Install it with `adb install` so its installer is "unknown". Uninstall it after recording.

## Checklist before recording
- Llama model is installed (Settings shows the AI explanation as ready) and the phone is cool (no thermal throttling).
- SMS protection is on and notifications are allowed.
- Install the release build so the debug banner and extra logging are gone.
