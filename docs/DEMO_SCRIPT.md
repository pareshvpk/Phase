# Recording script

Record the submission APK on a supported Arm phone. Use a second handset and test numbers for carrier delivery. Prepare the signed build and model using the [submission checklist](SUBMISSION_CHECKLIST.md). Keep personal messages and phone numbers out of frame.

| Time | Action and evidence |
|---|---|
| 0:00–0:25 | Show the phone model, app version and first-launch introduction. Open Protection and grant the requested permissions. |
| 0:25–1:20 | With cellular service available, send an authored test SMS from the second phone asking the recipient to disclose an OTP and PIN. Film the actual delivery, notification and tap-through. Show the reasons and the same-day Today entry. Send a routine test message and check the result. |
| 1:20–1:55 | Enable airplane mode and turn Wi-Fi off. Open Check, analyze the authored message, then request a Llama explanation. Record the model-ready state, actual output and inference evidence. If the fixed explanation appears, label it and investigate before claiming an offline Llama demonstration. |
| 1:55–2:25 | Open Protection and review enabled accessibility services. Show the observations and Android's settings for a consenting test app. Explain why the capability warrants review and why legitimate services may need it. Show actual changes only if observed. |
| 2:25–2:50 | Switch language or theme, then show how to revisit the introduction and privacy information. |
| 2:50–3:25 | On the companion host run the synthetic demo below. Label it “Synthetic Ethernet traffic replay”. Explain that 12 synthetic UDP flows were generated locally without sending packets. Show the flow summary and identify imputed features. If authorized live Linux footage exists, show it separately with interface and capture limits. |
| 3:25–3:45 | End with the model, platform and measured scope. Explicitly identify any steps omitted from this recording. |

From the repository root run `python tools/network_ids/monitor.py --demo-scan`. For an existing classic Ethernet capture use `--pcap path/to/sample.pcap`. For live Linux capture use `--interface eth0 --seconds 15 --max-packets 100` with appropriate capture privileges and the actual authorized interface name.

Genuine MMS is a separate hardware check. With carrier service available, send an MMS containing a test text part and record provider delivery and the app outcome. Keep synthetic publisher tests, earlier hardware evidence and current carrier delivery clearly labelled. The script itself is not a recording.
