# On-device Llama setup

ARM uses Llama 3.2 1B Instruct SpinQuant INT4 EO8 through ExecuTorch on a supported
64-bit Arm Android phone. Detection works without this model; the competition
demonstration must include actual Llama generation, not only template advice.

The model is **not bundled in the APK**. It is approximately 1.14 GB and is copied
separately. A model already provisioned on a phone works without internet access.
The optional in-app download has no configured public source in this build.

## Obtain the files

Use an account authorized for the model and comply with its distribution terms.
The existing host downloader requires `huggingface_hub` and an `HF_TOKEN`
environment variable; it does not print the token. Do not include the token or
model files in the source archive.

```powershell
py -m pip install huggingface_hub
py tools/llm/download_spinquant.py
```

This prepares `models/llama3_2_1b.pte` and `models/tokenizer.model`. Verify the
exact pair against the size and SHA-256 pins in `gradle.properties`:

```powershell
py tools/llm/provision_android.py --verify-only
```

A different export is rejected. Do not change the pins just to bypass a failed
check. A deliberate model upgrade needs runtime compatibility testing first.

## Install over USB

Enable USB debugging and authorize the host on a phone you control. Identify
the serial using `adb devices -l`. The helper requires an explicit serial so it
cannot accidentally select another attached device.

```powershell
py tools/llm/provision_android.py --serial DEVICE_SERIAL --apk app/build/outputs/apk/release/app-release.apk
```

Use `--adb C:/path/to/adb.exe` if ADB is not on PATH; `--models-dir` overrides the
local model directory. Omit `--apk` if the correct app is already installed.

The helper checks both local files before invoking ADB, installs the APK with
`-r` if requested, stops ARM, uploads to temporary files in the active user's
app-specific external `files/llm` directory, verifies device hashes, then
promotes the files and opens ARM. It never uninstalls the app to work around a
signing mismatch. A failed transfer leaves the app stopped and incomplete files
unused. Provisioning needs space for staged files, including an extra copy when
replacing an existing model. Some OEMs restrict shell access to app external
storage; the helper reports that failure rather than claiming success.

## Confirm on the phone

1. Open a suspicious message and generate an explanation.
2. Turn on airplane mode, turn Wi-Fi off, and generate again.
3. Verify the on-device Llama instrumentation/log evidence, not merely the
   presence of fixed advice on screen.

The app requires a compatible 64-bit runtime and Arm LSE atomics for the
ExecuTorch build. Unsupported phones show fixed localized advice. Host checksum
verification cannot prove device compatibility or generation.

## Host regression tests

```powershell
py -m unittest discover -s tools/llm -p "test_*.py" -v
```

Tests cover corrupt files, absent hash pins, explicit device selection and a
remote checksum mismatch preventing file promotion and application restart.
