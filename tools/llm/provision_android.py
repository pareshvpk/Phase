"""Verify and sideload ARM's pinned Llama files over USB; never downloads files.

Use --verify-only without a device. A real install requires an explicit --serial.
The app is force-stopped for the transfer and restarted only after verification.
Both debug and release builds can read their app-specific external directory.
"""

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "com.arm.threatassistant"
FILENAMES = ("llama3_2_1b.pte", "tokenizer.model")


def properties(path):
    result = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_files(directory, config):
    expected = {
        FILENAMES[0]: config.get("armLlmModelSha256", ""),
        FILENAMES[1]: config.get("armLlmTokenizerSha256", ""),
    }
    model_bytes = int(config.get("armLlmModelBytes", "0"))
    if model_bytes <= 0:
        raise ValueError("A positive pinned model size is required.")
    for name, digest in expected.items():
        if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise ValueError("A pinned SHA-256 is required for " + name)
        path = Path(directory) / name
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError("Missing or empty file: " + str(path))
        if name == FILENAMES[0] and path.stat().st_size != model_bytes:
            raise ValueError("Model size differs from gradle.properties.")
        if sha256(path) != digest.lower():
            raise ValueError("SHA-256 mismatch: " + name)
    return {name: digest.lower() for name, digest in expected.items()}


def provision(adb, serial, directory, hashes, apk=None):
    def run(*args, timeout=120):
        result = subprocess.run(
            [str(adb), "-s", serial, *map(str, args)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        if result.returncode:
            raise RuntimeError("ADB failed: " + (result.stderr or result.stdout).strip())
        return result.stdout.strip()

    if run("get-state") != "device":
        raise RuntimeError("Select an authorized USB device using --serial.")
    user_id = run("shell", "am", "get-current-user")
    if not re.fullmatch(r"\d+", user_id):
        raise RuntimeError("Could not determine the active Android user.")
    remote = f"/storage/emulated/{user_id}/Android/data/{PACKAGE}/files/llm"
    if apk is not None:
        # Never uninstall to work around a signing mismatch: that would erase user data.
        run("install", "-r", "--user", user_id, Path(apk).resolve(), timeout=300)
    if "package:" not in run("shell", "pm", "path", "--user", user_id, PACKAGE):
        raise RuntimeError("Install the ARM APK for the active user first, or pass --apk.")
    run("shell", "am", "force-stop", "--user", user_id, PACKAGE)
    run("shell", "mkdir", "-p", remote)
    # Stage both files before replacing either; incomplete transfers are ignored by ARM.
    for name in FILENAMES:
        staged = remote + "/" + name + ".part"
        run("push", Path(directory).resolve() / name, staged, timeout=1800)
        result = run("shell", "sha256sum", staged, timeout=300)
        if not result.split() or result.split()[0].lower() != hashes[name]:
            raise RuntimeError("Device checksum mismatch for " + name + "; app left stopped.")
    for name in reversed(FILENAMES):
        run("shell", "mv", remote + "/" + name + ".part", remote + "/" + name)
    run("shell", "am", "start", "--user", user_id, "-n", PACKAGE + "/.MainActivity")
    print("Verified model files installed. Check AI generation on the phone in airplane mode.")
    print("Files: " + remote)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models-dir", type=Path, default=ROOT / "models")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--serial", help="Explicit adb device serial (required for transfer)")
    parser.add_argument("--adb", default="adb", help="ADB executable or absolute path")
    parser.add_argument("--apk", type=Path, help="Optional signed APK to install with -r")
    args = parser.parse_args(argv)
    if not args.verify_only and not args.serial:
        parser.error("--serial is required for transfer, or use --verify-only")
    try:
        if args.apk is not None and not args.apk.is_file():
            raise ValueError("APK not found: " + str(args.apk))
        hashes = verify_files(args.models_dir, properties(ROOT / "gradle.properties"))
        print("Both local model files match the pinned SHA-256 checksums.")
        if not args.verify_only:
            adb = shutil.which(args.adb)
            if adb is None:
                raise ValueError("ADB not found. Pass --adb with its full path.")
            provision(adb, args.serial, args.models_dir, hashes, args.apk)
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
