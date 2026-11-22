"""Package the current source and built APK without keys, model blobs or caches."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]
ROOT_FILES = {".gitignore", "README.md", "ARCHITECTURE.md", "LICENSE", "build.gradle.kts",
              "gradle.properties", "gradlew", "gradlew.bat", "requirements.txt",
              "settings.gradle.kts", "settings-gradle.lockfile"}
PREFIXES = {"app", "gradle", "docs", "tools", "benchmarks"}
EXCLUDED = {"local.properties", "keystore.properties", ".env"}


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def source_paths():
    listing = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
    ).decode("utf-8").split("\0")
    for name in sorted(set(listing)):
        if not name:
            continue
        relative = Path(name)
        if name not in ROOT_FILES and relative.parts[0] not in PREFIXES:
            continue
        if (relative.name in EXCLUDED or relative.name.startswith(".env") or
                relative.suffix.lower() in {".jks", ".keystore", ".pte", ".pem", ".key", ".apk"} or
                any(part in {"build", "__pycache__", ".gradle", ".git", "data"} for part in relative.parts)):
            continue
        absolute = ROOT / relative
        if absolute.is_file() and not absolute.is_symlink() and absolute.resolve().is_relative_to(ROOT):
            yield name, absolute


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts/submission")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if not output.is_relative_to(ROOT / "artifacts"):
        parser.error("output-dir must be within this project's artifacts directory")
    apk = ROOT / "app/build/outputs/apk/release/app-release.apk"
    if not apk.is_file():
        parser.error("build and verify the release APK first")
    output.mkdir(parents=True, exist_ok=True)
    archive = output / "ARM-source.zip"
    files = list(source_paths())
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as target:
        for name, source in files:
            target.write(source, "ARM/" + name)
    with zipfile.ZipFile(archive) as check:
        if check.testzip() is not None:
            raise RuntimeError("source archive failed its CRC check")
        names = set(check.namelist())
        required = {"ARM/gradle/wrapper/gradle-wrapper.jar", "ARM/app/src/main/assets/sms_classifier_model.json",
                    "ARM/app/src/main/assets/url_host_model.json", "ARM/tools/network_ids/out/nids_model.json",
                    "ARM/tools/network_ids/monitor.py", "ARM/tools/llm/provision_android.py"}
        if not required.issubset(names):
            raise RuntimeError("missing required source or model assets: " + str(required - names))
    packaged_apk = output / "ARM-2.1.0-release.apk"
    shutil.copy2(apk, packaged_apk)
    for name in ("ENGINEERING_REPORT.md", "SUBMISSION_CHECKLIST.md", "DEMO_SCRIPT.md", "VALIDATION_2026-11-21.md"):
        shutil.copy2(ROOT / "docs" / name, output / name)
    record = {
        "application_id": "com.arm.threatassistant", "version": "2.1.0", "version_code": 3,
        "source_files": len(files),
        "source_includes_uncommitted_changes": True,
        "llama_model": "Separate authorized model files required; see tools/llm/README.md in source",
        "device_and_video_status": "Current-build device/Pi checks and final video pending",
        "files": {file.name: {"bytes": file.stat().st_size, "sha256": digest(file)}
                  for file in (archive, packaged_apk)},
    }
    (output / "manifest.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
