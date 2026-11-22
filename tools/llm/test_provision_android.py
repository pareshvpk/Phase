import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import provision_android as provision


class ProvisionTest(unittest.TestCase):
    def test_correct_pair_is_verified_and_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            for name, content in zip(provision.FILENAMES, (b"model", b"tokenizer")):
                (Path(folder) / name).write_bytes(content)
            config = {
                "armLlmModelBytes": "5",
                "armLlmModelSha256": hashlib.sha256(b"model").hexdigest(),
                "armLlmTokenizerSha256": hashlib.sha256(b"tokenizer").hexdigest(),
            }
            self.assertEqual(2, len(provision.verify_files(folder, config)))
            (Path(folder) / provision.FILENAMES[1]).write_bytes(b"corrupt")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                provision.verify_files(folder, config)

    def test_missing_pin_cannot_silently_disable_validation(self):
        with self.assertRaisesRegex(ValueError, "pinned SHA-256"):
            provision.verify_files(".", {"armLlmModelBytes": "5"})

    def test_requires_explicit_device_without_touching_adb(self):
        with patch("subprocess.run") as run:
            with self.assertRaises(SystemExit):
                provision.main([])
            run.assert_not_called()

    def test_remote_corruption_never_promotes_files_or_restarts_app(self):
        def fake_run(command, **kwargs):
            args = command[3:]
            response = ""
            if args == ["get-state"]:
                response = "device"
            elif args == ["shell", "am", "get-current-user"]:
                response = "0"
            elif args[:3] == ["shell", "pm", "path"]:
                response = "package:/data/app/test.apk"
            elif args[:2] == ["shell", "sha256sum"]:
                response = "0" * 64 + "  model.part"
            return subprocess.CompletedProcess(command, 0, response, "")

        with patch("subprocess.run", side_effect=fake_run) as run:
            with self.assertRaisesRegex(RuntimeError, "Device checksum mismatch"):
                provision.provision("adb", "device1", ".", {name: "1" * 64 for name in provision.FILENAMES})
            commands = [call.args[0][3:] for call in run.call_args_list]
            self.assertFalse(any(command[:2] == ["shell", "mv"] for command in commands))
            self.assertFalse(any(command[:3] == ["shell", "am", "start"] for command in commands))


if __name__ == "__main__":
    unittest.main()
