#!/usr/bin/env python3
"""Download the SpinQuant INT4 Llama-3.2-1B ExecuTorch export from Hugging Face.

Finds the single *.pte export in the repo (via list_repo_files), downloads it
together with tokenizer.model, and copies them into models/ as
llama3_2_1b.pte and tokenizer.model for verified USB provisioning. They are
not bundled in the APK; use provision_android.py after downloading.

The Hugging Face token is read from the HF_TOKEN environment variable and is
never hardcoded or printed.

Usage:
    HF_TOKEN=hf_... python tools/llm/download_spinquant.py
    HF_TOKEN=hf_... python tools/llm/download_spinquant.py --repo executorch-community/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8-ET --models-dir models

Do not run this against a phone; it only prepares files on the host.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

try:
    from huggingface_hub import hf_hub_download, list_repo_files
except ImportError as exc:
    sys.exit(f"huggingface_hub is required: {exc}\nInstall with: pip install huggingface_hub")

DEFAULT_REPO = "executorch-community/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8-ET"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        default=DEFAULT_REPO,
        help="Hugging Face repo id (default: %(default)s)",
    )
    parser.add_argument(
        "--models-dir",
        default="models",
        help="Destination directory (default: models)",
    )
    args = parser.parse_args()

    token = os.environ.get("HF_TOKEN")
    if not token:
        sys.exit("HF_TOKEN environment variable is required (set it, never hardcode or print it).")

    try:
        repo_files = list_repo_files(args.repo, token=token)
    except Exception as exc:  # network or auth failure
        sys.exit(f"Could not list files in {args.repo}: {exc}")

    ptes = [name for name in repo_files if name.endswith(".pte")]
    if len(ptes) != 1:
        sys.exit(
            f"Expected exactly one *.pte file in {args.repo}, found {len(ptes)}: {ptes}"
        )

    models_dir = Path(args.models_dir)
    models_dir.mkdir(parents=True, exist_ok=True)

    pte_path = hf_hub_download(repo_id=args.repo, filename=ptes[0], token=token)
    tokenizer_path = hf_hub_download(repo_id=args.repo, filename="tokenizer.model", token=token)

    shutil.copy2(pte_path, models_dir / "llama3_2_1b.pte")
    shutil.copy2(tokenizer_path, models_dir / "tokenizer.model")

    print(f"Downloaded {ptes[0]} and tokenizer.model from {args.repo}")
    print(f"Copied to {models_dir / 'llama3_2_1b.pte'} and {models_dir / 'tokenizer.model'}")


if __name__ == "__main__":
    main()
