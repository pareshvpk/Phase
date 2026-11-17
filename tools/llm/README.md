# Downloading the SpinQuant INT4 Llama model

Roadmap task 1.1: switch the bundled model to the ExecuTorch-community
**Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8** export, stored as
`models/llama3_2_1b.pte` alongside `models/tokenizer.model`.

## Usage

```sh
cd D:\ARM   # (or the repo root)
HF_TOKEN=hf_your_token python tools/llm/download_spinquant.py
```

- `HF_TOKEN` must be set in the environment; it is never hardcoded or printed by
  this script.
- `--repo` overrides the Hugging Face repo id
  (default: `executorch-community/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8-ET`).
- `--models-dir` overrides the destination directory (default: `models`).

The script first lists the repo files with `list_repo_files`, picks the single
`*.pte` (fails with the file list if there are zero or more than one), then
downloads the `.pte` and `tokenizer.model` via `hf_hub_download` and copies
them to `models/llama3_2_1b.pte` and `models/tokenizer.model`.

Install:

```sh
pip install huggingface_hub
```

## Do not run on a phone

This script only prepares files on the host. The model files are large
(~1 GB) and git-ignored; never commit them. The APK build bundles whatever is
in `models/` at build time.

## Verification

After downloading, run `./gradlew assembleDebug` — the build copies
`models/llama3_2_1b.pte` and `models/tokenizer.model` into the APK assets
(`androidResources.noCompress` keeps `pte`/`model` uncompressed so
`AssetManager.openFd` can report their length). The installer's marker compares
asset lengths, so swapping in the smaller SpinQuant export triggers a fresh
install on next launch.
