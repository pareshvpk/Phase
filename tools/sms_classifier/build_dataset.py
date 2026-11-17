#!/usr/bin/env python3
"""Download licence-compatible SMS scam datasets and build train/val/test CSVs.

Steps:
  fetch  - download raw files into tools/sms_classifier/data/raw/ (git-ignored)
           and write data/manifest.json (URL, licence, sha256, date).
  build  - normalise every source to (text, label, source, language, synthetic),
           clean, drop exact and near duplicates, group near-identical
           templates, cap synthetic rows, and split by template group so no
           template family appears in both train and test.

Only sources whose licence allows use in a shipped app are included (see
docs/DATASET_RESEARCH.md section 6). Sources without a licence, IEEE DataPort
(non-commercial) and test-only benchmarks are deliberately excluded.

Usage:
    py tools/sms_classifier/build_dataset.py fetch
    py tools/sms_classifier/build_dataset.py build
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import random
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.request
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE / "data"
RAW = DATA / "raw"
HF = "https://huggingface.co/datasets/{repo}/resolve/main/{path}"
HF_ROWS = "https://datasets-server.huggingface.co/rows?dataset={repo}&config=default&split=train&offset={offset}&length=100"

SOURCES = {
    "uci": {
        "url": "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip",
        "file": "uci.zip", "licence": "CC BY 4.0", "real": True,
        "cite": "Almeida & Hidalgo, UCI SMS Spam Collection (2011)",
    },
    "mendeley": {
        "url": "https://data.mendeley.com/public-files/datasets/f45bkkt8pr/files/"
               "edb361de-918d-469f-9106-e84823830665/file_downloaded",
        "file": "mendeley.zip", "licence": "CC BY 4.0", "real": True,
        "cite": "Mishra & Soni, SMS PHISHING DATASET, Mendeley Data, doi:10.17632/f45bkkt8pr.1",
    },
    "carnageiron": {
        "url": HF.format(repo="carnageiron/scam-ham-india", path="scam_hum_india.csv"),
        "file": "carnageiron.csv", "licence": "Apache-2.0", "real": True,
        "cite": "carnageiron/scam-ham-india (real samples + some augmentation)",
    },
    "bolewara": {
        "url": HF.format(repo="bolewara/hinglish-scam-text-dataset", path="data.json"),
        "file": "bolewara.json", "licence": "CC BY 4.0", "real": True,
        "cite": "bolewara/hinglish-scam-text-dataset",
    },
    "karanverma": {
        "url": HF.format(repo="karanverma19/Indian_Multilingual_Scam_Message_Dataset",
                         path="ultra_premium_scam_dataset.csv"),
        "file": "karanverma.csv", "licence": "Apache-2.0", "real": False,
        "cite": "karanverma19/Indian_Multilingual_Scam_Message_Dataset",
    },
    "ridham": {
        "url": HF.format(repo="Ridham115/indian-scam-sms-synthetic-audited", path="data/synthetic_audited.csv"),
        "file": "ridham.csv", "licence": "CC BY 4.0", "real": False,
        "cite": "Ridham115/indian-scam-sms-synthetic-audited",
    },
    "anmol14": {
        "url": HF.format(repo="anmolshrivastav/scam_ham_india_14_languages",
                         path="scam_ham_india_14_languages.csv"),
        "file": "anmol14.csv", "licence": "MIT", "real": False,
        "cite": "anmolshrivastav/scam_ham_india_14_languages",
    },
    "cloveai": {
        "url": "hf-rows:CloveAI/india-spam-sms",
        "file": "cloveai.jsonl", "licence": "MIT", "real": False,
        "cite": "CloveAI/india-spam-sms",
    },
}


def _get(url: str, attempts: int = 8) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "dataset-fetch/1.0"})
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.read()
        except urllib.error.HTTPError as err:
            if err.code not in (429, 500, 502, 503) or attempt == attempts - 1:
                raise
            wait = min(60, 2 ** attempt * 2)
            print(f"  HTTP {err.code}, retrying in {wait}s", flush=True)
            time.sleep(wait)
    raise RuntimeError("unreachable")


def _fetch_hf_rows(repo: str) -> bytes:
    out, offset, total = [], 0, None
    while total is None or offset < total:
        page = json.loads(_get(HF_ROWS.format(repo=repo, offset=offset)))
        total = page["num_rows_total"]
        out.extend(json.dumps(r["row"], ensure_ascii=False) for r in page["rows"])
        offset += len(page["rows"])
        if not page["rows"]:
            break
        time.sleep(0.5)
    return ("\n".join(out) + "\n").encode("utf-8")


def fetch() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for name, src in SOURCES.items():
        target = RAW / src["file"]
        if not target.exists():
            print(f"downloading {name} ...", flush=True)
            url = src["url"]
            data = _fetch_hf_rows(url.split(":", 1)[1]) if url.startswith("hf-rows:") else _get(url)
            target.write_bytes(data)
        blob = target.read_bytes()
        manifest[name] = {
            "url": src["url"], "licence": src["licence"], "real": src["real"], "cite": src["cite"],
            "file": src["file"], "bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest(),
            "downloaded": dt.date.fromtimestamp(target.stat().st_mtime).isoformat(),
        }
        print(f"{name}: {len(blob):,} bytes")
    (DATA / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Loaders: each yields (text, label, language) with label 1 = scam/spam, 0 = safe
# ---------------------------------------------------------------------------

KEEP_LANGS_ANMOL = {"English": "en", "Hindi": "hi", "Hinglish": "hinglish", "Tamil": "ta"}
KEEP_LANGS_RIDHAM = {"en": "en", "hi": "hi", "hinglish": "hinglish", "ta_en": "tanglish"}


def _csv(name: str):
    with open(RAW / name, encoding="utf-8-sig", newline="") as f:
        yield from csv.DictReader(f)


def load_uci():
    text = zipfile.ZipFile(RAW / "uci.zip").read("SMSSpamCollection").decode("utf-8", "replace")
    for line in text.splitlines():
        label, _, msg = line.partition("\t")
        if label in ("ham", "spam"):
            yield msg, int(label == "spam"), "en"


def load_mendeley():
    raw = zipfile.ZipFile(RAW / "mendeley.zip").read("Dataset_5971.csv").decode("utf-8", "replace")
    for row in csv.DictReader(io.StringIO(raw)):
        label = row["LABEL"].strip().lower()
        if label in ("ham", "spam", "smishing"):
            yield row["TEXT"], int(label != "ham"), "en"


def load_carnageiron():
    for row in _csv("carnageiron.csv"):
        label = row["label"].strip().lower()
        if label in ("ham", "spam", "scam"):
            yield row["text"], int(label != "ham"), "en"


def load_bolewara():
    data = json.loads((RAW / "bolewara.json").read_text(encoding="utf-8"))
    for row in data["rows"]:
        yield row["text"], int(row["label"]), "en"


def load_karanverma():
    langs = {"English": "en", "Hindi": "hi", "Hinglish": "hinglish"}
    for row in _csv("karanverma.csv"):
        label = row["label"].strip().lower()
        if label in ("scam", "legit"):
            yield row["message"], int(label == "scam"), langs.get(row["language"], "en")


def load_ridham():
    for row in _csv("ridham.csv"):
        lang = KEEP_LANGS_RIDHAM.get(row["language"])
        label = row["label"].strip().lower()
        if lang and label in ("scam", "safe"):
            yield row["text"], int(label == "scam"), lang


def load_anmol14():
    for row in _csv("anmol14.csv"):
        lang = KEEP_LANGS_ANMOL.get(row["language"])
        label = row["label"].strip().lower()
        if lang and label in ("scam", "ham"):
            yield row["text"], int(label == "scam"), lang


def load_cloveai():
    with open(RAW / "cloveai.jsonl", encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            yield row["text"], int(row["label"]), "en"


LOADERS = {
    "uci": load_uci, "mendeley": load_mendeley, "carnageiron": load_carnageiron,
    "bolewara": load_bolewara, "karanverma": load_karanverma, "ridham": load_ridham,
    "anmol14": load_anmol14, "cloveai": load_cloveai,
}

# ---------------------------------------------------------------------------
# Cleaning, near-duplicate grouping, split
# ---------------------------------------------------------------------------

URL_RE = re.compile(r"(https?://\S+|www\.\S+|\b[\w-]+\.(?:com|in|net|org|co|ly|me|xyz|info|top|link)\S*)", re.I)
NUM_RE = re.compile(r"\d+")
SPACE_RE = re.compile(r"\s+")
NAME_SLOT_RE = re.compile(r"\b(hi|dear|hello)\s+\w+", re.I)

MAX_SYNTHETIC_PER_GROUP = 5  # synthetic rows kept per template family; real rows are never capped
JACCARD_MIN = 0.8
NUM_PERM, BANDS = 100, 10
ROWS_PER_BAND = NUM_PERM // BANDS
PRIME = (1 << 61) - 1


def clean(text: str) -> str:
    text = unicodedata.normalize("NFC", text or "").replace("​", "")
    return SPACE_RE.sub(" ", text).strip()


def exact_key(text: str) -> str:
    return SPACE_RE.sub(" ", text.lower()).strip()


def template_text(text: str) -> str:
    """Masks the slots that vary inside a template family (links, numbers, names)."""
    t = URL_RE.sub(" <url> ", text.lower())
    t = NUM_RE.sub("0", t)
    t = NAME_SLOT_RE.sub(r"\1 <name>", t)
    return SPACE_RE.sub(" ", t).strip()


def detect_script(text: str, fallback: str) -> str:
    if any("஀" <= ch <= "௿" for ch in text):
        return "ta"
    if any("ऀ" <= ch <= "ॿ" for ch in text):
        return "hi"
    return fallback


def minhash_groups(texts: list[str]) -> list[int]:
    """Groups texts whose masked character 4-grams have Jaccard >= JACCARD_MIN (LSH + check)."""
    import numpy as np

    rng = np.random.RandomState(7)
    a = rng.randint(1, 1 << 31, size=NUM_PERM).astype(np.uint64)
    b = rng.randint(0, 1 << 31, size=NUM_PERM).astype(np.uint64)
    parent = list(range(len(texts)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    buckets: dict[tuple, list[int]] = {}
    gram_sets: list[set] = []
    for i, t in enumerate(texts):
        grams = {t[j:j + 4] for j in range(max(1, len(t) - 3))}
        gram_sets.append(grams)
        hashes = np.array([zlib_crc(g) for g in grams], dtype=np.uint64)
        sig = ((np.outer(a, hashes) + b[:, None]) % np.uint64(PRIME)).min(axis=1)
        for band in range(BANDS):
            key = (band, sig[band * ROWS_PER_BAND:(band + 1) * ROWS_PER_BAND].tobytes())
            members = buckets.setdefault(key, [])
            for j in members[:20]:  # verify against a few earlier members; no blind chaining
                ri, rj = find(i), find(j)
                if ri == rj:
                    break
                inter = len(grams & gram_sets[j])
                if inter / (len(grams) + len(gram_sets[j]) - inter) >= JACCARD_MIN:
                    parent[ri] = rj
                    break
            members.append(i)
    return [find(i) for i in range(len(texts))]


def zlib_crc(s: str) -> int:
    import zlib
    return zlib.crc32(s.encode("utf-8"))


def build() -> None:
    manifest = json.loads((DATA / "manifest.json").read_text(encoding="utf-8"))
    rows, seen_labels = [], defaultdict(set)
    per_source = Counter()
    for name, loader in LOADERS.items():
        real = manifest[name]["real"]
        for text, label, lang in loader():
            text = clean(text)
            if len(text) < 3 or not any(ch.isalpha() for ch in text):
                continue
            rows.append({"text": text, "label": label, "source": name, "real": real,
                         "language": detect_script(text, lang)})
            seen_labels[exact_key(text)].add(label)
            per_source[name] += 1
    print("loaded:", dict(per_source))

    # Exact duplicates: keep the first copy (real sources are loaded first); drop label conflicts.
    conflicts = {k for k, v in seen_labels.items() if len(v) > 1}
    unique, seen = [], set()
    for r in rows:
        k = exact_key(r["text"])
        if k in conflicts or k in seen:
            continue
        seen.add(k)
        unique.append(r)
    print(f"after exact dedupe: {len(unique)} (dropped {len(rows) - len(unique)}, "
          f"{len(conflicts)} texts with conflicting labels)")

    groups = minhash_groups([template_text(r["text"]) for r in unique])
    for r, g in zip(unique, groups):
        r["group"] = g
    sizes = Counter(groups)
    print(f"template groups: {len(sizes)}; largest: {sizes.most_common(3)}")

    # Cap rows per template family so templates cannot dominate.
    rng = random.Random(42)
    rng.shuffle(unique)
    kept, per_group = [], Counter()
    for r in unique:
        if r["real"]:
            kept.append(r)
        elif per_group[r["group"]] < MAX_SYNTHETIC_PER_GROUP:
            per_group[r["group"]] += 1
            kept.append(r)
    print(f"after per-template cap: {len(kept)}")

    # Group split 70/15/15 so a template family never straddles train and test.
    group_ids = sorted({r["group"] for r in kept})
    rng.shuffle(group_ids)
    assign, n_total, filled = {}, len(kept), Counter()
    group_size = Counter(r["group"] for r in kept)
    for g in group_ids:
        split = "test" if filled["test"] < 0.15 * n_total else "val" if filled["val"] < 0.15 * n_total else "train"
        assign[g] = split
        filled[split] += group_size[g]

    fields = ["text", "label", "source", "language", "real", "group"]
    for split in ("train", "val", "test"):
        part = [r for r in kept if assign[r["group"]] == split]
        with open(DATA / f"{split}.csv", "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
            w.writeheader()
            w.writerows(part)
        by_lang = Counter((r["language"], r["label"]) for r in part)
        n_real = sum(r["real"] for r in part)
        print(f"{split}: {len(part)} rows ({sum(r['label'] for r in part)} scam), real={n_real}; "
              f"by language/label: {dict(sorted(by_lang.items()))}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("step", choices=["fetch", "build"])
    args = parser.parse_args()
    if args.step == "fetch":
        fetch()
    else:
        build()


if __name__ == "__main__":
    main()
