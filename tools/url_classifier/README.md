# URL Specialist Classifier — Training Tools

This directory contains a reproducible Python training pipeline for URL
threat classification, complementing the Kotlin
`com.arm.threatassistant.domain.detection.urldetection.UrlSpecialistDetector`.

## Files

- `train.py` — Pure Python + numpy training pipeline. No scikit-learn
  dependency. Produces a JSON model artifact.
- `sample.csv` — 12-row toy dataset for development and smoke testing.
- `out/` — default output directory for the model artifact (git-ignored).

## Feature extraction (mirrors the Kotlin detector)

The Python features mirror `UrlSpecialistDetector` and the offline lists in
`UrlDetectionEvidence.kt` exactly:

| Feature | Mirrors | Type |
|---|---|---|
| `url_length` | raw URL string length | numeric |
| `subdomain_count` | host label count minus 2 | numeric |
| `has_ip_host` | `IP_BASED_URL` (IPv4 dotted-decimal host) | binary |
| `is_url_shortener` | `URL_SHORTENER` (offline shortener list) | binary |
| `suspicious_tld` | `SUSPICIOUS_TLD` (offline TLD list) | binary |
| `homograph_attack` | `HOMOGRAPH_ATTACK` (mixed Latin/Cyrillic/Greek or look-alike chars) | binary |
| `suspicious_subdomain` | `SUSPICIOUS_SUBDOMAIN` (depth > `MAX_SUBDOMAIN_DEPTH`=3) | binary |
| `misleading_structure` | `MISLEADING_STRUCTURE` (`@` in URL, brand after `/` or `%2F`) | binary |
| `unusual_port` | `UNUSUAL_PORT` (port != scheme default: http=80, https=443, ftp=21) | binary |
| `encoded_characters` | `ENCODED_CHARACTERS` (`%` in URL) | binary |
| `excessive_length` | `EXCESSIVE_LENGTH` (length > `MAX_URL_LENGTH`=200) | binary |
| `suspicious_domain_keywords` | `SUSPICIOUS_DOMAIN` (keyword list in host) | binary |

Bare `www.` URLs are prefixed with `http://` before parsing, matching the
Kotlin `parseTarget` handling; hosts are taken from the netloc with userinfo
and port stripped, matching the Kotlin `uri.host ?: authority` fallback so
non-ASCII homograph hosts are preserved.

Model: logistic regression, `p = sigmoid(w · x + b)`. The numeric features
(`url_length`, `subdomain_count`) are standardized to z-scores before
training; the per-feature mean and std are stored in the artifact and must
be applied by the app before scoring. Prediction is MALICIOUS when
`p >= threshold` (default 0.5), otherwise BENIGN.

## Usage

```bash
python train.py --data sample.csv --output out/url_classifier_model.json
```

Options: `--lr`, `--epochs`, `--l2`, `--seed`, `--model-version`.

## CSV format

UTF-8 CSV with header columns `url,label`. Labels are `malicious` or
`benign` (case-insensitive). Commas inside URLs are fine when the field is
quoted per standard CSV rules.

```csv
url,label
http://paypal.com-secure.verify-account.banking-login.tk/login,malicious
https://www.wikipedia.org,benign
```

This toolkit does NOT bundle a real dataset. `sample.csv` is synthetic and
for development only. For production training, provide your own labeled
data (e.g. PhishTank, OpenPhish, or manually labeled URLs) and verify its
license before use.

## Model output (JSON artifact)

```json
{
  "model_version": "1.0.0",
  "detector_id": "UrlSpecialistDetector",
  "label_map": { "BENIGN": 0, "MALICIOUS": 1 },
  "threshold": 0.5,
  "feature_names": ["url_length", "subdomain_count", "..."],
  "numeric_features": ["url_length", "subdomain_count"],
  "numeric_mean": [43.25, 0.083],
  "numeric_std": [12.1, 1.24],
  "weights": [0.876, 0.683, "..."],
  "bias": -11.55,
  "reference_lists": { "shortener_domains": ["bit.ly", "..."], "..." : "..." }
}
```

`reference_lists` carries the same offline lists as
`UrlDetectionEvidence.kt` so an on-device feature extractor can use the
artifact as the single source of truth.

## How the app would load the JSON

The app would ship the JSON in `app/src/main/assets/` and load it
offline with the Kotlin serialization pattern used by
`SmsSpecialistClassifier`:

1. Read the asset (`assets.open("url_classifier_model.json")`) and decode
   it with `kotlinx.serialization` into a small `@Serializable data class`
   holding `featureNames`, `weights`, `bias`, `threshold`,
   `numericFeatures`, `numericMean`, `numericStd`, and `referenceLists`.
2. For each extracted URL, compute the 12 features above (a pure-Kotlin
   port of `extract_features`, reusing the constants already defined in
   `UrlSpecialistDetector`).
3. Standardize the numeric features: for each name in `numericFeatures`,
   replace `x` with `(x - numericMean[i]) / numericStd[i]` (index aligned
   with `featureNames`). Binary features pass through unchanged.
4. Score `z = bias + Σ weights[i] * feature[i]`, then
   `p = 1 / (1 + exp(-z))`.
5. Emit a MALICIOUS verdict signal when `p >= threshold`; feed it into
   `ThreatAnalyzer` alongside the rule-based `UrlSpecialistDetector`
   signals.

No changes are required to the existing rule-based detector — the model
would be an additional offline signal source, not a replacement.

## Host model (v1)

`train_host_model.py` trains a second, complementary artifact:
`out/url_host_model.json` (detector id `UrlHostClassifier`). It scores the
**host only**, so a URL with a path is not automatically "phishing".

### Data

- UCI **PhiUSIIL_Phishing_URL_Dataset** (235,795 rows), CC BY 4.0, read
  straight from `data/raw/phiusiil.zip` (`zipfile` +
  `io.TextIOWrapper`, encoding `utf-8-sig` because the CSV starts with a BOM).
- **Label mapping — the source labels are inverted:** PhiUSIIL `label = 1`
  means LEGITIMATE, `label = 0` means PHISHING. This pipeline stores
  `phishing = 1`, `benign = 0`, i.e. `our_label = 1 - source_label`.
- Rows are deduplicated by normalised host; a host that appears with both
  labels (58 hosts) is dropped entirely.
- Stratified 70 / 15 / 15 split by host (train / val / test), seed 42.

### Host normalisation (reproduce exactly in Kotlin)

1. Lowercase, strip surrounding whitespace; if the string has no `://`
   prefix, prepend `http://`.
2. `netloc` = substring up to the first `/`, `?` or `#`. Drop userinfo
   (everything up to and including the **last** `@`), drop `:port`
   (for a bracketed IPv6 literal the brackets and their content are kept),
   then remove **one** trailing `.` from the host.
3. Remove **one** leading `www.` (only if still leading after step 2).
4. Text fed to the n-grammer = `"^" + host + "$"`.
5. Features = every character n-gram of length **3, 4 and 5** of that text,
   counted once per occurrence (raw TF).

Empty hosts after normalisation are discarded.

### Maths

- Vocabulary: n-grams with `df >= 3` on **train only**; keep the 20,000 with
  the highest `df` (ties broken alphabetically), then stored alphabetically.
- `TF` = raw count, `IDF = ln((n_docs + 1) / (df + 1)) + 1` (smooth IDF,
  `n_docs` = number of training hosts), `TF-IDF = TF * IDF`, row then
  L2-normalised.
- Logistic regression `p = sigmoid(w · x + b)` fitted with scipy
  `minimize(method="L-BFGS-B")`, L2 penalty `0.5 * lambda / n * ||w||²` on
  the weights only (bias unpenalised). `lambda` is chosen from
  `{0.3, 1.0, 3.0}` by validation F1; `0.3` won (val F1 `0.7784`).
- Threshold: the **smallest** validation threshold whose phishing precision
  is `>= 0.98` (we prefer missing phishing over alarming on real sites);
  `0.754312`. Stored in the artifact; prediction is phishing when
  `p >= threshold`.
- All floats in the artifact are rounded to 6 significant digits.

### Test metrics (held-out, 32,858 hosts)

| precision | recall | F1 | FPR |
|---|---|---|---|
| 0.979702 | 0.645434 | 0.778191 | 0.00835806 |

Artifact size ≈ 0.46 MB.

### Usage

```bash
py train_host_model.py --zip data/raw/phiusiil.zip \
    --output out/url_host_model.json --model-version 1.0.0
```

Options: `--parity` (default `out/host_model_parity.json`), `--seed`,
`--l2`, `--max-iter`.

### Parity file

`out/host_model_parity.json` holds 40 hosts taken deterministically from the
test set (20 phishing, 20 benign, evenly spaced over the alphabet) with
`{url, host, text, label, probability}`. The Kotlin port must reproduce
`probability` for every entry.

### Known limits

- PhiUSIIL benign rows are mostly popular English/Latin homepages, so the
  model is only meaningful for that host distribution; hosts outside it
  (e.g. `google.com`, `amazon.in`) can still score high because brand-like
  substrings also appear inside phishing hosts.
- Host-only features ignore the path, query and scheme — deliberate, since
  the benign side of the corpus is almost entirely bare homepages.
- Non-Latin / punycode hosts and IP hosts are scored but poorly covered by
  the training distribution.
- The corpus is a snapshot (UCI, CC BY 4.0); retrain to refresh.


### Host model v1 — final training run (2026-11-18, supersedes the numbers above)

The first run flagged popular real sites (google.com 0.77, amazon.in 0.92) because PhiUSIIL has few short,
popular benign domains. The shipped model adds benign hosts from the **Tranco top 30,000** list
(tranco-list.eu, free for research; free-hosting/CDN/shortener parents such as firebaseapp.com, github.io,
bit.ly are excluded because phishing lives on their subdomains) and a fixed list of Indian bank/government/shopping
sites.

```
py tools/url_classifier/train_host_model.py --zip tools/url_classifier/data/raw/phiusiil.zip \
   --tranco tools/url_classifier/data/raw/tranco.zip --output tools/url_classifier/out/url_host_model.json
```

| Test set (n = 36,758) | Value |
|---|---|
| Precision (phishing) | 0.980 |
| Recall (phishing) | 0.609 |
| F1 | 0.752 |
| False-positive rate | 0.64 % |
| Threshold (val precision ≥ 0.98) | 0.747 |
| L2 | 0.3 |
| Size | 0.46 MB |

Sanity check: sbi.co.in 0.32, onlinesbi.sbi 0.26, hdfcbank.com 0.13, amazon.in 0.48, irctc.co.in 0.43,
google.com 0.03, paytm.com 0.21, flipkart.com 0.08 (all below the threshold); sbi-kyc-update.xyz 0.996,
hdfc-netbanking-verify.top 0.994 (flagged); amaz0n-refund.in.net 0.46 and paytm-kyc.online 0.68 are **not**
flagged by the model (the rule detector still catches the keywords / look-alike characters).
The model is tuned for few false alarms, so it is an extra signal next to the rules, never the only one.
