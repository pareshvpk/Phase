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
