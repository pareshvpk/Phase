# SMS Specialist Classifier — Training Tools

This directory contains the reproducible Python training pipeline for the
SMS Specialist Classifier (Phase 3B).

## Files

- `train.py` — Pure Python + numpy training pipeline. No scikit-learn
  dependency. Produces a JSON model artifact consumed by the Kotlin
  `SmsSpecialistClassifier`.

## Reproducibility contract

The Python preprocessing and feature extraction match the Kotlin
implementation exactly:

1. Unicode NFC normalization
2. Lowercasing
3. Tokenization on non-alphanumeric boundaries (tokens >= 2 chars)
4. Word unigrams + bigrams
5. TF = raw term frequency
6. IDF = smooth_idf = log((n_docs + 1) / (df + 1)) + 1
7. TF-IDF = TF * IDF
8. L2 normalization
9. Logistic regression: p = sigmoid(w · x + b)
10. Prediction: THREAT if p >= threshold else SAFE

## Usage

```bash
python train.py \
    --data data/labeled.csv \
    --output ../app/src/main/assets/sms_classifier_model.json \
    --model-version 1.0.0 \
    --calibrate
```

## Dataset provenance

This toolkit does NOT bundle any dataset. You must provide your own labeled
CSV with columns `text,label` (0=SAFE, 1=THREAT) and verify its license
before use.

Suggested sources (verify licenses independently):

- UCI SMS Spam Collection
- Mendeley smishing datasets
- Manually labeled Indian-context SMS

Synthetic messages are supported for development but must NOT dominate
evaluation results.

## Model output

The model artifact is JSON with:

- `vocabulary` — ordered n-gram terms
- `idf` — per-term IDF values
- `weights` — logistic regression weights
- `bias` — intercept
- `threshold` — decision threshold
- `is_calibrated` — whether Platt scaling was applied
- `training_info` — provenance metadata

Never ship a synthetic or hand-crafted model as a production detector.

## Building the shipped model (v2.0.0)

```bash
py tools/sms_classifier/build_dataset.py fetch   # downloads 8 licence-compatible sources into data/ (git-ignored)
py tools/sms_classifier/build_dataset.py build   # clean, dedupe, template-group, split -> data/{train,val,test}.csv
py tools/sms_classifier/train.py --data tools/sms_classifier/data/train.csv \
    --val-data tools/sms_classifier/data/val.csv --test-data tools/sms_classifier/data/test.csv \
    --output app/src/main/assets/sms_classifier_model.json --model-version 2.0.0 \
    --optimizer lbfgs --min-df 2 --max-features 10000 --l2 0.1
```

`data/manifest.json` records URL, licence, SHA-256 and download date for every source.
After retraining, regenerate the expected scores in `ShippedModelParityTest`.

Test set (2,292 rows, no template shared with training): F1 0.960, precision 0.950, recall 0.971.
Real messages only at the app's 0.60 classifier cutoff: recall 0.914, false-alarm rate 0.007.
Weak spot: Tamil / Tanglish (only ~90 synthetic training rows; no licence-compatible real corpus).
