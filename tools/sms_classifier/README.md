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
