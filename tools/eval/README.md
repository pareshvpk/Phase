# SMS Classifier Evaluation

Evaluates an SMS classifier model against a labelled CSV and reports precision,
recall, F1, accuracy, a confusion matrix, and mean/p95 per-message latency.

## Requirements

Python 3 with `numpy` (no other third-party dependencies).

## Input

The CSV must have a header with `text,label`. Labels are `scam` (positive) and
`safe` (negative); `threat`/`1` and `ham`/`0` are also accepted. Blank rows are
skipped.

The model JSON is the artifact produced by
`tools/sms_classifier/train.py` (keys `vocabulary`, `idf`, `weights`, `bias`,
`threshold`). Inference reproduces that script's preprocessing, TF-IDF
vectorization, L2 normalization, and sigmoid scoring.

## Usage

```bash
python tools/eval/evaluate.py tools/eval/sample.csv \
    --model app/src/main/assets/sms_classifier_model_test_fixture.json
```

Write the same results as JSON:

```bash
python tools/eval/evaluate.py tools/eval/sample.csv \
    --model app/src/main/assets/sms_classifier_model_test_fixture.json \
    --json tools/eval/report.json
```

Latency is wall-clock time per message (preprocessing + vectorization +
scoring), measured with `time.perf_counter`; p95 uses `numpy.percentile`.
