"""Evaluate an SMS classifier model against a labelled CSV.

Inference mirrors the pipeline in tools/sms_classifier/train.py: NFC
normalization, lowercasing, Unicode alphanumeric tokenization, unigrams +
bigrams, TF-IDF with smooth IDF, L2 normalization, and logistic regression.

Only numpy is required beyond the Python standard library.
"""

import argparse
import csv
import json
import math
import sys
import time
import unicodedata
from collections import Counter

import numpy as np

MIN_TOKEN_LENGTH = 2

POSITIVE_LABELS = {"scam", "spam", "threat", "1"}
NEGATIVE_LABELS = {"safe", "ham", "legit", "0"}


def _is_usable_token(chars):
    if len(chars) >= MIN_TOKEN_LENGTH:
        return True
    if len(chars) == 1:
        return not chars[0].isascii() and chars[0].isalnum()
    return False


def preprocess(text):
    if not text or not text.strip():
        return []

    normalized = unicodedata.normalize("NFC", text)
    lowercased = normalized.lower()

    tokens = []
    current = []
    for ch in lowercased:
        if ch.isalnum():
            current.append(ch)
        else:
            if _is_usable_token(current):
                tokens.append("".join(current))
            current = []
    if _is_usable_token(current):
        tokens.append("".join(current))

    if not tokens:
        return []

    ngrams = list(tokens)
    for i in range(len(tokens) - 1):
        ngrams.append(tokens[i] + " " + tokens[i + 1])
    return ngrams


def parse_label(raw):
    value = (raw or "").strip().lower()
    if value in POSITIVE_LABELS:
        return 1
    if value in NEGATIVE_LABELS:
        return 0
    raise ValueError(f"unknown label {raw!r}; expected 'scam' or 'safe'")


def load_dataset(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"{path}: missing header row (expected text,label)")
        fields = {name.strip().lower(): name for name in reader.fieldnames}
        if "text" not in fields or "label" not in fields:
            raise ValueError(f"{path}: expected columns 'text,label', got {reader.fieldnames}")
        for line_no, row in enumerate(reader, start=2):
            text = (row.get(fields["text"]) or "").strip()
            if not text:
                continue
            try:
                label = parse_label(row.get(fields["label"]))
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: {exc}") from exc
            rows.append((text, label))
    if not rows:
        raise ValueError(f"{path}: no labelled rows found")
    return rows


class Model:
    def __init__(self, data):
        self.vocabulary = list(data["vocabulary"])
        self.idf = np.asarray(data["idf"], dtype=np.float64)
        self.weights = np.asarray(data["weights"], dtype=np.float64)
        self.bias = float(data["bias"])
        self.threshold = float(data.get("threshold", 0.5))
        self.model_version = data.get("model_version")
        self.detector_id = data.get("detector_id")
        self.is_calibrated = bool(data.get("is_calibrated", False))

        n = len(self.vocabulary)
        if len(self.idf) != n or len(self.weights) != n:
            raise ValueError(
                "model arrays are inconsistent: "
                f"vocabulary={n}, idf={len(self.idf)}, weights={len(self.weights)}"
            )
        self.index = {term: i for i, term in enumerate(self.vocabulary)}


def load_model(path):
    with open(path, encoding="utf-8") as f:
        return Model(json.load(f))


def vectorize(terms, model):
    vec = np.zeros(len(model.vocabulary), dtype=np.float64)
    if not terms or not model.vocabulary:
        return vec

    sq_sum = 0.0
    for term, count in Counter(terms).items():
        idx = model.index.get(term)
        if idx is None:
            continue
        tfidf = count * model.idf[idx]
        vec[idx] = tfidf
        sq_sum += tfidf * tfidf

    norm = math.sqrt(sq_sum)
    if norm > 0.0:
        vec /= norm
    return vec


def predict(text, model):
    vector = vectorize(preprocess(text), model)
    score = float(np.dot(vector, model.weights) + model.bias)
    score = max(-500.0, min(500.0, score))
    probability = 1.0 / (1.0 + math.exp(-score))
    label = 1 if probability >= model.threshold else 0
    return label, probability


def compute_metrics(y_true, y_pred):
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(y_true) if len(y_true) else 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
    }


def format_text(metrics, latency, model, model_path, rows, predictions):
    n_scam = sum(1 for _, label in rows if label == 1)
    n_safe = len(rows) - n_scam
    lines = [
        f"Model: {model_path}",
        f"Model version: {model.model_version}",
        f"Calibrated: {model.is_calibrated}",
        f"Threshold: {model.threshold:.4f}",
        f"Samples: {len(rows)} ({n_scam} scam, {n_safe} safe)",
        "",
        f"Precision: {metrics['precision']:.4f}",
        f"Recall:    {metrics['recall']:.4f}",
        f"F1:        {metrics['f1']:.4f}",
        f"Accuracy:  {metrics['accuracy']:.4f}",
        "",
        "Confusion matrix (rows = actual, columns = predicted):",
        f"{'':16}{'pred safe':>12}{'pred scam':>12}",
        f"{'actual safe':16}{metrics['tn']:>12}{metrics['fp']:>12}",
        f"{'actual scam':16}{metrics['fn']:>12}{metrics['tp']:>12}",
        "",
        f"Latency (ms): mean={latency['mean']:.4f}, p95={latency['p95']:.4f}",
        "",
        "Per-message predictions:",
    ]
    for item in predictions:
        actual = "scam" if item["label"] == 1 else "safe"
        predicted = "scam" if item["predicted"] == 1 else "safe"
        mark = "ok" if item["label"] == item["predicted"] else "MISS"
        lines.append(
            f"  [{mark:4}] actual={actual:4} predicted={predicted:4} "
            f"score={item['score']:.4f}  {item['text']}"
        )
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate an SMS classifier model")
    parser.add_argument("csv", help="Labelled CSV with columns text,label (scam/safe)")
    parser.add_argument("--model", required=True, help="Classifier model JSON")
    parser.add_argument("--json", metavar="PATH", help="Write metrics as JSON to PATH")
    args = parser.parse_args(argv)

    try:
        rows = load_dataset(args.csv)
        model = load_model(args.model)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    y_true = []
    y_pred = []
    predictions = []
    times_ms = []

    for text, label in rows:
        start = time.perf_counter()
        predicted, probability = predict(text, model)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        y_true.append(label)
        y_pred.append(predicted)
        times_ms.append(elapsed_ms)
        predictions.append(
            {
                "text": text,
                "label": label,
                "predicted": predicted,
                "score": probability,
            }
        )

    y_true = np.asarray(y_true, dtype=np.int64)
    y_pred = np.asarray(y_pred, dtype=np.int64)
    metrics = compute_metrics(y_true, y_pred)
    latency = {
        "mean": float(np.mean(times_ms)),
        "p95": float(np.percentile(times_ms, 95)),
    }

    print(format_text(metrics, latency, model, args.model, rows, predictions))

    if args.json:
        report = {
            "model": args.model,
            "model_version": model.model_version,
            "detector_id": model.detector_id,
            "threshold": model.threshold,
            "calibrated": model.is_calibrated,
            "samples": len(rows),
            "counts": {
                "scam": int(np.sum(y_true == 1)),
                "safe": int(np.sum(y_true == 0)),
            },
            "metrics": {
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1": metrics["f1"],
                "accuracy": metrics["accuracy"],
            },
            "confusion_matrix": {
                "true_safe": {"pred_safe": metrics["tn"], "pred_scam": metrics["fp"]},
                "true_scam": {"pred_safe": metrics["fn"], "pred_scam": metrics["tp"]},
            },
            "latency_ms": latency,
            "predictions": predictions,
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\nJSON report written to {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
