"""
SMS Specialist Classifier — Python training pipeline.

Trains a logistic regression model with TF-IDF features for offline SMS
smishing detection. The model artifact is a JSON file consumable by the
Kotlin SmsSpecialistClassifier.

REPRODUCIBILITY CONTRACT
------------------------
The Python preprocessing and feature extraction must match the Kotlin
implementation exactly:

  1. Unicode NFC normalization
  2. Lowercasing
  3. Tokenization on Unicode letter/number boundaries (tokens of length >= 2)
  4. Word n-grams: unigrams + bigrams (joined by single space)
  5. TF = raw term frequency
  6. IDF = smooth_idf = log((n_docs + 1) / (df + 1)) + 1
  7. TF-IDF = TF * IDF
  8. L2 normalization of the vector
  9. Logistic regression: p = sigmoid(w · x + b)
  10. Prediction: THREAT if p >= threshold else SAFE

No scikit-learn dependency. Pure Python + numpy only.

DATASET PROVENANCE
------------------
This pipeline does NOT bundle any dataset. You must provide your own labeled
data and verify its license before use. Suggested sources (verify licenses):

  - UCI SMS Spam Collection: https://archive.ics.uci.edu/ml/datasets/sms+spam+collection
    (License: verify on the UCI repository page)
  - Mendeley smishing datasets: search Mendeley Data for "smishing SMS dataset"
  - Indian-context labeled SMS: collect and label manually

Synthetic messages are supported for development but must NOT dominate
evaluation results.

Usage:
    python train.py --data data/labeled.csv --output ../app/src/main/assets/sms_classifier_model.json
"""

import argparse
import csv
import json
import math
import os
import sys
import unicodedata
from collections import Counter, defaultdict

import numpy as np

# ---------------------------------------------------------------------------
# Preprocessing (must match Kotlin SmsTextPreprocessor exactly)
# ---------------------------------------------------------------------------

MIN_TOKEN_LENGTH = 2
NGRAM_MAX = 2


def preprocess(text: str) -> list[str]:
    """NFC normalize, lowercase, tokenize, emit unigrams + bigrams.

    Tokenization matches Kotlin SmsTextPreprocessor exactly: any Unicode
    letter or number is a token character (so Devanagari and other non-Latin
    scripts are preserved); everything else is a delimiter. Tokens shorter
    than 2 chars are dropped, except single non-ASCII letters/digits which
    can be meaningful on their own.
    """
    if not text or not text.strip():
        return []

    # 1. NFC normalization
    normalized = unicodedata.normalize("NFC", text)
    # 2. Lowercasing
    lowercased = normalized.lower()
    # 3. Tokenization: split on non-letter/non-number boundaries
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

    # 4. Word n-grams (unigrams + bigrams)
    ngrams = list(tokens)
    for i in range(len(tokens) - 1):
        ngrams.append(tokens[i] + " " + tokens[i + 1])
    return ngrams


def _is_usable_token(chars: list[str]) -> bool:
    """Tokens of length >= 2 are kept; single ASCII characters are noise."""
    if len(chars) >= MIN_TOKEN_LENGTH:
        return True
    if len(chars) == 1:
        return not chars[0].isascii() and chars[0].isalnum()
    return False


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_data(path: str) -> list[tuple[str, int]]:
    """Load labeled data from CSV with columns: text,label (0=SAFE, 1=THREAT)."""
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = row["text"].strip()
            label = int(row["label"])
            if text:
                rows.append((text, label))
    return rows


def split_train_val_test(rows, train_frac=0.7, val_frac=0.15, seed=42):
    """Leakage-resistant split: shuffle, then split. Returns (train, val, test)."""
    rng = np.random.RandomState(seed)
    indices = rng.permutation(len(rows))
    n = len(rows)
    n_train = int(n * train_frac)
    n_val = int(n * val_frac)
    train_idx = indices[:n_train]
    val_idx = indices[n_train : n_train + n_val]
    test_idx = indices[n_train + n_val :]
    return (
        [rows[i] for i in train_idx],
        [rows[i] for i in val_idx],
        [rows[i] for i in test_idx],
    )


# ---------------------------------------------------------------------------
# Vocabulary and IDF
# ---------------------------------------------------------------------------

def build_vocabulary(train_rows, min_df=1):
    """Build ordered vocabulary from training data, filtering by min_df."""
    doc_freq = Counter()
    for text, _ in train_rows:
        terms = set(preprocess(text))
        for term in terms:
            doc_freq[term] += 1

    n_docs = len(train_rows)
    vocab_terms = [t for t, df in doc_freq.items() if df >= min_df]
    vocab_terms.sort()  # deterministic ordering

    idf = {}
    for term in vocab_terms:
        df = doc_freq[term]
        idf[term] = math.log((n_docs + 1) / (df + 1)) + 1.0  # smooth IDF

    return vocab_terms, idf


def term_to_index(vocab):
    return {t: i for i, t in enumerate(vocab)}


# ---------------------------------------------------------------------------
# TF-IDF vectorization (must match Kotlin TfIdfVectorizer exactly)
# ---------------------------------------------------------------------------

def vectorize(terms, vocab, idf, term_to_idx):
    """Raw-count TF * IDF, L2 normalized. Returns numpy array."""
    vocab_size = len(vocab)
    vec = np.zeros(vocab_size, dtype=np.float64)
    if not terms or vocab_size == 0:
        return vec

    tf = Counter(terms)
    sq_sum = 0.0
    for term, count in tf.items():
        idx = term_to_idx.get(term)
        if idx is None:
            continue  # OOV
        tfidf = count * idf[term]
        vec[idx] = tfidf
        sq_sum += tfidf * tfidf

    norm = math.sqrt(sq_sum)
    if norm > 0.0:
        vec = vec / norm
    return vec


# ---------------------------------------------------------------------------
# Logistic regression (pure numpy gradient descent)
# ---------------------------------------------------------------------------

def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.clip(z, -500, 500)))


def train_logistic_regression(X, y, lr=0.1, epochs=2000, l2_lambda=0.01, seed=42):
    """Train logistic regression with L2 regularization. Returns (w, b)."""
    rng = np.random.RandomState(seed)
    n_samples, n_features = X.shape
    w = rng.normal(0, 0.01, n_features)
    b = 0.0

    for _ in range(epochs):
        scores = X @ w + b
        p = sigmoid(scores)
        grad_w = (X.T @ (p - y)) / n_samples + (l2_lambda / n_samples) * w
        grad_b = np.mean(p - y)
        w -= lr * grad_w
        b -= lr * grad_b

    return w, b


# ---------------------------------------------------------------------------
# Calibration (Platt scaling) — optional, disabled by default
# ---------------------------------------------------------------------------

def calibrate_platt(scores, y_true):
    """Fit Platt scaling: p = sigmoid(A * score + B). Returns (A, B)."""
    # Simple logistic regression on the scores (1-D feature)
    X = scores.reshape(-1, 1).astype(np.float64)  # (n, 1)
    lr = 0.1
    epochs = 2000
    n = len(X)
    w = np.array([0.1])  # shape (1,)
    B = 0.0

    for _ in range(epochs):
        z = X @ w + B  # (n,) broadcast
        p = sigmoid(z)
        grad_w = (X.T @ (p - y_true)) / n + 0.01 * w / n  # (1,)
        grad_b = np.mean(p - y_true)
        w = w - lr * grad_w
        B = B - lr * grad_b

    return float(w[0]), float(B)


def apply_platt(score, A, B):
    return sigmoid(A * score + B)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(X, y, w, b, threshold=0.5, A=None, B=None):
    """Return metrics dict."""
    scores = X @ w + b
    if A is not None and B is not None:
        probs = np.array([apply_platt(s, A, B) for s in scores])
    else:
        probs = sigmoid(scores)
    preds = (probs >= threshold).astype(int)

    tp = int(np.sum((preds == 1) & (y == 1)))
    tn = int(np.sum((preds == 0) & (y == 0)))
    fp = int(np.sum((preds == 1) & (y == 0)))
    fn = int(np.sum((preds == 0) & (y == 1)))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "total": len(y),
    }


# ---------------------------------------------------------------------------
# Threshold selection
# ---------------------------------------------------------------------------

def select_threshold(X_val, y_val, w, b, A=None, B=None):
    """Choose threshold maximizing F1 on validation data."""
    scores = X_val @ w + b
    if A is not None and B is not None:
        probs = np.array([apply_platt(s, A, B) for s in scores])
    else:
        probs = sigmoid(scores)

    best_threshold = 0.5
    best_f1 = -1.0
    for t in np.linspace(0.05, 0.95, 181):
        preds = (probs >= t).astype(int)
        tp = int(np.sum((preds == 1) & (y_val == 1)))
        fp = int(np.sum((preds == 1) & (y_val == 0)))
        fn = int(np.sum((preds == 0) & (y_val == 1)))
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = float(t)
    return best_threshold


# ---------------------------------------------------------------------------
# Model saving
# ---------------------------------------------------------------------------

def save_model(vocab, idf, weights, bias, threshold, is_calibrated,
               model_version, detector_id, detector_version,
               label_map, feature_config, training_info, output_path):
    model = {
        "model_version": model_version,
        "detector_id": detector_id,
        "detector_version": detector_version,
        "vocabulary": vocab,
        "idf": [float(v) for v in idf],
        "weights": [float(v) for v in weights],
        "bias": float(bias),
        "threshold": float(threshold),
        "label_map": [[k, v] for k, v in label_map.items()],
        "is_calibrated": bool(is_calibrated),
        "feature_config": feature_config,
        "training_info": training_info,
    }
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(model, f, indent=2, ensure_ascii=False)
    print(f"Model saved to {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Train SMS Specialist Classifier")
    parser.add_argument("--data", required=True, help="Path to labeled CSV (text,label)")
    parser.add_argument("--output", required=True, help="Output JSON model path")
    parser.add_argument("--model-version", default="1.0.0")
    parser.add_argument("--min-df", type=int, default=1)
    parser.add_argument("--epochs", type=int, default=2000)
    parser.add_argument("--lr", type=float, default=0.1)
    parser.add_argument("--l2", type=float, default=0.01)
    parser.add_argument("--calibrate", action="store_true", help="Enable Platt scaling calibration")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    # Load data
    rows = load_data(args.data)
    if len(rows) < 10:
        print("ERROR: Need at least 10 labeled examples.", file=sys.stderr)
        sys.exit(1)

    n_threat = sum(1 for _, l in rows if l == 1)
    n_safe = len(rows) - n_threat
    print(f"Loaded {len(rows)} examples: {n_safe} SAFE, {n_threat} THREAT")

    # Split
    train, val, test = split_train_val_test(rows, seed=args.seed)
    print(f"Split: {len(train)} train, {len(val)} val, {len(test)} test")

    # Build vocabulary + IDF from training only
    vocab, idf = build_vocabulary(train, min_df=args.min_df)
    term_idx = term_to_index(vocab)
    print(f"Vocabulary size: {len(vocab)}")

    # Vectorize
    def vectorize_all(data_rows):
        Xs = []
        ys = []
        for text, label in data_rows:
            terms = preprocess(text)
            vec = vectorize(terms, vocab, idf, term_idx)
            Xs.append(vec)
            ys.append(label)
        return np.array(Xs), np.array(ys, dtype=np.float64)

    X_train, y_train = vectorize_all(train)
    X_val, y_val = vectorize_all(val)
    X_test, y_test = vectorize_all(test)

    # Train logistic regression
    w, b = train_logistic_regression(
        X_train, y_train, lr=args.lr, epochs=args.epochs, l2_lambda=args.l2, seed=args.seed
    )

    # Calibration (optional)
    A, B = None, None
    is_calibrated = False
    if args.calibrate and len(val) > 0:
        val_scores = X_val @ w + b
        A, B = calibrate_platt(val_scores, y_val)
        is_calibrated = True
        print(f"Platt calibration: A={A:.4f}, B={B:.4f}")

    # Threshold selection on validation
    threshold = select_threshold(X_val, y_val, w, b, A, B)
    print(f"Selected threshold: {threshold:.4f}")

    # Final evaluation on held-out test set
    metrics = evaluate(X_test, y_test, w, b, threshold, A, B)
    print("\n=== Test Set Results ===")
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    # Save model
    feature_config = {
        "ngram_range": [1, 2],
        "min_token_length": MIN_TOKEN_LENGTH,
        "use_idf": True,
        "smooth_idf": True,
        "sublinear_tf": False,
        "norm": "l2",
        "unicode_normalization": "NFC",
        "lowercase": True,
    }
    training_info = {
        "dataset": os.path.basename(args.data),
        "num_training_samples": len(train),
        "num_validation_samples": len(val),
        "num_test_samples": len(test),
        "vocabulary_size": len(vocab),
        "threshold": threshold,
        "is_calibrated": is_calibrated,
        "created_by": "tools/sms_classifier/train.py",
        "note": "Replace with real dataset provenance before production use.",
    }
    label_map = {"SAFE": 0, "THREAT": 1}

    save_model(
        vocab=vocab,
        idf=[idf[t] for t in vocab],
        weights=w,
        bias=b,
        threshold=threshold,
        is_calibrated=is_calibrated,
        model_version=args.model_version,
        detector_id="SmsSpecialistClassifier",
        detector_version="1.0.0",
        label_map=label_map,
        feature_config=feature_config,
        training_info=training_info,
        output_path=args.output,
    )


if __name__ == "__main__":
    main()
