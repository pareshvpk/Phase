"""
URL Specialist Classifier — Python training pipeline.

Trains a logistic regression model over structural URL features that mirror
the Kotlin UrlSpecialistDetector heuristics exactly. The model artifact is a
JSON file containing feature names, weights, and bias, consumable by an
offline Kotlin feature extractor.

REPRODUCIBILITY CONTRACT
------------------------
The Python feature extraction mirrors
com.arm.threatassistant.domain.detection.urldetection.UrlSpecialistDetector
and its companion lists in UrlDetectionEvidence.kt:

  1. url_length               — raw URL string length (numeric)
  2. subdomain_count          — host label count minus 2 (domain + TLD)
  3. has_ip_host              — host is an IPv4 dotted-decimal literal
  4. is_url_shortener         — host matches the offline shortener list
  5. suspicious_tld           — TLD matches the offline suspicious-TLD list
  6. homograph_attack         — mixed Latin/Cyrillic/Greek script or
                                Cyrillic look-alike characters in host
  7. suspicious_subdomain     — subdomain_count > 3 (MAX_SUBDOMAIN_DEPTH)
  8. misleading_structure     — '@' in URL, or a brand name after a path
                                separator ("/brand" or "%2Fbrand")
  9. unusual_port             — explicit port that differs from the scheme
                                default (http=80, https=443, ftp=21)
 10. encoded_characters       — '%' present anywhere in the URL
 11. excessive_length         — url_length > 200 (MAX_URL_LENGTH)
 12. suspicious_domain_keywords — host contains any keyword from the
                                offline suspicious-keyword list

Numeric features (url_length, subdomain_count) are standardized to z-scores;
their means and stds are stored in the artifact so the app can apply the
same transform.

Model: logistic regression, p = sigmoid(w · x + b). Prediction: MALICIOUS
if p >= threshold else BENIGN.

No scikit-learn dependency. Pure Python + numpy only.

Usage:
    python train.py --data sample.csv --output out/url_classifier_model.json
"""

import argparse
import csv
import json
import os
import re
import sys
from urllib.parse import urlparse

import numpy as np

NUMERIC_FEATURES = ["url_length", "subdomain_count"]

# ---------------------------------------------------------------------------
# Constants mirrored from UrlSpecialistDetector / UrlDetectionEvidence.kt
# ---------------------------------------------------------------------------

MAX_URL_LENGTH = 200
MAX_SUBDOMAIN_DEPTH = 3

IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
HAS_CYRILLIC = re.compile(r"[\u0400-\u04FF]")
HAS_GREEK = re.compile(r"[\u0370-\u03FF]")
HAS_LATIN = re.compile(r"[a-zA-Z]")
# а е о р с х
CYRILLIC_LOOK_ALIKES = ["\u0430", "\u0435", "\u043e", "\u0440", "\u0441", "\u0445"]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "adf.ly",
    "bit.do", "cutt.ly", "rebrand.ly", "short.url", "is.gd", "cli.re",
    "po.st", "bc.vc", "tiny.cc", "tr.im", "su.pr", "chilp.it", "x.co",
]

SUSPICIOUS_TLDS = [
    "xyz", "top", "club", "loan", "buzz", "work", "date", "download",
    "review", "country", "stream", "science", "win", "men", "racing",
    "cf", "ga", "gq", "ml", "tk", "cm", "biz",
]

BRAND_NAMES = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "instagram", "whatsapp", "netflix", "bank", "hdfc", "sbi", "icici",
    "axis", "upi", "phonepe", "paytm", "flipkart", "myntra", "snapdeal",
]

SUSPICIOUS_DOMAIN_KEYWORDS = [
    "secure", "verify", "account", "banking", "payment", "update",
    "confirm", "suspend", "limited", "urgent", "bonus", "winner",
    "prize", "reward", "login", "signin", "auth", "validate",
]

SCHEME_DEFAULT_PORTS = {"https": 443, "http": 80, "ftp": 21}

FEATURE_NAMES = [
    "url_length",
    "subdomain_count",
    "has_ip_host",
    "is_url_shortener",
    "suspicious_tld",
    "homograph_attack",
    "suspicious_subdomain",
    "misleading_structure",
    "unusual_port",
    "encoded_characters",
    "excessive_length",
    "suspicious_domain_keywords",
]

LABEL_MAP = {"benign": 0, "malicious": 1}


# ---------------------------------------------------------------------------
# Feature extraction (must match Kotlin UrlSpecialistDetector exactly)
# ---------------------------------------------------------------------------

def extract_host(url: str) -> str | None:
    """Extract the host like java.net.URI.host with the Kotlin fallback.

    Bare www. references have no scheme; prepend http:// so parsing works
    (matches the Kotlin parseTarget handling). The netloc is used directly
    so non-ASCII (homograph) hosts are preserved, with userinfo and port
    stripped the same way the Kotlin authority fallback does.
    """
    parse_target = url
    if parse_target.lower().startswith("www."):
        parse_target = "http://" + parse_target
    try:
        parsed = urlparse(parse_target)
    except ValueError:
        return None
    netloc = parsed.netloc
    if not netloc:
        return None
    host_port = netloc.split("@")[-1]
    if host_port.startswith("["):
        return host_port.split("]")[0] + "]"
    return host_port.split(":")[0]


def extract_scheme_and_port(url: str) -> tuple[str | None, int | None]:
    parse_target = url
    if parse_target.lower().startswith("www."):
        parse_target = "http://" + parse_target
    try:
        parsed = urlparse(parse_target)
    except ValueError:
        return None, None
    scheme = parsed.scheme if parsed.scheme else None
    port = parsed.port  # None when absent or invalid
    return scheme, port


def extract_features(url: str) -> list[float]:
    """Compute the feature vector for one URL, mirroring the Kotlin detector."""
    url_length = float(len(url))
    has_encoded_characters = "%" in url
    excessive_length = url_length > MAX_URL_LENGTH

    host = extract_host(url)
    scheme, port = extract_scheme_and_port(url)

    is_ip_based = bool(host) and bool(IPV4_PATTERN.match(host))  # type: ignore[arg-type]
    is_shortener = False
    suspicious_tld = False
    homograph = False
    suspicious_subdomain = False
    suspicious_keywords = False
    subdomain_count = 0.0

    if host is not None:
        lower = host.lower()
        subdomain_count = float(max(len(lower.split(".")) - 2, 0))
        is_shortener = any(lower == d or lower.endswith("." + d) for d in SHORTENER_DOMAINS)
        parts = lower.split(".")
        suspicious_tld = len(parts) >= 2 and parts[-1] in SUSPICIOUS_TLDS
        # isSuspiciousSubdomain: more than MAX_SUBDOMAIN_DEPTH subdomains
        suspicious_subdomain = len(parts) > 2 and (len(parts) - 2) > MAX_SUBDOMAIN_DEPTH
        suspicious_keywords = any(k in lower for k in SUSPICIOUS_DOMAIN_KEYWORDS)
        # isHomographAttack: mixed scripts or Cyrillic look-alikes
        has_latin = bool(HAS_LATIN.search(lower))
        has_cyrillic = bool(HAS_CYRILLIC.search(lower))
        has_greek = bool(HAS_GREEK.search(lower))
        mixed_script = has_latin and (has_cyrillic or has_greek)
        has_look_alike = any(c in lower for c in CYRILLIC_LOOK_ALIKES)
        homograph = mixed_script or (has_look_alike and has_latin)

    # isMisleadingStructure: '@' anywhere, or brand name after a path separator
    lower_url = url.lower()
    misleading = "@" in url or any(
        ("/" + brand) in lower_url or ("%2f" + brand) in lower_url
        for brand in BRAND_NAMES
    )

    # isUnusualPort: any port that is not the scheme default (or unknown scheme)
    unusual_port = False
    if port is not None:
        default = SCHEME_DEFAULT_PORTS.get(scheme.lower() if scheme else "")
        unusual_port = default is None or port != default

    return [
        url_length,
        subdomain_count,
        1.0 if is_ip_based else 0.0,
        1.0 if is_shortener else 0.0,
        1.0 if suspicious_tld else 0.0,
        1.0 if homograph else 0.0,
        1.0 if suspicious_subdomain else 0.0,
        1.0 if misleading else 0.0,
        1.0 if unusual_port else 0.0,
        1.0 if has_encoded_characters else 0.0,
        1.0 if excessive_length else 0.0,
        1.0 if suspicious_keywords else 0.0,
    ]


# ---------------------------------------------------------------------------
# Training (logistic regression, numpy only)
# ---------------------------------------------------------------------------

def sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -35.0, 35.0)))


def standardize_fit(X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Column means and stds for the numeric-feature columns (std 0 -> 1)."""
    idx = [FEATURE_NAMES.index(f) for f in NUMERIC_FEATURES]
    cols = X[:, idx]
    mean = cols.mean(axis=0)
    std = cols.std(axis=0)
    std = np.where(std < 1e-9, 1.0, std)
    return mean, std


def standardize_apply(X: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    idx = [FEATURE_NAMES.index(f) for f in NUMERIC_FEATURES]
    X = X.copy()
    X[:, idx] = (X[:, idx] - mean) / std
    return X


def train_logistic_regression(
    X: np.ndarray,
    y: np.ndarray,
    lr: float,
    epochs: int,
    l2_lambda: float,
    seed: int,
) -> tuple[np.ndarray, float]:
    """Full-batch gradient descent with L2 regularization (bias unregularized)."""
    rng = np.random.default_rng(seed)
    n, d = X.shape
    w = rng.normal(0.0, 0.01, size=d)
    b = 0.0
    for _ in range(epochs):
        p = sigmoid(X @ w + b)
        error = p - y
        grad_w = (X.T @ error) / n + l2_lambda * w
        grad_b = float(np.mean(error))
        w -= lr * grad_w
        b -= lr * grad_b
    return w, b


def accuracy(X: np.ndarray, y: np.ndarray, w: np.ndarray, b: float, threshold: float) -> float:
    preds = (sigmoid(X @ w + b) >= threshold).astype(np.float64)
    return float(np.mean(preds == y))


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_csv(path: str) -> tuple[list[str], np.ndarray]:
    urls: list[str] = []
    labels: list[int] = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "url" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise SystemExit("CSV must have header columns: url,label")
        for row in reader:
            url = (row.get("url") or "").strip()
            label = (row.get("label") or "").strip().lower()
            if not url or label not in LABEL_MAP:
                raise SystemExit(f"Invalid row: url={url!r}, label={label!r} (expected 'malicious' or 'benign')")
            urls.append(url)
            labels.append(LABEL_MAP[label])
    return urls, np.array(labels, dtype=np.float64)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Train URL specialist classifier")
    parser.add_argument("--data", required=True, help="CSV with columns url,label")
    parser.add_argument("--output", default="out/url_classifier_model.json", help="Output JSON path")
    parser.add_argument("--model-version", default="1.0.0")
    parser.add_argument("--lr", type=float, default=0.1)
    parser.add_argument("--epochs", type=int, default=2000)
    parser.add_argument("--l2", type=float, default=1e-4)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    urls, y = load_csv(args.data)
    X_raw = np.array([extract_features(u) for u in urls], dtype=np.float64)
    mean, std = standardize_fit(X_raw)
    X = standardize_apply(X_raw, mean, std)

    w, b = train_logistic_regression(X, y, lr=args.lr, epochs=args.epochs, l2_lambda=args.l2, seed=args.seed)

    train_acc = accuracy(X, y, w, b, threshold=0.5)
    print("=== Training Results ===")
    print(f"  samples: {len(urls)}")
    print(f"  accuracy: {train_acc:.4f}")
    for name, weight in zip(FEATURE_NAMES, w):
        print(f"  {name}: {weight:+.4f}")
    print(f"  bias: {b:+.4f}")

    artifact = {
        "model_version": args.model_version,
        "detector_id": "UrlSpecialistDetector",
        "detector_version": "1.0.0",
        "label_map": {"BENIGN": 0, "MALICIOUS": 1},
        "threshold": 0.5,
        "feature_names": FEATURE_NAMES,
        "numeric_features": NUMERIC_FEATURES,
        "numeric_mean": [float(x) for x in mean],
        "numeric_std": [float(x) for x in std],
        "weights": [float(x) for x in w],
        "bias": float(b),
        "reference_lists": {
            "shortener_domains": SHORTENER_DOMAINS,
            "suspicious_tlds": SUSPICIOUS_TLDS,
            "brand_names": BRAND_NAMES,
            "suspicious_domain_keywords": SUSPICIOUS_DOMAIN_KEYWORDS,
            "cyrillic_look_alikes": CYRILLIC_LOOK_ALIKES,
        },
        "training_info": {
            "dataset": os.path.basename(args.data),
            "num_samples": len(urls),
            "train_accuracy": train_acc,
            "feature_standardization": "z-score on numeric features (numeric_features, numeric_mean, numeric_std)",
            "learning_rate": args.lr,
            "epochs": args.epochs,
            "l2_lambda": args.l2,
            "seed": args.seed,
            "created_by": "tools/url_classifier/train.py",
            "note": "Sample data for development only; verify dataset provenance before production use.",
        },
    }

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"Model written to {args.output}")


if __name__ == "__main__":
    main()
