"""
Phishing-URL host model — Python training pipeline (Roadmap 2.4, Task C).

Trains a host-only character n-gram TF-IDF logistic regression on the UCI
PhiUSIIL dataset and emits a JSON artifact for the Kotlin UrlHostClassifier.

REPRODUCIBILITY CONTRACT (must match the Kotlin port exactly)
-------------------------------------------------------------
Host normalisation of a raw URL string:

  1. lowercase and strip surrounding whitespace; if the string has no "://"
     prefix, prepend "http://".
  2. netloc = substring up to the first "/", "?" or "#"; drop any userinfo
     (everything up to and including the LAST "@"); drop any ":port"
     (for "[...]" IPv6 literals the brackets and their content are kept and
     only a trailing ":<digits>" outside the brackets is dropped); remove a
     single trailing "." from the host.
  3. remove one leading "www." (only one, only if still leading).
  4. text fed to the n-grammer = "^" + host + "$".
  5. features = every character n-gram of length 3, 4 and 5 of that text,
     counted once per occurrence (raw TF).

Feature maths:

  6.  TF   = raw n-gram count
  7.  IDF  = ln((n_docs + 1) / (df + 1)) + 1   (smooth IDF, train docs only)
  8.  TF-IDF = TF * IDF, then L2-normalise the row
  9.  p = sigmoid(w . x + b)
  10. phishing when p >= threshold, else benign

No torch / pandas / pyarrow / sklearn. Pure Python + numpy + scipy only.

Usage:
    py train_host_model.py --zip data/raw/phiusiil.zip \
        --output out/url_host_model.json --model-version 1.0.0
"""

import argparse
import csv
import io
import json
import math
import os
import sys
import zipfile
from collections import Counter

import numpy as np

# ---------------------------------------------------------------------------
# Host normalisation (must match Kotlin UrlHostNormalizer exactly)
# ---------------------------------------------------------------------------

NGRAM_MIN = 3
NGRAM_MAX = 5
MAX_FEATURES = 20000
MIN_DF = 3


def normalise_host(url: str) -> str:
    """Steps 1-3 of the reproducibility contract. Returns "" when unusable."""
    s = (url or "").strip().lower()
    if not s:
        return ""
    if "://" not in s:
        s = "http://" + s
    rest = s.split("://", 1)[1]

    # netloc ends at the first path/query/fragment separator
    end = len(rest)
    for ch in ("/", "?", "#"):
        i = rest.find(ch)
        if 0 <= i < end:
            end = i
    netloc = rest[:end]

    # drop userinfo: everything up to the LAST "@" (passwords may contain "@")
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]

    # drop ":port"; keep bracketed IPv6 literals intact
    if netloc.startswith("["):
        close = netloc.find("]")
        host = netloc[: close + 1] if close != -1 else netloc
        tail = netloc[close + 1 :] if close != -1 else ""
        if tail.startswith(":") and tail[1:].isdigit():
            pass  # port already excluded by slicing at "]"
        elif tail and not tail.startswith(":"):
            host = host + tail
    else:
        host = netloc.split(":", 1)[0]

    # single trailing dot (FQDN root label)
    if host.endswith("."):
        host = host[:-1]
    # single leading "www."
    if host.startswith("www."):
        host = host[4:]
    return host


def host_text(host: str) -> str:
    """Step 4: the exact string the n-grammer sees."""
    return "^" + host + "$"


def char_ngrams(text: str, nmin: int = NGRAM_MIN, nmax: int = NGRAM_MAX) -> Counter:
    """Step 5: character n-grams of length nmin..nmax with occurrence counts."""
    counts: Counter = Counter()
    n = len(text)
    for k in range(nmin, nmax + 1):
        for i in range(n - k + 1):
            counts[text[i : i + k]] += 1
    return counts


# ---------------------------------------------------------------------------
# Data loading (PhiUSIIL: label 1 = LEGITIMATE, label 0 = PHISHING)
# ---------------------------------------------------------------------------

CSV_NAME = "PhiUSIIL_Phishing_URL_Dataset.csv"


def load_dataset(zip_path: str):
    """Read (host, our_label) pairs straight out of the zip.

    our_label: 1 = phishing, 0 = benign  (PhiUSIIL is inverted).
    """
    rows = []
    raw_total = 0
    with zipfile.ZipFile(zip_path) as zf:
        with zf.open(CSV_NAME) as fh:
            text = io.TextIOWrapper(fh, encoding="utf-8-sig", newline="")
            reader = csv.DictReader(text)
            for row in reader:
                raw_total += 1
                url = row["URL"]
                src_label = int(row["label"])  # 1 = legitimate, 0 = phishing
                host = normalise_host(url)
                if not host:
                    continue
                rows.append((host, 1 - src_label, url))
    return rows, raw_total


# Free-hosting / CDN / shortener parents: phishing lives on their subdomains, so
# they are never added as benign from the Tranco list.
TRANCO_EXCLUDE = {
    "firebaseapp.com", "web.app", "github.io", "blogspot.com", "weebly.com", "wixsite.com",
    "000webhostapp.com", "ngrok.io", "ngrok-free.app", "vercel.app", "netlify.app", "pages.dev",
    "workers.dev", "glitch.me", "repl.co", "herokuapp.com", "azurewebsites.net", "appspot.com",
    "duckdns.org", "bit.ly", "tinyurl.com", "wordpress.com", "sites.google.com", "googleusercontent.com",
    "r2.dev", "framer.app", "webflow.io", "square.site", "godaddysites.com", "myshopify.com",
}

# Real Indian sites that the PhiUSIIL benign side under-represents.
INDIAN_BENIGN = (
    "sbi.co.in onlinesbi.sbi sbi.bank.in hdfcbank.com icicibank.com axisbank.com kotak.com "
    "pnbindia.in bankofbaroda.in canarabank.com unionbankofindia.co.in amazon.in flipkart.com "
    "paytm.com phonepe.com irctc.co.in incometax.gov.in uidai.gov.in npci.org.in myntra.com "
    "swiggy.com zomato.com jio.com airtel.in bsnl.co.in indiapost.gov.in india.gov.in gov.in nic.in "
    "meesho.com bigbasket.com makemytrip.com"
).split()


def load_extra_benign(tranco_zip, top_n, phishing_hosts):
    """Benign hosts from the Tranco top list (tranco-list.eu) plus INDIAN_BENIGN."""
    extra = []
    if tranco_zip:
        with zipfile.ZipFile(tranco_zip) as zf:
            with zf.open("top-1m.csv") as fh:
                for i, line in enumerate(io.TextIOWrapper(fh, encoding="utf-8", newline="")):
                    if i >= top_n:
                        break
                    parts = line.strip().split(",", 1)
                    if len(parts) == 2:
                        extra.append(parts[1])
    extra += INDIAN_BENIGN
    rows = []
    for domain in extra:
        host = normalise_host(domain)
        if not host or host in TRANCO_EXCLUDE or host in phishing_hosts:
            continue
        rows.append((host, 0, "http://" + domain))
    return rows


def deduplicate(rows):
    """One entry per normalised host; hosts seen with both labels are dropped."""
    label_of = {}
    conflict = set()
    for host, label, _url in rows:
        if host in label_of:
            if label_of[host] != label:
                conflict.add(host)
        else:
            label_of[host] = label
    kept = []
    seen = set()
    for host, label, url in rows:
        if host in conflict or host in seen:
            continue
        seen.add(host)
        kept.append((host, label, url))
    return kept, len(conflict)


def split_stratified(rows, train_frac=0.7, val_frac=0.15, seed=42):
    """70/15/15 split, stratified by label (one row per host already)."""
    rng = np.random.RandomState(seed)
    train, val, test = [], [], []
    for label in (0, 1):
        idx = np.array([i for i, r in enumerate(rows) if r[1] == label])
        idx = rng.permutation(idx)
        n = len(idx)
        n_train = int(n * train_frac)
        n_val = int(n * val_frac)
        parts = (idx[:n_train], idx[n_train : n_train + n_val], idx[n_train + n_val :])
        for bucket, part in zip((train, val, test), parts):
            bucket.extend(rows[i] for i in part)
    return train, val, test


# ---------------------------------------------------------------------------
# Vocabulary / IDF / vectorisation
# ---------------------------------------------------------------------------

def build_vocabulary(train_rows, min_df=MIN_DF, max_features=MAX_FEATURES):
    """n-grams with df >= min_df on train; keep the top max_features by df
    (ties broken alphabetically). Returns (sorted vocab list, idf array)."""
    doc_freq: Counter = Counter()
    for host, _label, _url in train_rows:
        for term in char_ngrams(host_text(host)):
            doc_freq[term] += 1

    n_docs = len(train_rows)
    terms = [t for t, df in doc_freq.items() if df >= min_df]
    if max_features and len(terms) > max_features:
        terms.sort(key=lambda t: (-doc_freq[t], t))
        terms = terms[:max_features]
    terms.sort()  # deterministic ordering

    idf = np.array(
        [math.log((n_docs + 1) / (doc_freq[t] + 1)) + 1.0 for t in terms],
        dtype=np.float64,
    )
    return terms, idf


def vectorize_rows(rows, vocab, idf):
    """TF (raw count) * IDF, L2-normalised. Returns a csr_matrix + labels."""
    from scipy.sparse import csr_matrix

    term_idx = {t: i for i, t in enumerate(vocab)}
    indptr = [0]
    indices = []
    values = []
    labels = []
    for host, label, _url in rows:
        tf = char_ngrams(host_text(host))
        idx, vals = [], []
        sq = 0.0
        for term, count in tf.items():
            i = term_idx.get(term)
            if i is None:
                continue
            v = count * idf[i]
            idx.append(i)
            vals.append(v)
            sq += v * v
        norm = math.sqrt(sq)
        if norm > 0.0:
            vals = [v / norm for v in vals]
        indices.extend(idx)
        values.extend(vals)
        indptr.append(len(indices))
        labels.append(label)
    X = csr_matrix(
        (np.asarray(values, dtype=np.float64), np.asarray(indices, dtype=np.int32),
         np.asarray(indptr, dtype=np.int64)),
        shape=(len(rows), len(vocab)),
        dtype=np.float64,
    )
    return X, np.asarray(labels, dtype=np.float64)


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.clip(z, -500, 500)))


# ---------------------------------------------------------------------------
# Logistic regression (scipy L-BFGS-B, L2 on w)
# ---------------------------------------------------------------------------

def train_logistic_regression(X, y, l2_lambda=1.0, max_iter=500):
    from scipy.optimize import minimize

    n_samples, _n_features = X.shape

    def loss_grad(params):
        w, b = params[:-1], params[-1]
        z = np.asarray(X @ w).ravel() + b
        loss = (
            np.sum(np.logaddexp(0.0, z) - y * z) / n_samples
            + 0.5 * l2_lambda / n_samples * (w @ w)
        )
        r = (sigmoid(z) - y) / n_samples
        grad = np.empty_like(params)
        grad[:-1] = np.asarray(X.T @ r).ravel() + l2_lambda / n_samples * w
        grad[-1] = r.sum()
        return loss, grad

    res = minimize(
        loss_grad,
        np.zeros(X.shape[1] + 1),
        jac=True,
        method="L-BFGS-B",
        options={"maxiter": max_iter},
    )
    print(
        f"  L-BFGS l2={l2_lambda}: {res.nit} iterations, loss={res.fun:.6f}, "
        f"converged={res.success}"
    )
    return res.x[:-1], float(res.x[-1])


# ---------------------------------------------------------------------------
# Evaluation / threshold
# ---------------------------------------------------------------------------

def metrics_at(probs, y, threshold):
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
        "false_positive_rate": fpr,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "n": len(y),
    }


def select_threshold(probs, y, min_precision=0.98):
    """Smallest threshold on val whose phishing precision is >= min_precision."""
    order = np.argsort(-probs, kind="stable")
    ps = probs[order]
    ys = y[order]
    cum_tp = np.cumsum(ys == 1)
    cum_fp = np.cumsum(ys == 0)
    # group ties: end index of each distinct-probability block
    ends = np.flatnonzero(np.concatenate([ps[:-1] != ps[1:], [True]]))
    precision = cum_tp[ends] / (ends + 1)
    valid = np.flatnonzero(precision >= min_precision)
    if valid.size == 0:
        return 1.0, False
    # ends are ordered by descending probability -> last valid = smallest threshold
    return float(ps[ends[valid[-1]]]), True


def r6(x) -> float:
    """Round to 6 significant digits (keeps the artifact small)."""
    return float(f"{float(x):.6g}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def pick_parity(rows, k=20):
    """Deterministic, evenly spaced (alphabetically) k hosts per class."""
    out = []
    for label in (1, 0):
        hosts = sorted(r[0] for r in rows if r[1] == label)
        if not hosts:
            continue
        if len(hosts) <= k:
            chosen = hosts
        else:
            step = (len(hosts) - 1) / (k - 1)
            chosen = [hosts[int(round(i * step))] for i in range(k)]
        out.extend(chosen)
    return out


def main():
    parser = argparse.ArgumentParser(description="Train the phishing-URL host model")
    parser.add_argument("--zip", required=True, help="Path to phiusiil.zip")
    parser.add_argument("--output", required=True, help="Output JSON model path")
    parser.add_argument("--parity", default=None, help="Parity JSON path "
                        "(default: host_model_parity.json next to --output)")
    parser.add_argument("--model-version", default="1.0.0")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--l2", default="0.3,1,3",
                        help="Comma-separated L2 candidates (best val F1 wins)")
    parser.add_argument("--max-iter", type=int, default=500)
    parser.add_argument("--tranco", default=None, help="Path to Tranco top-1m.csv.zip (extra benign hosts)")
    parser.add_argument("--tranco-top", type=int, default=30000)
    args = parser.parse_args()

    # ---- data -------------------------------------------------------------
    rows, raw_total = load_dataset(args.zip)
    phishing_hosts = {h for h, label, _u in rows if label == 1}
    extra = load_extra_benign(args.tranco, args.tranco_top, phishing_hosts)
    print(f"Extra benign hosts (Tranco top {args.tranco_top if args.tranco else 0} + Indian list): {len(extra)}")
    rows, n_conflicts = deduplicate(rows + extra)
    print(
        f"Loaded {raw_total} rows -> {len(rows)} unique hosts "
        f"({n_conflicts} hosts dropped for conflicting labels)"
    )

    train, val, test = split_stratified(rows, seed=args.seed)
    y_train = np.array([r[1] for r in train], dtype=np.float64)
    y_val = np.array([r[1] for r in val], dtype=np.float64)
    y_test = np.array([r[1] for r in test], dtype=np.float64)
    print(
        f"Split: {len(train)} train ({int(y_train.sum())} phishing), "
        f"{len(val)} val ({int(y_val.sum())} phishing), "
        f"{len(test)} test ({int(y_test.sum())} phishing)"
    )

    # ---- features ---------------------------------------------------------
    vocab, idf = build_vocabulary(train)
    print(f"Vocabulary: {len(vocab)} n-grams (df >= {MIN_DF}, top {MAX_FEATURES})")

    X_train, y_train = vectorize_rows(train, vocab, idf)
    X_val, y_val = vectorize_rows(val, vocab, idf)
    X_test, y_test = vectorize_rows(test, vocab, idf)
    print(f"Train matrix: {X_train.shape}, nnz={X_train.nnz}")

    # ---- model selection on validation ------------------------------------
    l2_candidates = [float(x) for x in args.l2.split(",") if x.strip()]
    best = None
    for l2 in l2_candidates:
        w, b = train_logistic_regression(X_train, y_train, l2_lambda=l2,
                                         max_iter=args.max_iter)
        val_probs = sigmoid(np.asarray(X_val @ w).ravel() + b)
        threshold, ok = select_threshold(val_probs, y_val)
        val_m = metrics_at(val_probs, y_val, threshold)
        val_m50 = metrics_at(val_probs, y_val, 0.5)
        print(
            f"  val l2={l2}: threshold={threshold:.6g} precision={val_m['precision']:.4f} "
            f"recall={val_m['recall']:.4f} f1={val_m['f1']:.4f} (threshold_found={ok}); "
            f"f1@0.5={val_m50['f1']:.4f}"
        )
        if best is None or val_m["f1"] > best["f1"]:
            best = {"l2": l2, "w": w, "b": b, "threshold": threshold,
                    "f1": val_m["f1"], "val": val_m}

    w, b, threshold = best["w"], best["b"], best["threshold"]
    print(f"Selected l2={best['l2']}, threshold={threshold:.6g}")

    # ---- held-out test ----------------------------------------------------
    test_probs = sigmoid(np.asarray(X_test @ w).ravel() + b)
    test_m = metrics_at(test_probs, y_test, threshold)
    print("\n=== Test Set ===")
    for k in ("precision", "recall", "f1", "false_positive_rate", "n"):
        v = test_m[k]
        print(f"  {k}: {v if k == 'n' else f'{v:.4f}'}")

    # ---- artifact ---------------------------------------------------------
    out_dir = os.path.dirname(os.path.abspath(args.output))
    os.makedirs(out_dir, exist_ok=True)
    model = {
        "model_version": args.model_version,
        "detector_id": "UrlHostClassifier",
        "ngram_min": NGRAM_MIN,
        "ngram_max": NGRAM_MAX,
        "vocabulary": vocab,
        "idf": [r6(v) for v in idf],
        "weights": [r6(v) for v in w],
        "bias": r6(b),
        "threshold": r6(threshold),
        "dataset": "PhiUSIIL (UCI, CC BY 4.0) + Tranco top 30k benign (tranco-list.eu) + Indian bank/gov list, host-only, deduplicated",
        "metrics": {
            "test": {k: (r6(v) if k != "n" else int(v)) for k, v in test_m.items()
                     if k in ("precision", "recall", "f1", "false_positive_rate", "n")}
        },
    }
    with open(args.output, "w", encoding="utf-8", newline="") as f:
        json.dump(model, f, ensure_ascii=False, separators=(",", ":"))
    size = os.path.getsize(args.output)
    print(f"\nModel saved to {args.output} ({size} bytes, {size / 1024 / 1024:.2f} MB)")

    # ---- parity set -------------------------------------------------------
    parity_path = args.parity or os.path.join(out_dir, "host_model_parity.json")
    prob_of = {r[0]: p for r, p in zip(test, test_probs)}
    by_host = {r[0]: r for r in test}
    entries = []
    for host in pick_parity(test, k=20):
        _h, label, url = by_host[host]
        entries.append(
            {
                "url": url,
                "host": host,
                "text": host_text(host),
                "label": int(label),
                "probability": r6(prob_of[host]),
            }
        )
    parity = {
        "model_version": args.model_version,
        "detector_id": "UrlHostClassifier",
        "ngram_min": NGRAM_MIN,
        "ngram_max": NGRAM_MAX,
        "entries": entries,
    }
    with open(parity_path, "w", encoding="utf-8", newline="") as f:
        json.dump(parity, f, ensure_ascii=False, separators=(",", ":"))
    n_phish = sum(1 for e in entries if e["label"] == 1)
    print(f"Parity saved to {parity_path} ({len(entries)} hosts: "
          f"{n_phish} phishing, {len(entries) - n_phish} benign)")

    # ---- sanity check -----------------------------------------------------
    def predict_host(host: str) -> float:
        X, _ = vectorize_rows([(host, 0, "")], vocab, idf)
        return float(sigmoid(np.asarray(X @ w).ravel() + b)[0])

    sanity = [
        "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "amazon.in",
        "irctc.co.in", "google.com", "paytm.com", "flipkart.com",
        "sbi-kyc-update.xyz", "hdfc-netbanking-verify.top",
        "amaz0n-refund.in.net", "paytm-kyc.online", "192.168.4.1", "bit.ly",
    ]
    print("\n=== Sanity check (probability of phishing) ===")
    for raw in sanity:
        host = normalise_host(raw)
        p = predict_host(host)
        print(f"  {raw:32s} -> {host:32s} p={p:.6f}")


if __name__ == "__main__":
    main()
