"""
NSL-KDD network intrusion classifier — training pipeline.

Pure Python + numpy + scipy. No pandas / sklearn / torch. Runs on a
Raspberry Pi 5 after training (inference only needs numpy).

Pipeline:
  1. Parse KDDTrain+ / KDDTest+ (comma separated, no header, 41 features
     followed by attack name and difficulty).
  2. Map the 40+ attack names to 5 classes: normal, dos, probe, r2l, u2r.
  3. One-hot encode protocol_type / service / flag (categories from the
     training split; unknown values at inference become all zeros).
  4. log1p the heavy-tailed count/byte columns, then z-score every column
     with training-split mean/std (std 0 -> 1).
  5. Train a 64-unit ReLU MLP with softmax, scipy L-BFGS, class-weighted
     cross-entropy, L2 1e-4. Hold out 10% for early stopping/model
     selection. Evaluate on the official KDDTest+ set.
  6. Export out/nids_model.json and out/metrics.json.

Usage:
    py tools/network_ids/train.py
"""

import json
import os
import sys

import numpy as np
from scipy.optimize import minimize

SEED = 42
HIDDEN = 64
L2 = 1e-4
VAL_FRACTION = 0.10
CLASS_WEIGHT_EXPONENT = 0.75
MAX_ITER = 400
PATIENCE = 40

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "data", "raw")
OUT_DIR = os.path.join(SCRIPT_DIR, "out")
TRAIN_PATH = os.path.join(DATA_DIR, "KDDTrain+.txt")
TEST_PATH = os.path.join(DATA_DIR, "KDDTest+.txt")
MODEL_PATH = os.path.join(OUT_DIR, "nids_model.json")
METRICS_PATH = os.path.join(OUT_DIR, "metrics.json")

CLASSES = ["normal", "dos", "probe", "r2l", "u2r"]

FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

CATEGORICAL = ["protocol_type", "service", "flag"]

# Heavy-tailed columns that get log1p before z-scoring.
LOG_COLUMNS = [
    "duration", "src_bytes", "dst_bytes", "hot", "num_compromised",
    "num_root", "num_file_creations", "num_access_files", "count",
    "srv_count", "dst_host_count", "dst_host_srv_count",
]

ATTACK_MAP = {}
for _name in (
    "back land neptune pod smurf teardrop apache2 mailbomb processtable "
    "udpstorm"
).split():
    ATTACK_MAP[_name] = "dos"
for _name in "ipsweep nmap portsweep satan mscan saint".split():
    ATTACK_MAP[_name] = "probe"
for _name in (
    "ftp_write guess_passwd imap multihop phf spy warezclient warezmaster "
    "named sendmail snmpgetattack snmpguess xlock xsnoop worm httptunnel"
).split():
    ATTACK_MAP[_name] = "r2l"
for _name in (
    "buffer_overflow loadmodule perl rootkit ps sqlattack xterm"
).split():
    ATTACK_MAP[_name] = "u2r"


def log(msg=""):
    print(msg, flush=True)


def read_rows(path):
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append([part.strip() for part in line.split(",")])
    return rows


def label_to_class(name):
    name = name.strip().lower()
    if name == "normal":
        return "normal"
    if name in ATTACK_MAP:
        return ATTACK_MAP[name]
    # Unknown attack names are treated as r2l-style remote access attempts.
    return "r2l"


def build_schema(train_rows):
    categories = {}
    for col in CATEGORICAL:
        idx = FEATURES.index(col)
        categories[col] = sorted({row[idx] for row in train_rows})
    return {
        "base_features": list(FEATURES),
        "categorical": CATEGORICAL,
        "categories": categories,
        "log1p_columns": list(LOG_COLUMNS),
        "classes": list(CLASSES),
    }


def transform(rows, schema):
    """Rows are string lists; returns (X, feature_names) before z-scoring."""
    n = len(rows)
    columns = []
    names = []
    for idx, name in enumerate(FEATURES):
        if name in CATEGORICAL:
            cats = schema["categories"][name]
            lookup = {cat: j for j, cat in enumerate(cats)}
            block = np.zeros((n, len(cats)), dtype=np.float64)
            for i, row in enumerate(rows):
                j = lookup.get(row[idx])
                if j is not None:
                    block[i, j] = 1.0
            columns.append(block)
            names.extend(["%s=%s" % (name, cat) for cat in cats])
        else:
            values = np.array([float(row[idx]) for row in rows], dtype=np.float64)
            if name in LOG_COLUMNS:
                values = np.log1p(np.maximum(values, 0.0))
            columns.append(values[:, None])
            names.append(name)
    return np.hstack(columns), names


def round_sig(value, sig=6):
    value = float(value)
    if value == 0.0:
        return 0.0
    return float("%.*g" % (sig, value))


def round_vector(values, sig=6):
    return [round_sig(v, sig) for v in np.asarray(values).ravel()]


def round_matrix(matrix, sig=6):
    return [round_vector(row, sig) for row in np.asarray(matrix)]


def unpack(theta, n_in):
    pos = n_in * HIDDEN
    w1 = theta[:pos].reshape(n_in, HIDDEN)
    b1 = theta[pos:pos + HIDDEN]
    pos += HIDDEN
    w2 = theta[pos:pos + HIDDEN * len(CLASSES)].reshape(HIDDEN, len(CLASSES))
    pos += HIDDEN * len(CLASSES)
    b2 = theta[pos:pos + len(CLASSES)]
    return w1, b1, w2, b2


def pack(w1, b1, w2, b2):
    return np.concatenate(
        [w1.ravel(), b1.ravel(), w2.ravel(), b2.ravel()]
    )


def softmax(logits):
    shifted = logits - logits.max(axis=1, keepdims=True)
    exp = np.exp(shifted)
    return exp / exp.sum(axis=1, keepdims=True)


def macro_ce(theta, x, y, n_in):
    w1, b1, w2, b2 = unpack(theta, n_in)
    logits = np.maximum(x @ w1 + b1, 0.0) @ w2 + b2
    probs = softmax(logits)
    ce = -np.log(np.maximum(probs[np.arange(len(y)), y], 1e-12))
    per_class = [ce[y == c].mean() for c in range(len(CLASSES)) if np.any(y == c)]
    return float(np.mean(per_class))


class _StopNow(Exception):
    pass


def make_loss_grad(x, y, sample_weight, n_in):
    n = len(y)
    rows = np.arange(n)

    def loss_grad(theta):
        w1, b1, w2, b2 = unpack(theta, n_in)
        z1 = x @ w1 + b1
        h = np.maximum(z1, 0.0)
        logits = h @ w2 + b2
        probs = softmax(logits)

        ce = -np.mean(sample_weight * np.log(
            np.maximum(probs[rows, y], 1e-12)
        ))
        reg = 0.5 * L2 * (np.sum(w1 * w1) + np.sum(w2 * w2))
        loss = ce + reg

        dlogits = probs.copy()
        dlogits[rows, y] -= 1.0
        dlogits *= (sample_weight / n)[:, None]

        dw2 = h.T @ dlogits + L2 * w2
        db2 = dlogits.sum(axis=0)

        dh = dlogits @ w2.T
        dz1 = dh * (z1 > 0.0)
        dw1 = x.T @ dz1 + L2 * w1
        db1 = dz1.sum(axis=0)

        grad = pack(dw1, db1, dw2, db2)
        return loss, grad

    return loss_grad


def evaluate_predictions(y_true, y_pred):
    labels = list(range(len(CLASSES)))
    cm = np.zeros((len(CLASSES), len(CLASSES)), dtype=int)
    for t, p in zip(y_true, y_pred):
        cm[t, p] += 1

    per_class = {}
    for c, name in enumerate(CLASSES):
        tp = cm[c, c]
        support = cm[c, :].sum()
        predicted = cm[:, c].sum()
        precision = tp / predicted if predicted else 0.0
        recall = tp / support if support else 0.0
        per_class[name] = {
            "precision": round_sig(precision),
            "recall": round_sig(recall),
            "support": int(support),
        }

    normal_idx = CLASSES.index("normal")
    true_attack = np.asarray(y_true) != normal_idx
    pred_attack = np.asarray(y_pred) != normal_idx
    detection_rate = (
        pred_attack[true_attack].mean() if true_attack.any() else 0.0
    )
    false_alarm_rate = (
        pred_attack[~true_attack].mean() if (~true_attack).any() else 0.0
    )
    accuracy = float(np.mean(np.asarray(y_true) == np.asarray(y_pred)))

    return {
        "labels": list(CLASSES),
        "accuracy": round_sig(accuracy),
        "attack_detection_rate": round_sig(detection_rate),
        "false_alarm_rate": round_sig(false_alarm_rate),
        "per_class": per_class,
        "confusion_matrix": {
            "rows": "true class",
            "columns": "predicted class",
            "matrix": cm.tolist(),
        },
    }


def main():
    for path in (TRAIN_PATH, TEST_PATH):
        if not os.path.isfile(path):
            log("Missing data file: %s" % path)
            return 1

    log("Reading NSL-KDD ...")
    train_rows = read_rows(TRAIN_PATH)
    test_rows = read_rows(TEST_PATH)
    log("  train rows: %d" % len(train_rows))
    log("  test rows:  %d" % len(test_rows))

    def labels_of(rows):
        return np.array(
            [CLASSES.index(label_to_class(row[41])) for row in rows],
            dtype=np.int64,
        )

    y_train_all = labels_of(train_rows)
    y_test = labels_of(test_rows)

    schema = build_schema(train_rows)
    log("  protocol_type: %s" % ", ".join(schema["categories"]["protocol_type"]))
    log("  service categories: %d" % len(schema["categories"]["service"]))
    log("  flag categories: %d" % len(schema["categories"]["flag"]))

    x_all, feature_names = transform(train_rows, schema)
    x_test_raw, test_feature_names = transform(test_rows, schema)
    assert feature_names == test_feature_names

    rng = np.random.RandomState(SEED)
    order = rng.permutation(len(train_rows))
    n_val = int(round(VAL_FRACTION * len(train_rows)))
    val_idx = order[:n_val]
    tr_idx = order[n_val:]

    x_tr_raw = x_all[tr_idx]
    x_val_raw = x_all[val_idx]
    y_tr = y_train_all[tr_idx]
    y_val = y_train_all[val_idx]

    mean = x_tr_raw.mean(axis=0)
    std = x_tr_raw.std(axis=0)
    std[std == 0.0] = 1.0

    x_tr = (x_tr_raw - mean) / std
    x_val = (x_val_raw - mean) / std
    x_test = (x_test_raw - mean) / std

    counts = np.bincount(y_tr, minlength=len(CLASSES)).astype(np.float64)
    raw_weights = np.power(len(y_tr) / (len(CLASSES) * np.maximum(counts, 1.0)),
                           CLASS_WEIGHT_EXPONENT)
    class_weights = raw_weights / np.average(raw_weights, weights=counts)
    sample_weight = class_weights[y_tr]

    log("  train/holdout: %d / %d" % (len(y_tr), len(y_val)))
    log("  train class counts: %s" % dict(zip(CLASSES, counts.astype(int).tolist())))
    log("  class weights: %s" % dict(
        zip(CLASSES, [round_sig(float(w)) for w in class_weights])
    ))
    log("  expanded feature count: %d" % len(feature_names))

    n_in = x_tr.shape[1]
    init_rng = np.random.RandomState(SEED)
    w1 = init_rng.normal(0.0, np.sqrt(2.0 / n_in), (n_in, HIDDEN))
    b1 = np.zeros(HIDDEN)
    w2 = init_rng.normal(0.0, np.sqrt(1.0 / HIDDEN), (HIDDEN, len(CLASSES)))
    b2 = np.zeros(len(CLASSES))
    theta0 = pack(w1, b1, w2, b2)

    loss_grad = make_loss_grad(x_tr, y_tr, sample_weight, n_in)

    state = {"best": np.inf, "params": theta0.copy(), "iter": 0,
             "stale": 0, "since": 0}

    def callback(theta):
        state["iter"] += 1
        state["since"] += 1
        score = macro_ce(theta, x_val, y_val, n_in)
        if score < state["best"] - 1e-5:
            state["best"] = score
            state["params"] = theta.copy()
            state["stale"] = 0
            state["since"] = 0
        else:
            state["stale"] += 1
        if state["iter"] % 10 == 0:
            log("  iter %3d  val macro-CE %.5f  best %.5f"
                % (state["iter"], score, state["best"]))
        if state["stale"] >= PATIENCE:
            raise _StopNow()

    log("Training MLP (64 ReLU units, L-BFGS, seed %d) ..." % SEED)
    try:
        result = minimize(
            loss_grad,
            theta0,
            method="L-BFGS-B",
            jac=True,
            callback=callback,
            options={"maxiter": MAX_ITER, "maxls": 20, "ftol": 1e-12,
                     "gtol": 1e-7},
        )
        best_theta = state["params"] if state["since"] >= 0 else result.x
        if state["best"] == np.inf:
            best_theta = result.x
        log("  stopped after %d iterations (best val macro-CE %.5f)"
            % (state["iter"], state["best"]))
    except _StopNow:
        best_theta = state["params"]
        log("  early stop after %d iterations (best val macro-CE %.5f)"
            % (state["iter"], state["best"]))

    w1, b1, w2, b2 = unpack(best_theta, n_in)

    def predict(x):
        return np.argmax(np.maximum(x @ w1 + b1, 0.0) @ w2 + b2, axis=1)

    val_pred = predict(x_val)
    val_acc = float(np.mean(val_pred == y_val))
    log("  holdout accuracy: %.4f" % val_acc)

    log("Evaluating on KDDTest+ ...")
    test_pred = predict(x_test)
    metrics = evaluate_predictions(y_test.tolist(), test_pred.tolist())

    log("")
    log("KDDTest+ results")
    log("  overall accuracy:        %.4f" % metrics["accuracy"])
    log("  attack detection rate:   %.4f" % metrics["attack_detection_rate"])
    log("  false-alarm rate:        %.4f" % metrics["false_alarm_rate"])
    log("  %-8s %10s %10s %10s" % ("class", "precision", "recall", "support"))
    for name in CLASSES:
        row = metrics["per_class"][name]
        log("  %-8s %10.4f %10.4f %10d"
            % (name, row["precision"], row["recall"], row["support"]))
    log("  confusion matrix (rows=true, cols=pred):")
    log("           " + " ".join("%8s" % n for n in CLASSES))
    for i, name in enumerate(CLASSES):
        log("  %-8s " % name + " ".join(
            "%8d" % v for v in metrics["confusion_matrix"]["matrix"][i]
        ))

    os.makedirs(OUT_DIR, exist_ok=True)

    model = {
        "format": "nsl-kdd-mlp-v1",
        "base_features": list(FEATURES),
        "categorical": list(CATEGORICAL),
        "categories": schema["categories"],
        "log1p_columns": list(LOG_COLUMNS),
        "feature_names": feature_names,
        "classes": list(CLASSES),
        "hidden_units": HIDDEN,
        "mean": round_vector(mean),
        "std": round_vector(std),
        "W1": round_matrix(w1),
        "b1": round_vector(b1),
        "W2": round_matrix(w2),
        "b2": round_vector(b2),
    }
    with open(MODEL_PATH, "w", encoding="utf-8") as handle:
        json.dump(model, handle, indent=1)
        handle.write("\n")

    metrics_out = {
        "dataset": "NSL-KDD",
        "test_set": "KDDTest+",
        "n_test": len(y_test),
        "n_train": len(y_tr),
        "n_holdout": len(y_val),
        "holdout_accuracy": round_sig(val_acc),
        "overall_accuracy": metrics["accuracy"],
        "attack_detection_rate": metrics["attack_detection_rate"],
        "false_alarm_rate": metrics["false_alarm_rate"],
        "per_class": metrics["per_class"],
        "confusion_matrix": metrics["confusion_matrix"],
        "class_weights": dict(
            zip(CLASSES, [round_sig(float(w)) for w in class_weights])
        ),
        "hyperparameters": {
            "model": "1-hidden-layer MLP, 64 ReLU units, softmax",
            "optimizer": "scipy L-BFGS-B",
            "l2": L2,
            "seed": SEED,
            "class_weight_exponent": CLASS_WEIGHT_EXPONENT,
            "val_fraction": VAL_FRACTION,
        },
    }
    with open(METRICS_PATH, "w", encoding="utf-8") as handle:
        json.dump(metrics_out, handle, indent=2)
        handle.write("\n")

    log("")
    log("Wrote %s" % MODEL_PATH)
    log("Wrote %s" % METRICS_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(main())
