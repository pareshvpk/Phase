"""Evaluate monitor JSONL against independently assigned flow labels, offline."""
import argparse
from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path
import sys


CLASSES = ("normal", "dos", "probe", "r2l", "u2r")


def load_labels(path):
    return parse_labels(path.read_bytes())


def parse_labels(data):
    labels = {}
    with io.StringIO(data.decode("utf-8-sig"), newline="") as stream:
        rows = csv.DictReader(stream)
        if rows.fieldnames != ["flow_index", "label"]:
            raise ValueError("labels must have the header flow_index,label")
        for line, row in enumerate(rows, 2):
            try:
                index = int(row["flow_index"])
            except (ValueError, TypeError):
                raise ValueError(f"labels line {line}: flow_index must be a positive integer") from None
            label = (row["label"] or "").strip()
            if None in row or index < 1 or index in labels or label not in CLASSES:
                raise ValueError(f"labels line {line}: invalid/duplicate index or unsupported label")
            labels[index] = label
    if not labels:
        raise ValueError("labels must contain at least one labelled flow")
    return labels


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def binary_metrics(counts):
    tp, fn, fp, tn = (counts[key] for key in ("tp", "fn", "fp", "tn"))
    return dict(true_positive=tp, false_negative=fn, false_positive=fp, true_negative=tn,
                recall=ratio(tp, tp + fn), false_positive_rate=ratio(fp, fp + tn),
                precision=ratio(tp, tp + fp))


def evaluate(path, labels, allow_partial=False):
    matrix = [[0 for _ in CLASSES] for _ in CLASSES]
    model_counts, observation_counts = Counter(), Counter()
    flow_count, labelled = 0, 0
    summary = None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for line, raw in enumerate(stream, 1):
            digest.update(raw)
            if not raw.strip():
                continue
            try:
                record = json.loads(raw)
            except (ValueError, UnicodeError):
                raise ValueError(f"monitor line {line}: invalid JSON") from None
            if not isinstance(record, dict) or summary is not None:
                raise ValueError(f"monitor line {line}: invalid record or data after final summary")
            if record.get("type") == "summary":
                for key in ("frames", "flows", "skipped_frames"):
                    if type(record.get(key)) is not int or record[key] < 0:
                        raise ValueError(f"monitor summary: {key} must be a nonnegative integer")
                if record["flows"] != flow_count or not (
                    flow_count <= record["frames"] - record["skipped_frames"]
                ):
                    raise ValueError("monitor summary counts disagree with output")
                summary = record
                continue
            if record.get("type") != "flow":
                raise ValueError(f"monitor line {line}: expected flow or summary")
            prediction = record.get("experimental_model_class")
            observations = record.get("observations")
            if prediction not in CLASSES or not isinstance(observations, list) or any(
                not isinstance(item, dict) or not isinstance(item.get("kind"), str) or not item["kind"]
                for item in observations
            ):
                raise ValueError(f"monitor line {line}: invalid prediction or observations")
            flow_count += 1
            truth = labels.get(flow_count)
            if truth is None:
                continue
            labelled += 1
            matrix[CLASSES.index(truth)][CLASSES.index(prediction)] += 1
            is_attack = truth != "normal"
            for counts, flagged in ((model_counts, prediction != "normal"),
                                    (observation_counts, bool(observations))):
                key = ("tp" if flagged else "fn") if is_attack else ("fp" if flagged else "tn")
                counts[key] += 1
    if summary is None:
        raise ValueError("monitor output has no final summary; capture may be incomplete")
    if any(index > flow_count for index in labels):
        raise ValueError("labels refer to flow indexes absent from monitor output")
    if labelled == 0 or (labelled != flow_count and not allow_partial):
        raise ValueError("every flow must be labelled; use --allow-partial to report subset metrics")
    per_class = {}
    for index, name in enumerate(CLASSES):
        support = sum(matrix[index])
        predicted = sum(row[index] for row in matrix)
        per_class[name] = dict(support=support, precision=ratio(matrix[index][index], predicted),
                               recall=ratio(matrix[index][index], support))
    return dict(
        format="arm-network-evaluation-v1", monitor_sha256=digest.hexdigest(),
        flow_count=flow_count, labelled_flows=labelled,
        label_coverage=ratio(labelled, flow_count), partial=labelled != flow_count,
        capture_summary={key: summary[key] for key in ("frames", "flows", "skipped_frames")},
        experimental_model=dict(
            classes=list(CLASSES), confusion_matrix=matrix,
            accuracy=ratio(sum(matrix[i][i] for i in range(len(CLASSES))), labelled),
            per_class=per_class, binary=binary_metrics(model_counts)),
        traffic_observations=binary_metrics(observation_counts),
        limitations=[
            "Labels must come from independent ground truth, not monitor predictions.",
            "Metrics count emitted flow segments, not unique connections or attack incidents.",
            "Traffic observations flag patterns that can also be legitimate activity.",
            "Unlabelled and skipped frames are not covered by these classification metrics.",
            "Packet-derived model scores are experimental; these results apply only to the supplied labels."
        ])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="complete monitor JSONL output")
    parser.add_argument("--labels", type=Path, required=True, help="CSV: flow_index,label (one-based flow order)")
    parser.add_argument("--allow-partial", action="store_true", help="explicitly evaluate only labelled flows")
    args = parser.parse_args(argv)
    try:
        label_bytes = args.labels.read_bytes()
        result = evaluate(args.input, parse_labels(label_bytes), args.allow_partial)
        result["labels_sha256"] = hashlib.sha256(label_bytes).hexdigest()
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, csv.Error) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
