"""
NSL-KDD network intrusion detector - pure-numpy inference.

Loads out/nids_model.json (exported by train.py), rebuilds the exact
one-hot + log1p + z-score feature pipeline, runs a numpy forward pass and
prints a verdict, a plain-language explanation, the top-3 input features
that drove the decision (gradient x input on the predicted class) and
three remediation steps per class.

Runs with numpy only (no scipy) so it works on a Raspberry Pi 5.

Usage:
    py tools/network_ids/detect.py --model tools/network_ids/out/nids_model.json --demo
    py tools/network_ids/detect.py --model tools/network_ids/out/nids_model.json \
        --input flows.csv [--limit N] [--llama-cmd "<command>"]
"""

import argparse
import json
import math
import os
import subprocess
import sys
import time

import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_PATH = os.path.join(SCRIPT_DIR, "data", "raw", "KDDTest+.txt")

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

TEMPLATES = {
    "normal": (
        "This looks like ordinary traffic - a normal connection with no "
        "signs of an attack."
    ),
    "dos": (
        "Something is flooding this device/network with connection requests "
        "to knock it offline (a denial-of-service attack)."
    ),
    "probe": (
        "Someone appears to be scanning your network to find open ports and "
        "weak spots before attacking (a probe/scan)."
    ),
    "r2l": (
        "Someone is trying to break into an account or service on this "
        "machine from outside (remote-to-local attack)."
    ),
    "u2r": (
        "An attacker who is already on this machine is trying to gain "
        "administrator/root control (user-to-root attack)."
    ),
}

REMEDIATION = {
    "normal": [
        "No action needed - this looks like normal traffic.",
        "Keep your router and devices updated with the latest firmware.",
        "Keep monitoring for sudden spikes in connection attempts.",
    ],
    "dos": [
        "Block the source of the flood at your router/firewall.",
        "Enable rate limiting or DDoS protection on your router.",
        "If a device is saturated, disconnect it and reboot the router.",
    ],
    "probe": [
        "Change your router admin password.",
        "Turn off UPnP.",
        "Close unused ports and enable the router firewall.",
    ],
    "r2l": [
        "Change passwords for the targeted service/account and enable "
        "two-factor authentication.",
        "Disable remote login services you do not need (telnet, FTP, "
        "unencrypted remote shell).",
        "Check logs for successful logins from unfamiliar locations.",
    ],
    "u2r": [
        "Disconnect the affected device from the network immediately.",
        "Run a full malware scan and check for new administrator accounts.",
        "Reinstall the OS if root access is confirmed and restore from a "
        "known-good backup.",
    ],
}

FRIENDLY = {
    "duration": "connection length (seconds)",
    "land": "source and destination are the same (land attack)",
    "wrong_fragment": "malformed packet fragments",
    "urgent": "urgent data packets",
    "hot": "privileged-access indicators",
    "num_failed_logins": "failed login attempts",
    "logged_in": "successful login",
    "num_compromised": "compromised conditions",
    "root_shell": "root shell obtained",
    "su_attempted": "attempts to switch to root",
    "num_root": "root accesses",
    "num_file_creations": "files created",
    "num_shells": "shell sessions opened",
    "num_access_files": "files accessed",
    "num_outbound_cmds": "outbound commands",
    "is_host_login": "host login",
    "is_guest_login": "guest login",
    "src_bytes": "bytes sent from this device",
    "dst_bytes": "bytes received by this device",
    "count": "many connection attempts in the last 2 seconds",
    "srv_count": "many connections to the same service in the last 2 seconds",
    "serror_rate": "many half-open connections (SYN errors)",
    "srv_serror_rate": "many half-open connections to the same service",
    "rerror_rate": "many rejected connections",
    "srv_rerror_rate": "many rejected connections to the same service",
    "same_srv_rate": "repeated connections to the same service",
    "diff_srv_rate": "connections spread across many services",
    "srv_diff_host_rate": "the same service contacting many hosts",
    "dst_host_count": "many connections to this host",
    "dst_host_srv_count": "many connections to this host and service",
    "dst_host_same_srv_rate": "this host repeatedly contacted on the same service",
    "dst_host_diff_srv_rate": "this host contacted across many services",
    "dst_host_same_src_port_rate": "same source port reused to this host",
    "dst_host_srv_diff_host_rate": "this service reached from many hosts",
    "dst_host_serror_rate": "many half-open connections to this host",
    "dst_host_srv_serror_rate": "many half-open connections to this host and service",
    "dst_host_rerror_rate": "many rejected connections to this host",
    "dst_host_srv_rerror_rate": "many rejected connections to this host and service",
}


def label_to_class(name):
    name = (name or "").strip().lower()
    if name == "normal":
        return "normal"
    return ATTACK_MAP.get(name, "r2l")


def read_csv_rows(path):
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rows.append([part.strip() for part in line.split(",")])
    return rows


def load_model(path):
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    model = {
        "format": raw.get("format", "nsl-kdd-mlp-v1"),
        "base_features": raw["base_features"],
        "categorical": set(raw["categorical"]),
        "categories": raw["categories"],
        "log1p_columns": set(raw["log1p_columns"]),
        "feature_names": raw["feature_names"],
        "classes": raw["classes"],
        "mean": np.asarray(raw["mean"], dtype=np.float64),
        "std": np.asarray(raw["std"], dtype=np.float64),
        "W1": np.asarray(raw["W1"], dtype=np.float64),
        "b1": np.asarray(raw["b1"], dtype=np.float64),
        "W2": np.asarray(raw["W2"], dtype=np.float64),
        "b2": np.asarray(raw["b2"], dtype=np.float64),
    }
    if len(model["feature_names"]) != len(model["mean"]):
        raise ValueError("model feature_names and mean have different lengths")
    return model


def featurize(row, model):
    values = []
    for idx, name in enumerate(model["base_features"]):
        if name in model["categorical"]:
            cats = model["categories"][name]
            for cat in cats:
                values.append(1.0 if row[idx] == cat else 0.0)
        else:
            value = float(row[idx])
            if name in model["log1p_columns"]:
                value = math.log1p(max(value, 0.0))
            values.append(value)
    x = np.asarray(values, dtype=np.float64)
    if x.shape[0] != model["mean"].shape[0]:
        raise ValueError(
            "expanded feature count %d does not match model (%d)"
            % (x.shape[0], model["mean"].shape[0])
        )
    return (x - model["mean"]) / model["std"]


def forward(x, model):
    z1 = x @ model["W1"] + model["b1"]
    hidden = np.maximum(z1, 0.0)
    logits = hidden @ model["W2"] + model["b2"]
    shifted = logits - logits.max()
    exp = np.exp(shifted)
    probs = exp / exp.sum()
    return int(np.argmax(probs)), probs, z1


def top_features(x, z1, model, class_index, k=3):
    mask = (z1 > 0.0).astype(np.float64)
    grad = model["W1"] @ (mask * model["W2"][:, class_index])
    contributions = grad * x
    order = np.argsort(-np.abs(contributions))[:k]
    result = []
    for idx in order:
        name = model["feature_names"][idx]
        result.append((name, friendly_name(name), float(contributions[idx])))
    return result


def friendly_name(feature):
    if feature in FRIENDLY:
        return FRIENDLY[feature]
    if "=" in feature:
        base, value = feature.split("=", 1)
        if base == "protocol_type":
            return "protocol used: %s" % value
        if base == "service":
            return "service contacted: %s" % value
        if base == "flag":
            return "connection state: %s" % value
    return feature.replace("_", " ")


def pick_demo_rows(limit=10):
    if not os.path.isfile(TEST_PATH):
        raise FileNotFoundError("demo data not found: %s" % TEST_PATH)
    rows = read_csv_rows(TEST_PATH)
    picked = []
    seen = {}
    for idx, row in enumerate(rows):
        if len(row) < 42:
            continue
        cls = label_to_class(row[41])
        if seen.get(cls, 0) < 2:
            picked.append((idx + 1, row, cls))
            seen[cls] = seen.get(cls, 0) + 1
        if len(picked) >= limit:
            break
    picked.sort(key=lambda item: item[0])
    return picked


def call_llama(command, prompt):
    try:
        proc = subprocess.run(
            command,
            shell=True,
            input=prompt,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    text = (proc.stdout or "").strip()
    return text or None


def build_prompt(class_name, confidence, features):
    lines = [
        "You are a friendly home-network security assistant.",
        "Explain this result in plain language for a non-expert and give "
        "practical next steps.",
        "Verdict: %s (confidence %.1f%%)" % (class_name, confidence * 100.0),
        "Top signals:",
    ]
    for name, friendly, contribution in features:
        lines.append("- %s (%s): %+.3f" % (friendly, name, contribution))
    lines.append(
        "Do not invent IP addresses or hostnames. Keep it under 120 words."
    )
    return "\n".join(lines) + "\n"


def load_metrics(model_path):
    path = os.path.join(os.path.dirname(os.path.abspath(model_path)),
                        "metrics.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None


def print_header(model, metrics):
    print("NSL-KDD intrusion detector")
    print("Model: %s  (%d features -> %d hidden -> %d classes)" % (
        model["format"], model["mean"].shape[0],
        model["W1"].shape[1], len(model["classes"]),
    ))
    print("Classes: %s" % ", ".join(model["classes"]))
    if metrics:
        print("KDDTest+ accuracy %.1f%%, attack detection %.1f%%, "
              "false alarms %.1f%%" % (
                  metrics.get("overall_accuracy", 0.0) * 100.0,
                  metrics.get("attack_detection_rate", 0.0) * 100.0,
                  metrics.get("false_alarm_rate", 0.0) * 100.0,
              ))
    print("")


def print_result(index, total, row_number, true_label, class_name,
                 confidence, features, llama_text):
    is_attack = class_name != "normal"
    print("-" * 70)
    origin = "row %d" % row_number if row_number is not None else "input"
    true_text = ""
    if true_label:
        true_text = ", true: %s" % true_label
    print("Flow %d/%d  (%s%s)" % (index, total, origin, true_text))
    print("  Verdict: %s (confidence %.1f%%)  [%s]" % (
        class_name, confidence * 100.0, "ATTACK" if is_attack else "NORMAL",
    ))
    print("  What this means: %s" % TEMPLATES.get(class_name, "Unknown class."))
    print("  Top features that pushed this decision:")
    for rank, (name, friendly, contribution) in enumerate(features, 1):
        if contribution > 0:
            direction = "toward %s" % class_name
        else:
            direction = "away from %s" % class_name
        print("    %d. %s -> %s  (%+.3f, %s)" % (
            rank, name, friendly, contribution, direction,
        ))
    print("  What to do:")
    for rank, step in enumerate(REMEDIATION.get(class_name, []), 1):
        print("    %d. %s" % (rank, step))
    if llama_text:
        print("  AI explanation:")
        for line in llama_text.splitlines():
            print("    %s" % line)
    print("")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="NSL-KDD intrusion detector (numpy inference)."
    )
    parser.add_argument("--model", required=True, help="path to nids_model.json")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", help="CSV of 41 NSL-KDD features "
                                        "(optionally + attack, difficulty)")
    source.add_argument("--demo", action="store_true",
                        help="use 10 mixed rows from KDDTest+")
    parser.add_argument("--limit", type=int, default=None,
                        help="maximum number of rows to process")
    parser.add_argument("--llama-cmd", default=None,
                        help="command that reads a prompt on stdin and "
                             "prints an AI explanation")
    args = parser.parse_args(argv)

    try:
        model = load_model(args.model)
    except Exception as exc:
        print("Could not load model: %s" % exc, file=sys.stderr)
        return 1

    if args.demo:
        try:
            picked = pick_demo_rows(10)
        except Exception as exc:
            print("Could not load demo data: %s" % exc, file=sys.stderr)
            return 1
        items = []
        for row_number, row, true_class in picked:
            items.append((row_number, row, "%s (%s)" % (row[41], true_class)))
    else:
        try:
            rows = read_csv_rows(args.input)
        except Exception as exc:
            print("Could not read input: %s" % exc, file=sys.stderr)
            return 1
        items = []
        for row_number, row in enumerate(rows, 1):
            true_label = None
            if len(row) == 43:
                true_label = "%s (%s)" % (row[41], label_to_class(row[41]))
            items.append((row_number, row, true_label))

    if args.limit is not None:
        if args.limit < 1:
            print("--limit must be at least 1", file=sys.stderr)
            return 1
        items = items[:args.limit]

    if not items:
        print("No flows to process.", file=sys.stderr)
        return 1

    metrics = load_metrics(args.model)
    print_header(model, metrics)

    latencies = []
    for index, (row_number, row, true_label) in enumerate(items, 1):
        if len(row) not in (41, 43):
            print("Row %d: expected 41 or 43 columns, got %d" % (
                row_number, len(row)), file=sys.stderr)
            return 1
        try:
            x = featurize(row, model)
        except Exception as exc:
            print("Row %d: bad feature value (%s)" % (row_number, exc),
                  file=sys.stderr)
            return 1

        start = time.perf_counter()
        class_index, probs, z1 = forward(x, model)
        latencies.append(time.perf_counter() - start)

        class_name = model["classes"][class_index]
        features = top_features(x, z1, model, class_index)

        llama_text = None
        if args.llama_cmd:
            prompt = build_prompt(class_name, float(probs[class_index]),
                                  features)
            llama_text = call_llama(args.llama_cmd, prompt)
            if llama_text is None:
                print("(AI command failed; using template explanation.)",
                      file=sys.stderr)

        print_result(index, len(items), row_number, true_label, class_name,
                     float(probs[class_index]), features, llama_text)

    mean_ms = (sum(latencies) / len(latencies)) * 1000.0
    count = len(latencies)
    print("Mean per-flow inference time: %.3f ms (numpy forward pass, %d %s)"
          % (mean_ms, count, "flow" if count == 1 else "flows"))
    if args.llama_cmd:
        print("Note: AI explanations are optional; template text is always "
              "shown.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
