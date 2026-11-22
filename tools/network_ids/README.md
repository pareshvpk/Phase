# Network IDS companion (Raspberry Pi 5 / PC)

A small, CPU-only network intrusion detector for a home network. It classifies
one network connection ("flow") at a time into one of five classes:

| class | meaning |
| --- | --- |
| `normal` | ordinary traffic |
| `dos` | denial of service / flooding |
| `probe` | scanning and probing |
| `r2l` | remote-to-local break-in attempt |
| `u2r` | user-to-root privilege escalation |

The model is a one-hidden-layer MLP trained on NSL-KDD. Inference is a plain
numpy forward pass, so it runs on a Raspberry Pi 5 (or any PC) with Python 3.11
and numpy. `scipy` is only needed to retrain; the training script uses it for
L-BFGS.

The companion supports prepared NSL-KDD feature rows and passive packet summaries.
The packet monitor measures flow metadata and produces an experimental model
score for each flow. All processing stays local.

## Files

```
tools/network_ids/
  monitor.py            PCAP/live passive flow monitoring and offline demo
  test_monitor.py       synthetic packet tests
  evaluate.py           offline evaluation of independently labelled monitor output
  test_evaluate.py      metric, coverage and input-integrity tests
  train.py              training pipeline (numpy + scipy, offline)
  detect.py             inference + explanations (numpy only)
  data/raw/KDDTrain+.txt
  data/raw/KDDTest+.txt
  out/nids_model.json   exported weights + feature pipeline
  out/metrics.json      test metrics on KDDTest+
```

## Dataset and licence

[NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) from the University of New
Brunswick - Canadian Institute for Cybersecurity (UNB CIC). It is a cleaned
version of KDD Cup 1999 and is free to use for research. If you publish work
using it, cite:

> M. Tavallaee, E. Bagheri, W. Lu, and A. A. Ghorbani, "A Detailed Analysis of
> the KDD CUP 99 Data Set", IEEE CISDA, 2009.

Check the UNB CIC page for the current terms before redistributing the data.
The dataset is old (1999 traffic), see [Limits](#limits).

## Feature pipeline

Each input row has the 41 standard NSL-KDD features in this order:

```
duration, protocol_type, service, flag, src_bytes, dst_bytes, land,
wrong_fragment, urgent, hot, num_failed_logins, logged_in, num_compromised,
root_shell, su_attempted, num_root, num_file_creations, num_shells,
num_access_files, num_outbound_cmds, is_host_login, is_guest_login, count,
srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate,
same_srv_rate, diff_srv_rate, srv_diff_host_rate, dst_host_count,
dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate,
dst_host_same_src_port_rate, dst_host_srv_diff_host_rate,
dst_host_serror_rate, dst_host_srv_serror_rate, dst_host_rerror_rate,
dst_host_srv_rerror_rate
```

The exact transforms are stored in `out/nids_model.json`, so `detect.py` and
`train.py` cannot drift apart:

1. One-hot encode `protocol_type`, `service`, `flag`. The categories come from
   the training split (3 protocol values, 70 services, 11 flags). An unknown
   value at inference becomes an all-zero block.
2. `log1p(max(value, 0))` on the heavy-tailed columns: `duration`, `src_bytes`,
   `dst_bytes`, `hot`, `num_compromised`, `num_root`, `num_file_creations`,
   `num_access_files`, `count`, `srv_count`, `dst_host_count`,
   `dst_host_srv_count`.
3. Z-score every column with the training mean/std (std 0 -> 1).

That gives 122 model inputs. The model is 122 -> 64 ReLU -> 5 softmax, trained
with class-weighted cross-entropy (weights proportional to
`1/class_frequency ** 0.75`), L2 `1e-4`, seed 42, 10% of the training split
held out for model selection. Floats in the JSON are rounded to 6 significant
digits.

## Test metrics (KDDTest+)

Official, harder test set: 22,544 flows. Training split: 113,376 flows,
holdout: 12,597 (holdout accuracy 0.9886).

| Metric | Value |
| --- | --- |
| Overall accuracy | **0.7801** (78.0%) |
| Attack detection rate (binary recall) | **0.7090** (70.9%) |
| False-alarm rate on normal traffic | **0.0719** (7.2%) |

Per class:

| class | precision | recall | support |
| --- | ---: | ---: | ---: |
| normal | 0.7070 | 0.9281 | 9711 |
| dos | 0.9709 | 0.8604 | 7458 |
| probe | 0.6954 | 0.6423 | 2421 |
| r2l | 0.6682 | 0.1961 | 2887 |
| u2r | 0.3365 | 0.5224 | 67 |

Confusion matrix (rows = true class, columns = predicted class):

| true \ pred | normal | dos | probe | r2l | u2r |
| --- | ---: | ---: | ---: | ---: | ---: |
| normal | 9013 | 70 | 611 | 6 | 11 |
| dos | 872 | 6417 | 45 | 111 | 13 |
| probe | 587 | 122 | 1555 | 157 | 0 |
| r2l | 2251 | 0 | 25 | 566 | 45 |
| u2r | 25 | 0 | 0 | 7 | 35 |

The gap between holdout accuracy (98.9%) and KDDTest+ accuracy (78.0%) is the
well-known NSL-KDD domain shift: KDDTest+ contains attack types and feature
combinations that are not in KDDTrain+. r2l is the weak spot (most r2l flows
look like normal logins), which is why the explanations are useful even when
the verdict is uncertain.

## Running on a Raspberry Pi 5

Only numpy is required for inference. From `tools/network_ids` on the Pi:

```sh
python3 detect.py --model out/nids_model.json --demo
python3 detect.py --model out/nids_model.json --input flows.csv --limit 20
```

The model is a 133 KB JSON file; copy `detect.py`, `out/nids_model.json` and
your CSV. No torch, pandas, pyarrow or sklearn. `train.py` additionally needs
scipy; retraining on the Pi is possible but slow, train on a PC instead.

Input CSV: no header, comma separated, either the 41 features or the 43
columns of the NSL-KDD files (41 features + attack name + difficulty). If the
two label columns are present they are only used to show the true label. Blank
lines are skipped.

To retrain on a PC (not needed for inference):

```sh
py tools/network_ids/train.py
```

Windows dev command used for the demo:

```sh
py tools/network_ids/detect.py --model tools/network_ids/out/nids_model.json --demo
```

`--demo` picks 10 class-balanced rows from KDDTest+ (first two of each class)
and prints the true label next to the prediction. Because it is a real test
split, some demo rows are misclassified; that is the model's measured
behaviour, not a bug.

## What `detect.py` prints

For every flow:

- verdict: class plus confidence, and `[ATTACK]` / `[NORMAL]`;
- a plain-language explanation from a per-class template;
- the top 3 features that pushed the decision. These use gradient x input on
  the predicted class: the gradient of the predicted logit with respect to the
  z-scored input, multiplied element-wise by that input. Feature names are
  shown with friendly descriptions, e.g. `serror_rate -> many half-open
  connections (SYN errors)`;
- three remediation steps for the predicted class;
- after all flows, the mean per-flow forward-pass time.

The gradient/input attribution is a simple local saliency method. It explains
the model, not ground truth.

## Monitoring an Ethernet interface or an offline PCAP

Run these commands from `tools/network_ids`. Install Python 3.11+ and NumPy
(on Raspberry Pi OS, `sudo apt install python3-numpy`). The demo uses two
in-memory synthetic UDP datagrams and works offline without capture privileges
or dataset downloads.

```sh
python3 monitor.py --demo
python3 monitor.py --demo-scan
python3 monitor.py --pcap sample.pcap --max-packets 1000
sudo python3 monitor.py --interface eth0 --seconds 30
python3 -m unittest discover -p 'test_monitor.py' -v
```

Live capture uses a Linux packet socket and requires CAP_NET_RAW or root.
Choose an Ethernet interface that sees the intended traffic. By default the Pi
sees frames delivered to its interface. Capturing other hosts' conversations
requires an appropriate observation point and interface configuration.
[Python socket API](https://docs.python.org/3/library/socket.html#socket-families) and [Linux packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html).

Both sources support Ethernet IPv4 TCP/UDP, including up to two VLAN tags.
Flows and port-fanout histories are isolated by VLAN stack as well as endpoints.
The JSON `vlan_ids` array lists IDs outermost first, or is empty for untagged
traffic. VLAN priority bits do not create a different network. Linux live
capture requests `PACKET_AUXDATA` and restores an outer tag stripped into
driver metadata; truncated frames or control metadata are counted as skipped.
These paths have synthetic and mocked-socket tests; actual NIC offload behaviour
still needs verification on the target device.
Offline input accepts classic PCAP 2.4 with microsecond or nanosecond timestamps
in either byte order. IPv6, non-TCP/UDP, fragments, truncated and malformed
headers count as skipped frames. PCAPNG requires conversion to Ethernet PCAP.
Records above 256 KiB are rejected. Frame checksums are not validated.
[Classic PCAP file format](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/).

The monitor streams JSON Lines to stdout. A flow includes endpoint addresses
and ports, first and last timestamps (Unix seconds), packet count, observed
model inputs, the list of imputed inputs, local model contributions and a
class-specific follow-up check. Only metadata is printed. The final summary
counts frames processed, frames skipped and flows emitted. Errors go to stderr
with a nonzero exit code. Capture defaults are 10,000 frames, 512 active flows
and 30 live seconds. `--max-packets`, `--max-flows`, `--seconds` and `--idle`
adjust these bounds. Idle expiration uses the timestamp of the next observed
frame and defaults to 30 seconds. Capacity pressure emits the least recently
seen flow. At end of input or a capture limit all remaining flows are emitted.

A flow groups both directions of a protocol and endpoint pair. The first sender
is treated as originator, reversed when the first TCP packet is SYN+ACK.
Midstream observations may therefore reverse client/server roles. Duration is
whole seconds. Byte counts sum transport payload lengths, including retransmits.
The destination port suggests a service on a short allowlist. Both TCP FINs
suggest the SF state. A reset ends a flow, and a new SYN following both FINs
starts a fresh one. A midstream capture, reused tuple, offload or dropped
packets can distort the observed values. The monitor does not reassemble TCP
or read application content.

Each flow's `observations` list includes an explanation and follow-up action
when a rule triggers. One rule looks for ten distinct destination ports active
within 60 seconds between the same apparent source and destination IP over the
same protocol, using the last packet time of completed flow summaries. It
retains up to ten ports for each of the 512 most recently processed peer pairs.
A second rule looks for at least 1,000 packets per second averaged across a
single flow lasting at least one second. Ordinary discovery or bulk transfers
can meet these thresholds. The offline `--demo-scan` fixture produces twelve
UDP flow summaries and three port-fanout observations without opening sockets.

Unobservable login and privilege features, historical NSL-KDD window
statistics and other unknown inputs are set to their training means in
standardized feature space. Missing categorical blocks use the training mean
for each one-hot column. The raw features used and imputed feature names are
reported per flow. The resulting model scores are uncalibrated on packet
captures. The KDDTest+ metrics above apply only to complete benchmark rows.
A labelled deployment capture is required to measure accuracy at that site.

## Evaluating labelled capture output

`evaluate.py` uses only the Python standard library and never accesses the
network. Save a complete monitor run, then label each emitted flow from
independent evidence such as a controlled test scenario or confirmed host logs.
Do not use the model's predicted class as ground truth.

```sh
python3 monitor.py --pcap sample.pcap --max-packets 10000 > flows.jsonl
python3 evaluate.py --input flows.jsonl --labels labels.csv > evaluation.json
python3 -m unittest discover -s . -p 'test_*.py' -v
```

The UTF-8 CSV must have exactly `flow_index,label` columns. Indexes start at one
and count only `type: flow` records in emission order, excluding the summary:

```csv
flow_index,label
1,normal
2,probe
3,dos
```

Allowed classes are `normal`, `dos`, `probe`, `r2l` and `u2r`. Label every flow
by default. `--allow-partial` explicitly permits a labelled subset and reports
its coverage. Duplicate indexes, unknown classes, out-of-range labels, incomplete
output and inconsistent summary counts fail with a nonzero exit code. Input
must be UTF-8; in Windows PowerShell use `| Set-Content -Encoding UTF8 flows.jsonl`
instead of its default redirection encoding.

The report includes SHA-256 hashes of the exact monitor output and labels used,
multiclass confusion matrix (rows=true, columns=predicted), per-class precision
and recall, and binary attack recall/false-positive rate. It measures the
experimental model separately from the presence of traffic-pattern observations.
A zero denominator is JSON `null`, never an assumed perfect result. The report
contains counts rather than endpoint addresses or packet content.

These are **flow-segment** metrics. Idle/capacity limits can split connections,
and fanout observations need several flows before triggering. Metrics do not
measure unique incidents, skipped protocols, unlabelled traffic or unseen hosts.
Synthetic fixture results validate the evaluator and cannot establish live
intrusion-detection accuracy.

## Optional Llama via ExecuTorch `llama_main`

### Observed traffic patterns

The monitor also reports bounded, deterministic observations independently of
the experimental classifier: at least 10 distinct destination ports contacted
by one source on one device within 60 seconds, or a flow averaging at least
1,000 packets per second over at least one measured second. Authorized scanners
and large legitimate transfers can produce these observations. They are reasons
to investigate, not confirmed attacks. Each observation includes an explanation
and a verification/remediation step. History is capped at 512 source/device pairs
and 10 retained ports per pair.

Run an entirely offline synthetic port-fanout example (no packets are sent):

```sh
python3 tools/network_ids/monitor.py --demo-scan
python3 -m unittest discover -s tools/network_ids -v
```

Live capture sees only traffic delivered to the selected interface; it does not
automatically observe an entire switched network. The implementation currently
supports Ethernet IPv4 TCP/UDP, not IPv6, ICMP, fragmented-IP reassembly or PCAPNG.
The summary counts unsupported/truncated frames as skipped. Complete-row NSL-KDD
metrics do not apply to these partial-feature monitor outputs.

Protocol references: [Linux packet socket API](https://man7.org/linux/man-pages/man7/packet.7.html),
[PCAP format draft](https://www.ietf.org/archive/id/draft-ietf-opsawg-pcap-07.html).

### Existing feature-row Llama runner

`--llama-cmd` is optional. If given, `detect.py` builds a short prompt (class,
confidence, top features, no IPs or raw logs), writes it to the command's
stdin, and prints its stdout as "AI explanation". If the command is missing,
exits non-zero, or times out, the template explanation is still shown and a
note goes to stderr.

Build an ExecuTorch Llama runner for the Pi (see the ExecuTorch
`examples/models/llama` docs) and export a `.pte`. `llama_main` usually takes
the prompt as an argument, so use a tiny wrapper that forwards stdin:

```sh
#!/bin/sh
PROMPT="$(cat)"
exec /home/pi/executorch/cmake-out/examples/models/llama/llama_main \
  --model_path /home/pi/models/llama.pte \
  --tokenizer_path /home/pi/models/tokenizer.model \
  --prompt "$PROMPT"
```

Then:

```sh
python3 detect.py --model out/nids_model.json --input flows.csv \
  --llama-cmd "/home/pi/llama_stdin.sh"
```

The detector never requires the LLM; all core output works offline without it.

## Limits

- NSL-KDD is 1999 traffic. Modern protocols, TLS everywhere, cloud services,
  encrypted DNS and IoT traffic look different. Do not treat 78% as your
  home's detection rate.
- The five classes are coarse. `r2l` recall is only 0.196 and `u2r` has just 67
  test examples, so those numbers are noisy.
- No packet payload inspection, no IP reputation, no asset inventory, no
  blocking. Use it alongside a firewall, updates and antivirus, not instead of
  them.
- The saliency explanation is approximate and model-specific; a listed feature
  can be correlated rather than causal.
- The model file is rounded to 6 significant digits. Predictions can differ in
  the last decimal from the training run; the reported metrics come from
  `train.py` on the unrounded weights.
