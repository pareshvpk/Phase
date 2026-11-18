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

This is a **companion / teaching tool**, not an inline firewall. It does not
capture packets, block traffic or scan your machine. It tells you what a flow
looks like, why, and what to check.

## Files

```
tools/network_ids/
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

## Live traffic -> NSL-KDD features (not implemented)

`detect.py` consumes feature rows. It does **not** capture live traffic. To go
from a real home network to `flows.csv` you would need a flow exporter such as
Zeek or argus, plus a converter. That converter is not included here; the
honest status is "design documented, code not written".

Sketch of the conversion:

1. Run Zeek (or argus) on the Pi / router mirror port and keep connection logs
   (`conn.log` / argus records): timestamps, source and destination
   addresses/ports, protocol, duration, bytes and connection state.
2. For each finished connection, map to one NSL-KDD row:
   - `duration`, `src_bytes`, `dst_bytes` from the log;
   - `protocol_type` -> `tcp` / `udp` / `icmp`;
   - `flag` -> `SF` for a normal close, `S0` for no reply / SYN-only, `REJ`
     for rejected, `RSTO` / `RSTR` / `RSTOS0` for reset variants, `OTH`
     otherwise;
   - `service` -> the well-known port's service name from the NSL-KDD
     category list (`http`, `domain`, `ftp`, `ssh`, `telnet`, `smtp`, ...),
     otherwise `other`;
   - the login/privilege columns (`logged_in`, `num_failed_logins`,
     `root_shell`, ...) are not visible in a connection log. Leave them at 0;
     this loses information for r2l/u2r. The z-score pipeline accepts zeros.
3. The `count`, `srv_count`, `*_rate`, `same_srv_rate` and `dst_host_*`
   features are windowed aggregates, not per-connection values. They need:
   - a 2-second sliding window per destination host for `count` and the
     serror/rerror/same-service rates;
   - a 100-connection window per destination host for the `dst_host_*`
     columns.
   Compute them over recent connections, then emit the row. Results will
   differ from NSL-KDD's exact definitions; expect accuracy loss.
4. Append the two label columns only if you have ground truth for evaluation.

No IP addresses are passed to the model or to the optional language model, so
the rows themselves are privacy-friendly.

## Optional Llama via ExecuTorch `llama_main`

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
