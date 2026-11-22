"""Regenerate Kotlin network-model expectations using the existing Python inference."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/network_ids"))
import detect

model = detect.load_model(str(ROOT / "tools/network_ids/out/nids_model.json"))
rows = [
    {},
    {"protocol_type": "tcp", "service": "http_443", "duration": 3, "src_bytes": 340, "dst_bytes": 18000},
    {"protocol_type": "udp", "service": "domain_u", "duration": 0, "src_bytes": 44, "dst_bytes": 120},
    {"protocol_type": "tcp", "duration": 120, "src_bytes": 5000000, "dst_bytes": 0},
    {"protocol_type": "udp", "duration": 60, "src_bytes": 0, "dst_bytes": 100000000},
]
fixtures = []
for values in rows:
    vector = detect.featurize([values.get(name, 0) for name in model["base_features"]], model)
    for i, name in enumerate(model["feature_names"]):
        if name.split("=")[0] not in values:
            vector[i] = 0
    prediction, scores, _ = detect.forward(vector, model)
    fixtures.append(dict(values=values, label=model["classes"][prediction],
                         score=float(scores[prediction]), imputed=len(model["base_features"]) - len(values)))
(ROOT / "app/src/test/resources/network_model_parity.json").write_text(json.dumps(fixtures, indent=2) + "\n", encoding="utf-8")
print(f"Generated {len(fixtures)} model parity cases")
