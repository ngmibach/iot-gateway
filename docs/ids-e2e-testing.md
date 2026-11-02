# IDS model and end-to-end testing

How the bundled model was trained, what the tests check, and how attacks are
simulated. For the integration, deployment, and operator usage, see
[`ids.md`](ids.md).

## Run the offline model E2E

Needs the IDS runtime dependencies and `pytest`. No broker, gateway, Raspberry
Pi, or systemd.

```bash
PYTHONPATH=gateway/ids pytest -q gateway/ids/tests/e2e/test_model_pipeline.py
```

It has not been executed in the development environment (LightGBM was not
installed there). It is not shown in the app; the Security page shows live
alerts only.

### What the three checks do

1. **Training metadata contract.** Verifies the LightGBM task, attack label,
   selected threshold (`0.05`), feature order, group-split fields, disjoint
   train/validation/test sessions, recorded row counts, sample-weight
   declaration, and disabled scaler.
2. **Held-out model evaluation.** Scores
   [`model_heldout_test.csv`](../gateway/ids/tests/fixtures/model_heldout_test.csv)
   with the actual bundled model at the metadata threshold. The fixture has 516
   windows (462 non-attack, 54 attack) from the training split's test sessions
   only: `heavy_attack_1`, `heavy_attack_2`, `light_attack_2`,
   `sensor1_benign_03`. It holds only the model features plus `label` and
   `session_id` (no IPs or device IDs); session IDs select and verify the split
   and are never model inputs. The test compares the resulting confusion matrix,
   precision, recall, FPR, and FNR with the bundled metadata. This tests real
   inference on held-out data without retraining.
3. **Runtime input path / attack simulation.** Writes normal and attack-like
   JSONL events and passes them through production `SensorLogCapture`, feature
   extraction, and model inference. The simulated burst uses
   `sensors/.../flood/...` topics, very short inter-arrival times, and a
   synthetic `debug.attack_blob`, mirroring the features the training data
   associates with attacks. It proves those patterns reach the model. It is a
   smoke test, not an accuracy benchmark: it has about 8 events at 50 ms spacing
   with small payloads, whereas real attack windows have about 38 messages per
   3 s, ~77 ms inter-arrival, ~2.6 KB average payload, flood topics, and blob
   ratio 1. The test does not require every generated event to be flagged.

## Training data and pipeline

Supplied in a separate `iot-gateway-submit` tree (not deployed):

- `gateway/ids/dataset/raw/sensor1_sessions/`: labeled JSONL logs (benign and
  light/mid/heavy attack sessions).
- `gateway/ids/train/prepare_ids_dataset.py`: turns logs into window features
  and a manifest.
- `gateway/ids/dataset/processed/ids_features_gateway_message_v2.csv` and
  `dataset_manifest_gateway_message_v2.json`: 2,577 windows from 16 sessions
  (263 attack, 2,314 non-attack).
- `gateway/ids/train/train_ids_model.py`: fitting, group split, threshold tuning,
  test metrics, artifact export.

Preparation groups messages by session, source IP, device, and 3-second bucket,
and derives volume, topic diversity/flood ratio, payload-size, inter-arrival,
delay, and attack-blob features. Attack windows are `1`; benign and recovery are
`0`.

Training uses LightGBM (300 estimators, learning rate 0.05, 31 leaves, seed 42)
with a `session_id` group split so no session leaks between sets. Realized rows:
834 train, 1,227 validation, 516 test. The threshold is swept 0.05-0.95 (step
0.01) on validation scores, preferring recall then precision at a 2% target FPR;
the test split is evaluated only afterwards. 12 features ship;
`process_path_ratio` is constant and dropped. Feature order must match across
preparation, training, metadata, and inference.

## Provenance and fidelity caveats

- Manifest `label_attack_threshold: 0.34` vs. the prep script's rule (attack if
  at least half of messages are in the attack phase; no such option).
- The trainer uses normalized inverse-class-frequency weights; the metadata
  describes `train_weight_hint` and `source_ip`/`device_id` group weighting the
  trainer does not produce.
- The supplied tree's edited metadata has test counts inconsistent with its
  confusion matrix. The E2E compares predictions with the **target's** bundled
  metadata and fails on disagreement.
- Training `payload_len` is the full raw JSON line, runtime uses the payload
  object; inter-arrival calculation differs; and the runtime polls about every
  second and clears its buffer, so it can score windows smaller than the
  3-second training windows.

So the E2E verifies the bundled model on its held-out rows; it does not show the
supplied artifacts can regenerate that exact model. Align the prep script,
trainer, manifest, and metadata, then regenerate artifacts and fixture together
for full reproducibility. Reported metrics (about 100% precision/recall in the
metadata, unverified until run) describe one small split with only a few
sessions and do not guarantee results for new devices, environments, attacks, or
live Raspberry Pi traffic, which is unmeasured.

## Other IDS tests

| Suite | Purpose |
|---|---|
| `gateway/ids/tests/test_model_assets.py` | Model load, feature order, probability output. |
| `gateway/ids/tests/test_structured_input.py` | Partial writes, rotation/truncation, no fabricated source IP, config migration. |
| `apps/control-service/tests/test_ids_api.py` | Auth, validation, IDS-only service ops, Loki filtering. |
| `apps/control-service/provisioner/tests/test_provisioner.py` | Missing assets, unsupported arch, dependency errors, separate service install. |
| `gateway/agent/tests/test_decrypt_worker.py` | Structured events with legacy log preserved. |
| `gateway/agent/tests/test_shipper.py` | Alert shipping once across partial writes/rotation. |
| `apps/desktop/tests/security-ui.test.cjs` | Control/refresh/error states, safe rendering. |

The existing
[`test_linux_register_provision.py`](../apps/control-service/tests/e2e/test_linux_register_provision.py)
covers mocked provision/register flows. Real gateway deployment, ARM wheels,
systemd behavior, and live Loki delivery still need hardware testing.
