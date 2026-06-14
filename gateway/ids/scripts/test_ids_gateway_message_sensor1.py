from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline IDS evaluation for gateway message-level model on sensor1 windows"
    )
    parser.add_argument("--dataset", default="data/processed/ids_features_gateway_message.csv")
    parser.add_argument("--model", default="models/ids_model.joblib")
    parser.add_argument("--scaler", default="models/feature_scaler.joblib")
    parser.add_argument("--metadata", default="models/model_metadata.json")
    parser.add_argument("--output-dir", default="output/ids_eval_gateway_message")
    parser.add_argument("--target-column", default="label")
    parser.add_argument("--session-column", default="session_id")
    parser.add_argument(
        "--timestamp-candidates",
        default="window_start,window_start_ts,event_ts,timestamp",
        help="Comma-separated timestamp columns to try in order",
    )
    parser.add_argument(
        "--device-id",
        default="sensor1",
        help="Filter by this device ID if device column is available. Empty disables device filter.",
    )
    parser.add_argument(
        "--source-ip",
        default="",
        help="Optional exact source IP filter if source_ip column is available.",
    )
    parser.add_argument(
        "--device-column-candidates",
        default="device_id,deviceId,device",
        help="Comma-separated candidate names for device column",
    )
    return parser.parse_args()


def _safe_rate(num: int, den: int) -> float | None:
    if den == 0:
        return None
    return float(num / den)


def _safe_roc_auc(y_true: np.ndarray, y_score: np.ndarray) -> float | None:
    if len(np.unique(y_true)) < 2:
        return None
    return float(roc_auc_score(y_true, y_score))


def _safe_pr_auc(y_true: np.ndarray, y_score: np.ndarray) -> float | None:
    if len(np.unique(y_true)) < 2:
        return None
    return float(average_precision_score(y_true, y_score))


def _resolve_positive_class_index(model: Any, metadata: dict[str, Any]) -> int:
    classes = list(getattr(model, "classes_", []))
    if not classes:
        return 1

    for idx, label in enumerate(classes):
        if label == 1 or str(label) == "1":
            return idx

    positive_label = metadata.get("positive_label")
    if positive_label is not None:
        for idx, label in enumerate(classes):
            if str(label) == str(positive_label):
                return idx

    return 1 if len(classes) > 1 else 0


def _first_existing_column(df: pd.DataFrame, candidates_csv: str) -> str | None:
    candidates = [c.strip() for c in candidates_csv.split(",") if c.strip()]
    for col in candidates:
        if col in df.columns:
            return col
    return None


def _compute_confusion_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float | int | None]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "tp": int(tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "fpr": _safe_rate(int(fp), int(fp + tn)),
        "fnr": _safe_rate(int(fn), int(fn + tp)),
    }


def main() -> None:
    args = parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    metadata = json.loads(Path(args.metadata).read_text(encoding="utf-8"))
    model = joblib.load(args.model)

    feature_columns = list(metadata.get("feature_columns", []))
    if not feature_columns:
        raise ValueError("metadata.feature_columns is empty; cannot run inference safely")

    threshold = float(metadata.get("selected_threshold", 0.5))
    scaler_enabled = bool(metadata.get("scaler_enabled", False))
    scaler_feature_names = list(metadata.get("scaler_feature_names", []))

    df = pd.read_csv(args.dataset, low_memory=False)

    device_col = _first_existing_column(df, args.device_column_candidates)
    if args.device_id and device_col:
        df = df.loc[df[device_col].astype(str) == str(args.device_id)].copy()

    if args.source_ip and "source_ip" in df.columns:
        df = df.loc[df["source_ip"].astype(str) == str(args.source_ip)].copy()

    if df.empty:
        raise ValueError("No rows left after sensor filter. Check --device-id/--source-ip values")

    missing_cols = [c for c in feature_columns if c not in df.columns]
    required_meta = [args.target_column, args.session_column]
    missing_meta = [c for c in required_meta if c not in df.columns]
    if missing_cols or missing_meta:
        raise KeyError(
            f"Missing columns. features={missing_cols}, required={missing_meta}"
        )

    ts_col = _first_existing_column(df, args.timestamp_candidates)
    if ts_col:
        df[ts_col] = pd.to_datetime(df[ts_col], errors="coerce", utc=True)

    X = df[feature_columns].astype(float)

    if scaler_enabled:
        scaler = joblib.load(args.scaler)

        # Keep runtime feature order. If scaler records names, enforce exact same ordering.
        if scaler_feature_names:
            if scaler_feature_names != feature_columns:
                raise ValueError(
                    "metadata scaler_feature_names does not match feature_columns; refusing to reorder"
                )

        X_model = scaler.transform(X)
    else:
        X_model = X.to_numpy(dtype=float)

    pos_idx = _resolve_positive_class_index(model, metadata)
    scores = model.predict_proba(X_model)[:, pos_idx].astype(float)
    preds = (scores >= threshold).astype(int)

    y = df[args.target_column].astype(int).to_numpy()

    cm_metrics = _compute_confusion_metrics(y, preds)

    overall = {
        "rows": int(len(df)),
        "sessions": int(df[args.session_column].nunique()),
        "device_filter": args.device_id,
        "source_ip_filter": args.source_ip if args.source_ip else None,
        "threshold": threshold,
        "roc_auc": _safe_roc_auc(y, scores),
        "pr_auc": _safe_pr_auc(y, scores),
        "brier_score": float(brier_score_loss(y, scores)),
        "precision_attack": float(precision_score(y, preds, pos_label=1, zero_division=0)),
        "recall_attack": float(recall_score(y, preds, pos_label=1, zero_division=0)),
        "f1_attack": float(f1_score(y, preds, pos_label=1, zero_division=0)),
        **cm_metrics,
        "score_positive_mean": float(scores[y == 1].mean()) if np.any(y == 1) else None,
        "score_negative_mean": float(scores[y == 0].mean()) if np.any(y == 0) else None,
        "score_positive_p50": float(np.quantile(scores[y == 1], 0.5)) if np.any(y == 1) else None,
        "score_negative_p50": float(np.quantile(scores[y == 0], 0.5)) if np.any(y == 0) else None,
        "timestamp_column": ts_col,
    }

    session_rows: list[dict[str, Any]] = []
    for session_id, grp in df.assign(score=scores, pred=preds).groupby(args.session_column, sort=True):
        gy = grp[args.target_column].astype(int).to_numpy()
        gs = grp["score"].to_numpy(dtype=float)
        gp = grp["pred"].to_numpy(dtype=int)

        gcm = _compute_confusion_metrics(gy, gp)

        row = {
            "session_id": str(session_id),
            "rows": int(len(grp)),
            "attack_ratio": float(gy.mean()),
            "score_mean": float(gs.mean()),
            "score_min": float(gs.min()),
            "score_p50": float(np.quantile(gs, 0.5)),
            "score_max": float(gs.max()),
            "pred_attack_ratio": float(gp.mean()),
            **gcm,
            "roc_auc": _safe_roc_auc(gy, gs),
            "pr_auc": _safe_pr_auc(gy, gs),
        }
        session_rows.append(row)

    session_df = pd.DataFrame(session_rows).sort_values(by=["session_id"], kind="stable")

    eval_df = df.copy()
    eval_df["score"] = scores
    eval_df["pred"] = preds

    if ts_col:
        sensor_time_df = eval_df[[args.session_column, ts_col, "score", "pred", args.target_column]].copy()
        sensor_time_df = sensor_time_df.sort_values(by=[args.session_column, ts_col], kind="stable")
        sensor_time_df.columns = ["session_id", "timestamp", "score", "pred", "label"]
        sensor_time_df.to_csv(out_dir / "sensor1_window_scores.csv", index=False)

    session_df.to_csv(out_dir / "session_summary.csv", index=False)
    (out_dir / "overall_summary.json").write_text(json.dumps(overall, indent=2), encoding="utf-8")

    print("[IDS-EVAL] Completed")
    print(json.dumps(overall, indent=2))
    print(f"[IDS-EVAL] session_summary_csv={out_dir / 'session_summary.csv'}")
    if ts_col:
        print(f"[IDS-EVAL] sensor1_window_scores_csv={out_dir / 'sensor1_window_scores.csv'}")


if __name__ == "__main__":
    main()
