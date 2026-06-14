from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)


def _load_pickle(path: Path) -> Any:
    with path.open('rb') as f:
        return pickle.load(f)


def _resolve_artifacts(args):
    report_dir = Path(args.report_dir) if args.report_dir else None
    model_path = Path(args.model_path) if args.model_path else None
    metadata_path = Path(args.metadata_path) if args.metadata_path else None
    scaler_path = Path(args.scaler_path) if args.scaler_path else None

    if report_dir:
        if model_path is None:
            for cand in [report_dir / 'model.pkl', report_dir / 'ids_model.pkl', report_dir / 'classifier.pkl']:
                if cand.exists():
                    model_path = cand
                    break
        if metadata_path is None:
            for cand in [report_dir / 'model_metadata.json', report_dir / 'metadata.json']:
                if cand.exists():
                    metadata_path = cand
                    break
        if scaler_path is None:
            for cand in [report_dir / 'scaler.pkl', report_dir / 'ids_scaler.pkl']:
                if cand.exists():
                    scaler_path = cand
                    break

    if model_path is None or not model_path.exists():
        raise FileNotFoundError('Model file not found. Pass --model-path or --report-dir containing model.pkl')
    if metadata_path is None or not metadata_path.exists():
        raise FileNotFoundError('Metadata file not found. Pass --metadata-path or --report-dir containing model_metadata.json')
    return model_path, metadata_path, scaler_path


def _predict_scores(model, X: pd.DataFrame) -> np.ndarray:
    if hasattr(model, 'predict_proba'):
        proba = model.predict_proba(X)
        if isinstance(proba, list):
            proba = np.asarray(proba)
        if proba.ndim == 2:
            return proba[:, 1].astype(float)
    if hasattr(model, 'decision_function'):
        raw = np.asarray(model.decision_function(X), dtype=float)
        return 1.0 / (1.0 + np.exp(-raw))
    pred = np.asarray(model.predict(X), dtype=float)
    return pred


def _safe_auc(y_true: np.ndarray, y_score: np.ndarray) -> float | None:
    if len(np.unique(y_true)) < 2:
        return None
    return float(roc_auc_score(y_true, y_score))


def _safe_pr_auc(y_true: np.ndarray, y_score: np.ndarray) -> float | None:
    if len(np.unique(y_true)) < 2:
        return None
    return float(average_precision_score(y_true, y_score))


def _rate(numer: int, denom: int) -> float | None:
    if denom == 0:
        return None
    return float(numer / denom)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset', required=True)
    ap.add_argument('--report-dir', default='')
    ap.add_argument('--model-path', default='')
    ap.add_argument('--metadata-path', default='')
    ap.add_argument('--scaler-path', default='')
    ap.add_argument('--session-column', default='session_id')
    ap.add_argument('--target-column', default='label')
    ap.add_argument('--output-dir', default='output/ids_eval')
    args = ap.parse_args()

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    model_path, metadata_path, scaler_path = _resolve_artifacts(args)
    metadata = json.loads(Path(metadata_path).read_text(encoding='utf-8'))
    dataset = pd.read_csv(args.dataset)

    feature_columns = metadata['feature_columns']
    threshold = float(metadata.get('selected_threshold', 0.5))
    scaler_enabled = bool(metadata.get('scaler_enabled', False))

    missing = [c for c in feature_columns + [args.target_column, args.session_column] if c not in dataset.columns]
    if missing:
        raise KeyError(f'Missing columns in dataset: {missing}')

    X = dataset[feature_columns].copy()
    y = dataset[args.target_column].astype(int).to_numpy()
    sessions = dataset[args.session_column].astype(str)

    scaler = None
    if scaler_enabled and scaler_path and Path(scaler_path).exists():
        scaler = _load_pickle(Path(scaler_path))
        X_arr = scaler.transform(X)
        if hasattr(scaler, 'feature_names_in_'):
            X_model = pd.DataFrame(X_arr, columns=list(scaler.feature_names_in_))
        else:
            X_model = pd.DataFrame(X_arr, columns=feature_columns)
    else:
        X_model = X

    model = _load_pickle(model_path)
    scores = _predict_scores(model, X_model)
    preds = (scores >= threshold).astype(int)

    dataset_eval = dataset.copy()
    dataset_eval['score'] = scores
    dataset_eval['pred'] = preds

    cm = confusion_matrix(y, preds, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    p, r, f1, _ = precision_recall_fscore_support(y, preds, average='binary', zero_division=0)

    overall = {
        'rows': int(len(dataset_eval)),
        'sessions': int(sessions.nunique()),
        'threshold': threshold,
        'roc_auc': _safe_auc(y, scores),
        'pr_auc': _safe_pr_auc(y, scores),
        'brier_score': float(brier_score_loss(y, scores)),
        'precision_attack': float(p),
        'recall_attack': float(r),
        'f1_attack': float(f1),
        'tp': int(tp),
        'tn': int(tn),
        'fp': int(fp),
        'fn': int(fn),
        'fpr': _rate(int(fp), int(fp + tn)),
        'fnr': _rate(int(fn), int(fn + tp)),
        'score_positive_mean': float(dataset_eval.loc[dataset_eval[args.target_column] == 1, 'score'].mean()) if (dataset_eval[args.target_column] == 1).any() else None,
        'score_negative_mean': float(dataset_eval.loc[dataset_eval[args.target_column] == 0, 'score'].mean()) if (dataset_eval[args.target_column] == 0).any() else None,
    }

    session_rows = []
    for session_id, grp in dataset_eval.groupby(args.session_column, sort=True):
        yy = grp[args.target_column].astype(int).to_numpy()
        ss = grp['score'].to_numpy(dtype=float)
        pp = grp['pred'].to_numpy(dtype=int)
        gcm = confusion_matrix(yy, pp, labels=[0, 1])
        gtn, gfp, gfn, gtp = gcm.ravel()
        gp, gr, gf1, _ = precision_recall_fscore_support(yy, pp, average='binary', zero_division=0)
        session_rows.append({
            'session_id': session_id,
            'rows': int(len(grp)),
            'label_mode': int(round(float(grp[args.target_column].mean()))),
            'attack_ratio': float(grp[args.target_column].mean()),
            'score_mean': float(grp['score'].mean()),
            'score_min': float(grp['score'].min()),
            'score_p50': float(grp['score'].median()),
            'score_max': float(grp['score'].max()),
            'pred_attack_ratio': float(grp['pred'].mean()),
            'precision_attack': float(gp),
            'recall_attack': float(gr),
            'f1_attack': float(gf1),
            'tp': int(gtp),
            'tn': int(gtn),
            'fp': int(gfp),
            'fn': int(gfn),
            'fpr': _rate(int(gfp), int(gfp + gtn)),
            'fnr': _rate(int(gfn), int(gfn + gtp)),
            'roc_auc': _safe_auc(yy, ss),
            'pr_auc': _safe_pr_auc(yy, ss),
        })

    session_df = pd.DataFrame(session_rows).sort_values(['label_mode', 'session_id']).reset_index(drop=True)

    feature_snapshot = []
    for col in feature_columns:
        benign = dataset_eval.loc[dataset_eval[args.target_column] == 0, col]
        attack = dataset_eval.loc[dataset_eval[args.target_column] == 1, col]
        feature_snapshot.append({
            'feature': col,
            'benign_mean': float(benign.mean()) if len(benign) else None,
            'attack_mean': float(attack.mean()) if len(attack) else None,
            'benign_p95': float(benign.quantile(0.95)) if len(benign) else None,
            'attack_p05': float(attack.quantile(0.05)) if len(attack) else None,
        })
    feature_df = pd.DataFrame(feature_snapshot)

    dataset_eval.to_csv(outdir / 'window_predictions.csv', index=False)
    session_df.to_csv(outdir / 'session_summary.csv', index=False)
    feature_df.to_csv(outdir / 'feature_class_snapshot.csv', index=False)
    (outdir / 'overall_summary.json').write_text(json.dumps(overall, indent=2), encoding='utf-8')

    print(json.dumps({
        'overall_summary': overall,
        'artifacts': {
            'window_predictions_csv': str(outdir / 'window_predictions.csv'),
            'session_summary_csv': str(outdir / 'session_summary.csv'),
            'feature_class_snapshot_csv': str(outdir / 'feature_class_snapshot.csv'),
            'overall_summary_json': str(outdir / 'overall_summary.json'),
        }
    }, indent=2))


if __name__ == '__main__':
    main()
