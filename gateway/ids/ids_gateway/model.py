from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import joblib
import numpy as np


class IDSModel:
    def __init__(self, model_path: str, scaler_path: str | None, features: List[str]) -> None:
        model_p = self._resolve_path(model_path)
        self.model = joblib.load(model_p)
        self.model_path = model_p

        self.metadata = self._load_metadata(model_p)

        metadata_features = self.metadata.get("feature_columns")
        if isinstance(metadata_features, list) and metadata_features:
            self.features = [str(x) for x in metadata_features]
        else:
            self.features = [str(x) for x in features]

        self.scaler_enabled = bool(self.metadata.get("scaler_enabled", False))
        self.scaler = None

        if self.scaler_enabled and scaler_path:
            scaler_p = self._resolve_path(scaler_path)
            if scaler_p.exists():
                self.scaler = joblib.load(scaler_p)

        self.expected_feature_count = len(self.features)
        self.positive_class_index = self._resolve_positive_class_index()

    @staticmethod
    def _load_metadata(model_path: Path) -> dict:
        metadata_path = model_path.with_name("model_metadata.json")
        if not metadata_path.exists():
            return {}
        try:
            with metadata_path.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
            if isinstance(payload, dict):
                return payload
        except Exception:
            pass
        return {}

    def _resolve_positive_class_index(self) -> int:
        classes = list(getattr(self.model, "classes_", []))
        if not classes:
            return 1

        for idx, label in enumerate(classes):
            if label == 1 or str(label) == "1":
                return idx

        positive_label = self.metadata.get("positive_label")
        if positive_label is not None:
            for idx, label in enumerate(classes):
                if str(label) == str(positive_label):
                    return idx

        return 1 if len(classes) > 1 else 0

    def get_default_threshold(self) -> float | None:
        threshold = self.metadata.get("selected_threshold")
        if isinstance(threshold, (int, float)):
            return float(threshold)
        return None

    @staticmethod
    def _resolve_path(path: str) -> Path:
        p = Path(path)

        if p.is_absolute() and p.exists():
            return p

        docker_p = Path("/app") / p
        if docker_p.exists():
            return docker_p

        cwd_p = Path.cwd() / p
        if cwd_p.exists():
            return cwd_p

        return p

    def _build_matrix(self, feature_dicts: List[Dict[str, float]]) -> np.ndarray:
        rows = []
        for fd in feature_dicts:
            row = [float(fd.get(name, 0.0)) for name in self.features]
            rows.append(row)

        arr = np.asarray(rows, dtype=float)

        if arr.ndim != 2:
            raise ValueError(f"Expected 2D feature matrix, got shape={arr.shape}")

        if arr.shape[1] != self.expected_feature_count:
            raise ValueError(
                f"Feature count mismatch. got={arr.shape[1]}, "
                f"expected={self.expected_feature_count}, features={self.features}"
            )

        if self.scaler_enabled:
            if self.scaler is None:
                raise ValueError("Metadata says scaler_enabled=true but scaler could not be loaded")

            scaler_n_features = getattr(self.scaler, "n_features_in_", None)
            if scaler_n_features is not None and int(scaler_n_features) != arr.shape[1]:
                raise ValueError(
                    f"Scaler feature count mismatch. got={arr.shape[1]}, "
                    f"expected={scaler_n_features}"
                )

            arr = self.scaler.transform(arr)

        model_n_features = getattr(self.model, "n_features_in_", None)
        if model_n_features is not None and int(model_n_features) != arr.shape[1]:
            raise ValueError(
                f"Model feature count mismatch after preprocessing. "
                f"got={arr.shape[1]}, expected={model_n_features}"
            )

        return arr

    def predict_attack_probability(self, feature_dict: Dict[str, float]) -> float:
        arr = self._build_matrix([feature_dict])
        proba = self.model.predict_proba(arr)
        return float(proba[0][self.positive_class_index])

    def predict_batch(self, feature_dicts: List[Dict[str, float]]) -> List[float]:
        if not feature_dicts:
            return []
        arr = self._build_matrix(feature_dicts)
        proba = self.model.predict_proba(arr)
        return [float(p) for p in proba[:, self.positive_class_index]]