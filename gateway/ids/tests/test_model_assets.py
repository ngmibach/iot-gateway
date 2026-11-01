from __future__ import annotations

import json
import unittest
from pathlib import Path

from ids_gateway.features import FEATURE_NAMES, empty_feature_vector
from ids_gateway.model import IDSModel


class BundledModelTests(unittest.TestCase):
    def test_metadata_feature_order_and_prediction(self) -> None:
        models = Path(__file__).resolve().parents[1] / "models"
        metadata = json.loads((models / "model_metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["feature_columns"], FEATURE_NAMES)

        model = IDSModel(
            str(models / "ids_model.joblib"),
            str(models / "feature_scaler.joblib"),
            FEATURE_NAMES,
        )
        score = model.predict_attack_probability(empty_feature_vector())
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)


if __name__ == "__main__":
    unittest.main()
