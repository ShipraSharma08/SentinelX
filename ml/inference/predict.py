from pathlib import Path

import numpy as np
import pandas as pd
from joblib import load


ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "ml/models/web_coverage_candidate.joblib"

MODEL_NAME = "web_coverage_candidate"

_model = None
_feature_names = None


def _load_model():
    """Load the selected model once and cache its expected feature names."""
    global _model, _feature_names

    if _model is None:
        if not MODEL_PATH.is_file():
            raise FileNotFoundError(
                f"Trained model not found: {MODEL_PATH}"
            )

        model = load(MODEL_PATH)

        if not hasattr(model, "feature_names_in_"):
            raise ValueError(
                "The trained model does not expose feature names."
            )

        feature_names = list(model.feature_names_in_)

        if not feature_names:
            raise ValueError("The trained model has no input features.")

        _model = model
        _feature_names = feature_names

    return _model, _feature_names


def predict_flow(features: dict) -> dict:
    """Classify one network flow as BENIGN or ATTACK."""
    if not isinstance(features, dict):
        raise TypeError("Features must be provided as a dictionary.")

    model, feature_names = _load_model()

    row = pd.DataFrame([features])
    row.columns = row.columns.str.strip()

    if row.columns.duplicated().any():
        raise ValueError("Duplicate feature names are not allowed.")

    missing = sorted(set(feature_names) - set(row.columns))
    unexpected = sorted(set(row.columns) - set(feature_names))

    if missing or unexpected:
        raise ValueError(
            f"Feature mismatch. Missing: {missing}; "
            f"unexpected: {unexpected}"
        )

    row = row.loc[:, feature_names]

    for column in feature_names:
        row[column] = pd.to_numeric(row[column], errors="raise")

    values = row.to_numpy(dtype=np.float64)

    if not np.isfinite(values).all():
        raise ValueError(
            "Feature values must all be finite numbers; "
            "NaN and Infinity are not allowed."
        )

    prediction = int(model.predict(row)[0])
    probabilities = model.predict_proba(row)[0]
    classes = list(model.classes_)

    if 1 not in classes:
        raise ValueError(
            "The trained model does not contain the ATTACK class (1)."
        )

    attack_probability = float(probabilities[classes.index(1)])

    return {
        "prediction": "ATTACK" if prediction == 1 else "BENIGN",
        "attack_probability": round(attack_probability, 6),
        "model": MODEL_NAME,
    }
