from pathlib import Path

import pandas as pd
from joblib import load


ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = ROOT / "ml/models/baseline_logistic_regression.joblib"

_model = None
_feature_names = None


def _load_model():
    global _model, _feature_names

    if _model is None:
        if not MODEL_PATH.is_file():
            raise FileNotFoundError(
                f"Trained model not found: {MODEL_PATH}"
            )

        _model = load(MODEL_PATH)
        _feature_names = list(_model.feature_names_in_)

    return _model, _feature_names


def predict_flow(features: dict) -> dict:
    """
    Predict whether one network flow is BENIGN or ATTACK.

    `features` must contain the numeric network-flow features
    expected by the trained model.
    """
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

    prediction = int(model.predict(row)[0])
    probabilities = model.predict_proba(row)[0]

    attack_index = list(model.classes_).index(1)
    attack_probability = float(probabilities[attack_index])

    return {
        "prediction": "ATTACK" if prediction == 1 else "BENIGN",
        "attack_probability": round(attack_probability, 6),
        "model": "baseline_logistic_regression",
    }