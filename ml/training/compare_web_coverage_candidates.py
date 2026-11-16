import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from ml.training.train_candidate_web_coverage import (
    DATA_DIR,
    VALIDATION_FILE_NAME,
    PER_FILE_CLASS_LIMIT,
    SEED,
    sample_csv_by_class,
)


def main():
    model_dir = Path("ml/models")
    validation_file = DATA_DIR / VALIDATION_FILE_NAME

    existing_model_path = model_dir / "candidate_logistic_regression.joblib"
    existing_metrics_path = (
        model_dir / "candidate_logistic_regression_metrics.json"
    )
    web_model_path = model_dir / "web_coverage_candidate.joblib"
    web_metrics_path = model_dir / "web_coverage_candidate_metrics.json"

    required_files = [
        validation_file,
        existing_model_path,
        existing_metrics_path,
        web_model_path,
        web_metrics_path,
    ]

    for path in required_files:
        if not path.is_file():
            raise FileNotFoundError(f"Required file not found: {path}")

    with existing_metrics_path.open() as file:
        existing_metadata = json.load(file)

    with web_metrics_path.open() as file:
        web_metadata = json.load(file)

    print("Sampling the Thursday WebAttacks capture...")
    sample = sample_csv_by_class(
        validation_file,
        PER_FILE_CLASS_LIMIT,
        np.random.default_rng(SEED + 1),
    )

    if sample["target"].nunique() != 2:
        raise ValueError("Validation sample must contain both classes.")

    _, validation = train_test_split(
        sample,
        test_size=0.20,
        stratify=sample["target"],
        random_state=SEED,
    )

    y_true = validation["target"].to_numpy()
    X_validation = validation.drop(columns=["target"])

    print(f"\nSame validation rows: {len(validation):,}")
    print(f"Actual benign: {(y_true == 0).sum():,}")
    print(f"Actual attacks: {(y_true == 1).sum():,}")

    models = [
        (
            "Existing candidate",
            existing_model_path,
            existing_metadata,
        ),
        (
            "Web-coverage candidate",
            web_model_path,
            web_metadata,
        ),
    ]

    for name, model_path, metadata in models:
        model = joblib.load(model_path)
        expected_features = metadata["features"]

        missing = set(expected_features) - set(X_validation.columns)
        if missing:
            raise ValueError(
                f"{name}: validation is missing expected features: "
                f"{sorted(missing)}"
            )

        X = X_validation.reindex(columns=expected_features)
        predictions = model.predict(X)

        tn, fp, fn, tp = confusion_matrix(
            y_true, predictions, labels=[0, 1]
        ).ravel()

        print(f"\n=== {name} ===")
        print(f"Accuracy:         {accuracy_score(y_true, predictions):.4f}")
        print(
            "Attack precision: "
            f"{precision_score(y_true, predictions, zero_division=0):.4f}"
        )
        print(
            "Attack recall:    "
            f"{recall_score(y_true, predictions, zero_division=0):.4f}"
        )
        print(
            "Attack F1:        "
            f"{f1_score(y_true, predictions, zero_division=0):.4f}"
        )
        print(f"False positives:  {fp:,}")
        print(f"False negatives:  {fn:,}")
        print(f"TN={tn:,}, TP={tp:,}")


if __name__ == "__main__":
    main()
