import json
from pathlib import Path

import joblib

from ml.training.train_candidate_web_coverage import (
    DATA_DIR,
    FINAL_HOLDOUT_FILE_NAME,
    evaluate_full_capture,
)


def main():
    root = Path(__file__).resolve().parents[2]
    model_path = root / "ml/models/web_coverage_candidate.joblib"
    metadata_path = root / "ml/models/web_coverage_candidate_metrics.json"
    output_path = root / "ml/models/web_coverage_candidate_holdout_metrics.json"
    holdout_path = DATA_DIR / FINAL_HOLDOUT_FILE_NAME

    for path in (model_path, metadata_path, holdout_path):
        if not path.is_file():
            raise FileNotFoundError(f"Required file not found: {path}")

    with metadata_path.open() as file:
        metadata = json.load(file)

    model = joblib.load(model_path)
    feature_columns = metadata["features"]

    print("FINAL HOLDOUT EVALUATION")
    print(f"Model: {model_path.name}")
    print(f"Holdout: {holdout_path.name}")
    print("The holdout will not be used for training or threshold tuning.")

    results = evaluate_full_capture(
        model=model,
        validation_file=holdout_path,
        feature_columns=__import__("pandas").Index(feature_columns),
    )

    report = {
        "model": "web_coverage_candidate",
        "holdout_file": holdout_path.name,
        "evaluation_type": "final_holdout",
        "threshold": 0.5,
        "results": results,
        "note": (
            "Wednesday holdout evaluated after model selection. "
            "Do not use these results to tune this model or its threshold."
        ),
    }

    with output_path.open("w") as file:
        json.dump(
            report,
            file,
            indent=2,
            default=lambda value: (
                value.item() if hasattr(value, "item") else str(value)
            ),
        )

    print(f"\nFinal holdout report saved: {output_path}")


if __name__ == "__main__":
    main()
