from pathlib import Path
import json

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "ml/data/raw/MachineLearningCSV/MachineLearningCVE"
MODEL_DIR = ROOT / "ml/models"

SEED = 42
CHUNK_SIZE = 100_000
PER_FILE_CLASS_LIMIT = 10_000
TOTAL_CLASS_LIMIT = 50_000


def load_sample():
    if not DATA_DIR.is_dir():
        raise FileNotFoundError(f"Dataset directory not found: {DATA_DIR}")

    files = sorted(DATA_DIR.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {DATA_DIR}")

    rng = np.random.default_rng(SEED)
    file_samples = []

    for file in files:
        collected = {"BENIGN": 0, "ATTACK": 0}
        selected_parts = []

        print(f"Reading: {file.name}")

        for chunk in pd.read_csv(
            file, chunksize=CHUNK_SIZE, low_memory=False
        ):
            chunk.columns = chunk.columns.str.strip()

            if "Label" not in chunk.columns:
                raise ValueError(f"Label column missing: {file.name}")

            labels = chunk["Label"].astype("string").str.strip()
            features = chunk.drop(columns=["Label"])
            features = features.apply(pd.to_numeric, errors="coerce")
            features = features.replace([np.inf, -np.inf], np.nan)

            for class_name in ("BENIGN", "ATTACK"):
                remaining = PER_FILE_CLASS_LIMIT - collected[class_name]
                if remaining <= 0:
                    continue

                if class_name == "BENIGN":
                    mask = labels.eq("BENIGN").fillna(False)
                    target = 0
                else:
                    mask = labels.notna() & labels.ne("BENIGN")
                    target = 1

                positions = np.flatnonzero(mask.to_numpy())
                if len(positions) == 0:
                    continue

                chosen = rng.choice(
                    positions,
                    size=min(remaining, len(positions)),
                    replace=False,
                )

                part = features.iloc[chosen].copy()
                part["target"] = target
                selected_parts.append(part)
                collected[class_name] += len(part)

            if all(
                collected[name] >= PER_FILE_CLASS_LIMIT
                for name in ("BENIGN", "ATTACK")
            ):
                break

        if selected_parts:
            file_samples.append(
                pd.concat(selected_parts, ignore_index=True)
            )

    if not file_samples:
        raise ValueError("No usable samples found.")

    data = pd.concat(file_samples, ignore_index=True)

    balanced_parts = []
    for target in (0, 1):
        class_data = data.loc[data["target"] == target]
        if class_data.empty:
            raise ValueError(f"No samples found for class {target}.")

        balanced_parts.append(
            class_data.sample(
                n=min(TOTAL_CLASS_LIMIT, len(class_data)),
                random_state=SEED,
            )
        )

    data = pd.concat(balanced_parts, ignore_index=True)
    data = data.sample(frac=1, random_state=SEED).reset_index(drop=True)

    y = data.pop("target").astype("int8")
    X = data.loc[:, data.nunique(dropna=True) > 1]
    X = X.dropna(axis=1, how="all")

    if X.shape[1] == 0:
        raise ValueError("No usable feature columns remain.")

    return X, y


def main():
    print("Loading bounded CIC-IDS2017 sample...")
    X, y = load_sample()

    print(f"\nSample rows: {len(X):,}")
    print(f"Feature count: {X.shape[1]}")
    print("Class counts (0=BENIGN, 1=ATTACK):")
    print(y.value_counts().sort_index().to_string())

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=SEED,
        stratify=y,
    )

    model = make_pipeline(
        SimpleImputer(strategy="median"),
        StandardScaler(),
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=SEED,
        ),
    )

    print("\nTraining Logistic Regression baseline...")
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    metrics = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(
            precision_score(y_test, predictions, zero_division=0)
        ),
        "recall": float(
            recall_score(y_test, predictions, zero_division=0)
        ),
        "macro_f1": float(
            f1_score(y_test, predictions, average="macro")
        ),
    }

    print("\n=== Evaluation ===")
    for name, value in metrics.items():
        print(f"{name}: {value:.4f}")

    print("\nConfusion matrix [BENIGN, ATTACK]:")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))
    print("\nClassification report:")
    print(classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["BENIGN", "ATTACK"],
        zero_division=0,
    ))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODEL_DIR / "baseline_logistic_regression.joblib"
    metrics_path = MODEL_DIR / "baseline_logistic_regression_metrics.json"

    dump(model, model_path)
    metadata = {
        "model": "LogisticRegression",
        "task": "binary_classification",
        "classes": {"0": "BENIGN", "1": "ATTACK"},
        "random_state": SEED,
        "sample_rows": int(len(X)),
        "feature_count": int(X.shape[1]),
        "features": X.columns.tolist(),
        "metrics": metrics,
        "evaluation_note": (
            "Random stratified row split; not a temporal or "
            "capture-day holdout evaluation."
        ),
    }
    metrics_path.write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    print(f"\nModel saved: {model_path}")
    print(f"Metrics saved: {metrics_path}")


if __name__ == "__main__":
    main()
