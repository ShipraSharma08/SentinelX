from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from ml.training.train_baseline import (
    CHUNK_SIZE,
    DATA_DIR,
    SEED,
    TEST_FILE_NAME,
    load_training_sample,
    prepare_features,
)


VALIDATION_FILE_NAME = "Tuesday-WorkingHours.pcap_ISCX.csv"
THRESHOLDS = [0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]


def calculate_metrics(tn, fp, fn, tp):
    total = tn + fp + fn + tp

    attack_precision = tp / (tp + fp) if tp + fp else 0.0
    attack_recall = tp / (tp + fn) if tp + fn else 0.0

    benign_precision = tn / (tn + fn) if tn + fn else 0.0
    benign_recall = tn / (tn + fp) if tn + fp else 0.0

    attack_f1 = (
        2 * attack_precision * attack_recall
        / (attack_precision + attack_recall)
        if attack_precision + attack_recall
        else 0.0
    )
    benign_f1 = (
        2 * benign_precision * benign_recall
        / (benign_precision + benign_recall)
        if benign_precision + benign_recall
        else 0.0
    )

    return {
        "accuracy": (tn + tp) / total if total else 0.0,
        "attack_precision": attack_precision,
        "attack_recall": attack_recall,
        "macro_f1": (benign_f1 + attack_f1) / 2,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "true_positives": tp,
    }


def main():
    validation_path = DATA_DIR / VALIDATION_FILE_NAME

    if not DATA_DIR.is_dir():
        raise FileNotFoundError(f"Dataset directory not found: {DATA_DIR}")

    if not validation_path.is_file():
        raise FileNotFoundError(
            f"Validation capture not found: {validation_path}"
        )

    csv_files = sorted(DATA_DIR.glob("*.csv"))
    holdouts = [p for p in csv_files if p.name == TEST_FILE_NAME]

    if len(holdouts) != 1:
        raise ValueError(
            f"Expected exactly one final holdout: {TEST_FILE_NAME}"
        )

    training_files = [
        p for p in csv_files
        if p.name not in {TEST_FILE_NAME, VALIDATION_FILE_NAME}
    ]

    if not training_files:
        raise ValueError("No training captures available.")

    print("Experiment: threshold validation")
    print(f"Validation capture: {VALIDATION_FILE_NAME}")
    print(f"Final holdout excluded: {TEST_FILE_NAME}")
    print("Training captures:")
    for path in training_files:
        print(f"  - {path.name}")

    print("\nSampling training data...")
    train_data = load_training_sample(training_files)

    X_train = train_data.drop(columns=["target"])
    y_train = train_data["target"].astype("int8")

    X_train = X_train.dropna(axis=1, how="all")
    constant_columns = [
        col for col in X_train.columns
        if X_train[col].nunique(dropna=True) <= 1
    ]
    X_train = X_train.drop(columns=constant_columns)

    if X_train.empty:
        raise ValueError("No usable training features remain.")

    feature_columns = list(X_train.columns)

    print(f"\nTraining rows: {len(X_train):,}")
    print(f"Feature count: {len(feature_columns)}")
    print(f"Training class counts: {y_train.value_counts().to_dict()}")

    model = make_pipeline(
        SimpleImputer(strategy="median"),
        StandardScaler(),
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=SEED,
        ),
    )

    print("\nFitting temporary validation model...")
    model.fit(X_train, y_train)

    counts = {
        threshold: {"tn": 0, "fp": 0, "fn": 0, "tp": 0}
        for threshold in THRESHOLDS
    }
    total_rows = 0
    unlabeled_rows = 0
    class_counts = {0: 0, 1: 0}

    print("\nEvaluating Tuesday capture in chunks...")

    for chunk in pd.read_csv(
        validation_path,
        chunksize=CHUNK_SIZE,
        low_memory=False,
    ):
        original_rows = len(chunk)
        features, targets = prepare_features(chunk)

        unlabeled_rows += original_rows - len(targets)

        if targets.empty:
            continue

        missing = set(feature_columns) - set(features.columns)
        if missing:
            raise ValueError(
                f"Validation capture missing training features: "
                f"{sorted(missing)}"
            )

        X_chunk = features.reindex(columns=feature_columns)
        probabilities = model.predict_proba(X_chunk)[:, 1]
        y_true = targets.to_numpy(dtype=np.int8)

        total_rows += len(y_true)
        class_counts[0] += int((y_true == 0).sum())
        class_counts[1] += int((y_true == 1).sum())

        for threshold in THRESHOLDS:
            predictions = (probabilities >= threshold).astype(np.int8)
            tn, fp, fn, tp = confusion_matrix(
                y_true, predictions, labels=[0, 1]
            ).ravel()

            counts[threshold]["tn"] += int(tn)
            counts[threshold]["fp"] += int(fp)
            counts[threshold]["fn"] += int(fn)
            counts[threshold]["tp"] += int(tp)

    if total_rows == 0 or not all(class_counts.values()):
        raise ValueError(
            "Validation capture must contain labeled BENIGN and ATTACK rows."
        )

    print(f"\nEvaluated rows: {total_rows:,}")
    print(f"Class counts: {class_counts}")
    print(f"Unlabeled rows ignored: {unlabeled_rows:,}")

    print("\nThreshold comparison (validation only)")
    print(
        f"{'Threshold':>9} {'Recall':>9} {'Precision':>10} "
        f"{'Macro-F1':>9} {'FP':>10} {'FN':>10} {'Accuracy':>10}"
    )

    for threshold in THRESHOLDS:
        c = counts[threshold]
        m = calculate_metrics(c["tn"], c["fp"], c["fn"], c["tp"])

        print(
            f"{threshold:>9.2f} "
            f"{m['attack_recall']:>9.4f} "
            f"{m['attack_precision']:>10.4f} "
            f"{m['macro_f1']:>9.4f} "
            f"{m['false_positives']:>10,} "
            f"{m['false_negatives']:>10,} "
            f"{m['accuracy']:>10.4f}"
        )

    print("\nNo model or metrics artifacts were saved.")
    print("Wednesday final holdout was not evaluated or used for tuning.")


if __name__ == "__main__":
    main()
