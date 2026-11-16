from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight

from ml.training.train_baseline import (
    CHUNK_SIZE,
    DATA_DIR,
    SEED,
    TEST_FILE_NAME,
    load_training_sample,
    prepare_features,
)

VALIDATION_FILE = "Tuesday-WorkingHours.pcap_ISCX.csv"
THRESHOLDS = [0.10, 0.20, 0.30, 0.40, 0.50, 0.70]


def metrics(tn, fp, fn, tp):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

    benign_precision = tn / (tn + fn) if tn + fn else 0.0
    benign_recall = tn / (tn + fp) if tn + fp else 0.0

    attack_f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )
    benign_f1 = (
        2 * benign_precision * benign_recall
        / (benign_precision + benign_recall)
        if benign_precision + benign_recall else 0.0
    )

    return {
        "precision": precision,
        "recall": recall,
        "macro_f1": (attack_f1 + benign_f1) / 2,
        "fp": fp,
        "fn": fn,
    }


def main():
    validation_path = DATA_DIR / VALIDATION_FILE
    if not validation_path.is_file():
        raise FileNotFoundError(validation_path)

    csv_files = sorted(DATA_DIR.glob("*.csv"))
    if sum(p.name == TEST_FILE_NAME for p in csv_files) != 1:
        raise ValueError("Expected exactly one Wednesday final holdout.")

    training_files = [
        p for p in csv_files
        if p.name not in {VALIDATION_FILE, TEST_FILE_NAME}
    ]
    if not training_files:
        raise ValueError("No training captures found.")

    print("Training captures:", len(training_files))
    print("Validation capture:", VALIDATION_FILE)
    print("Wednesday final holdout: excluded")

    train = load_training_sample(training_files)
    X_train = train.drop(columns=["target"])
    y_train = train["target"].astype("int8")

    X_train = X_train.dropna(axis=1, how="all")
    constant = [
        col for col in X_train.columns
        if X_train[col].nunique(dropna=True) <= 1
    ]
    X_train = X_train.drop(columns=constant)
    feature_columns = list(X_train.columns)

    if not feature_columns:
        raise ValueError("No usable features remain.")

    imputer = SimpleImputer(strategy="median")
    X_imputed = imputer.fit_transform(X_train)

    models = {
        "LogisticRegression": make_pipeline(
            StandardScaler(),
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=SEED,
            ),
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=150,
            learning_rate=0.1,
            max_leaf_nodes=31,
            l2_regularization=1.0,
            random_state=SEED,
        ),
    }

    print(f"Training rows: {len(X_train):,}")
    print(f"Features: {len(feature_columns)}")

    for name, model in models.items():
        print(f"\nFitting {name}...")
        if name == "HistGradientBoosting":
            weights = compute_sample_weight("balanced", y_train)
            model.fit(X_imputed, y_train, sample_weight=weights)
        else:
            model.fit(X_imputed, y_train)

    totals = {
        name: {
            threshold: np.zeros(4, dtype=np.int64)
            for threshold in THRESHOLDS
        }
        for name in models
    }
    class_counts = np.zeros(2, dtype=np.int64)
    evaluated_rows = 0
    ignored_rows = 0

    print("\nEvaluating validation capture in chunks...")

    for chunk in pd.read_csv(
        validation_path,
        chunksize=CHUNK_SIZE,
        low_memory=False,
    ):
        original_rows = len(chunk)
        features, targets = prepare_features(chunk)
        ignored_rows += original_rows - len(targets)

        if targets.empty:
            continue

        missing = set(feature_columns) - set(features.columns)
        if missing:
            raise ValueError(
                f"Validation features missing: {sorted(missing)}"
            )

        X = imputer.transform(features.reindex(columns=feature_columns))
        y = targets.to_numpy(dtype=np.int8)

        evaluated_rows += len(y)
        class_counts += np.bincount(y, minlength=2)

        for name, model in models.items():
            probabilities = model.predict_proba(X)[:, 1]

            for threshold in THRESHOLDS:
                predicted = (probabilities >= threshold).astype(np.int8)
                tn, fp, fn, tp = confusion_matrix(
                    y, predicted, labels=[0, 1]
                ).ravel()
                totals[name][threshold] += [tn, fp, fn, tp]

    if evaluated_rows == 0 or not np.all(class_counts > 0):
        raise ValueError("Validation data must contain both classes.")

    print(f"\nEvaluated rows: {evaluated_rows:,}")
    print(f"Class counts (BENIGN, ATTACK): {class_counts.tolist()}")
    print(f"Unlabeled rows ignored: {ignored_rows:,}")

    for name in models:
        print(f"\n=== {name} ===")
        print(
            f"{'Threshold':>9} {'Recall':>9} {'Precision':>10} "
            f"{'Macro-F1':>9} {'FP':>10} {'FN':>10}"
        )
        for threshold in THRESHOLDS:
            tn, fp, fn, tp = totals[name][threshold]
            m = metrics(int(tn), int(fp), int(fn), int(tp))
            print(
                f"{threshold:>9.2f} {m['recall']:>9.4f} "
                f"{m['precision']:>10.4f} {m['macro_f1']:>9.4f} "
                f"{m['fp']:>10,} {m['fn']:>10,}"
            )

    print("\nExperiment complete. No model or metrics artifacts saved.")
    print("Wednesday holdout was not used.")


if __name__ == "__main__":
    main()
