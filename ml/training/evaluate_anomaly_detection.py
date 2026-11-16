import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from ml.training.train_baseline import (
    CHUNK_SIZE,
    DATA_DIR,
    SEED,
    TEST_FILE_NAME,
    load_training_sample,
    prepare_features,
)

VALIDATION_FILE = "Tuesday-WorkingHours.pcap_ISCX.csv"
TARGET_FALSE_POSITIVE_RATES = [0.01, 0.02, 0.05]


def main():
    validation_path = DATA_DIR / VALIDATION_FILE

    if not validation_path.is_file():
        raise FileNotFoundError(validation_path)

    csv_files = sorted(DATA_DIR.glob("*.csv"))

    if sum(p.name == TEST_FILE_NAME for p in csv_files) != 1:
        raise ValueError("Expected exactly one Wednesday holdout.")

    training_files = [
        p for p in csv_files
        if p.name not in {VALIDATION_FILE, TEST_FILE_NAME}
    ]

    print("Training captures:", len(training_files))
    print("Training mode: BENIGN-only anomaly detection")
    print("Validation capture:", VALIDATION_FILE)
    print("Wednesday final holdout: EXCLUDED")

    train = load_training_sample(training_files)
    y_train = train["target"].astype("int8")
    X_train = train.drop(columns=["target"])
    X_train = X_train.replace([np.inf, -np.inf], np.nan)

    # Fit the anomaly detector only on benign flows.
    X_benign = X_train.loc[y_train == 0].copy()
    X_benign = X_benign.dropna(axis=1, how="all")

    if len(X_benign) < 100:
        raise ValueError("Insufficient benign training rows.")

    feature_columns = list(X_benign.columns)

    fit_rows, calibration_rows = train_test_split(
        np.arange(len(X_benign)),
        test_size=0.20,
        random_state=SEED,
    )

    X_fit = X_benign.iloc[fit_rows]
    X_calibration = X_benign.iloc[calibration_rows]

    imputer = SimpleImputer(strategy="median")
    X_fit_ready = imputer.fit_transform(X_fit)
    X_calibration_ready = imputer.transform(X_calibration)

    print(f"Benign training rows: {len(X_benign):,}")
    print(f"Detector fit rows: {len(fit_rows):,}")
    print(f"Benign calibration rows: {len(calibration_rows):,}")
    print(f"Features: {len(feature_columns)}")

    detector = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=SEED,
        n_jobs=-1,
    )

    print("\nFitting Isolation Forest...")
    detector.fit(X_fit_ready)

    # Larger anomaly scores indicate more unusual traffic.
    calibration_scores = -detector.score_samples(X_calibration_ready)

    thresholds = {
        rate: np.quantile(calibration_scores, 1 - rate)
        for rate in TARGET_FALSE_POSITIVE_RATES
    }

    totals = {
        rate: np.zeros(4, dtype=np.int64)
        for rate in TARGET_FALSE_POSITIVE_RATES
    }

    evaluated_rows = 0
    ignored_rows = 0
    class_counts = np.zeros(2, dtype=np.int64)

    print("\nEvaluating Tuesday in chunks...")

    for chunk in pd.read_csv(
        validation_path,
        chunksize=CHUNK_SIZE,
        low_memory=False,
    ):
        features, targets = prepare_features(chunk)
        ignored_rows += len(chunk) - len(targets)

        if targets.empty:
            continue

        missing = set(feature_columns) - set(features.columns)
        if missing:
            raise ValueError(
                f"Validation features missing: {sorted(missing)}"
            )

        features = features.reindex(columns=feature_columns)
        features = features.replace([np.inf, -np.inf], np.nan)

        X = imputer.transform(features)
        y = targets.to_numpy(dtype=np.int8)

        evaluated_rows += len(y)
        class_counts += np.bincount(y, minlength=2)

        anomaly_scores = -detector.score_samples(X)

        for rate, threshold in thresholds.items():
            predicted = (anomaly_scores >= threshold).astype(np.int8)
            tn, fp, fn, tp = confusion_matrix(
                y, predicted, labels=[0, 1]
            ).ravel()
            totals[rate] += [tn, fp, fn, tp]

    if evaluated_rows == 0 or not np.all(class_counts > 0):
        raise ValueError("Validation must contain both classes.")

    print(f"\nEvaluated rows: {evaluated_rows:,}")
    print(f"Class counts (BENIGN, ATTACK): {class_counts.tolist()}")
    print(f"Unlabeled rows ignored: {ignored_rows:,}")

    print("\n=== ISOLATION FOREST RESULTS ===")
    print(
        "Target FPR is calibrated on held-out BENIGN training rows; "
        "actual Tuesday FPR may differ."
    )
    print(
        f"{'Target FPR':>10} {'Recall':>9} {'Precision':>10} "
        f"{'Macro-F1':>9} {'Actual FPR':>11} {'FP':>10} {'FN':>10}"
    )

    for rate in TARGET_FALSE_POSITIVE_RATES:
        tn, fp, fn, tp = totals[rate]
        recall = recall_score(
            [0] * int(tn + fp) + [1] * int(fn + tp),
            [0] * int(tn) + [1] * int(fp) + [0] * int(fn) + [1] * int(tp),
            zero_division=0,
        ) if False else (tp / (tp + fn) if tp + fn else 0.0)

        precision = tp / (tp + fp) if tp + fp else 0.0
        actual_fpr = fp / (tn + fp) if tn + fp else 0.0

        # Macro-F1 computed from the confusion matrix.
        predicted_all = np.concatenate([
            np.zeros(int(tn), dtype=np.int8),
            np.ones(int(fp), dtype=np.int8),
            np.zeros(int(fn), dtype=np.int8),
            np.ones(int(tp), dtype=np.int8),
        ])
        actual_all = np.concatenate([
            np.zeros(int(tn + fp), dtype=np.int8),
            np.ones(int(fn + tp), dtype=np.int8),
        ])
        macro_f1 = f1_score(
            actual_all, predicted_all, average="macro", zero_division=0
        )

        print(
            f"{rate:>9.0%} {recall:>9.4f} {precision:>10.4f} "
            f"{macro_f1:>9.4f} {actual_fpr:>10.4%} "
            f"{int(fp):>10,} {int(fn):>10,}"
        )

    print("\nExperiment complete. No model or metrics artifacts saved.")
    print("Wednesday final holdout was not used.")


if __name__ == "__main__":
    main()
