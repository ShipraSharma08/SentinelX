import numpy as np
import pandas as pd

from ml.training.train_baseline import (
    CHUNK_SIZE,
    DATA_DIR,
    SEED,
    TEST_FILE_NAME,
    load_training_sample,
    prepare_features,
)

VALIDATION_FILE = "Tuesday-WorkingHours.pcap_ISCX.csv"
SAMPLE_PER_CLASS = 20_000


def clean_numeric(frame):
    return frame.replace([np.inf, -np.inf], np.nan)


def feature_stats(series):
    values = pd.to_numeric(series, errors="coerce")
    values = values.replace([np.inf, -np.inf], np.nan)
    valid = values.dropna()

    if valid.empty:
        return {
            "mean": np.nan,
            "std": np.nan,
            "median": np.nan,
            "iqr": np.nan,
            "missing_rate": 1.0,
        }

    return {
        "mean": valid.mean(),
        "std": valid.std(ddof=0),
        "median": valid.median(),
        "iqr": valid.quantile(0.75) - valid.quantile(0.25),
        "missing_rate": 1 - len(valid) / len(values),
    }


def shift_scores(train_series, validation_series):
    a = feature_stats(train_series)
    b = feature_stats(validation_series)

    pooled_std = np.sqrt(
        (a["std"] ** 2 + b["std"] ** 2) / 2
    )

    if not np.isfinite(pooled_std):
        smd = np.nan
    elif pooled_std > 1e-12:
        smd = abs(a["mean"] - b["mean"]) / pooled_std
    else:
        smd = 0.0 if a["mean"] == b["mean"] else np.inf

    pooled_iqr = (a["iqr"] + b["iqr"]) / 2

    if not np.isfinite(pooled_iqr):
        median_shift = np.nan
    elif pooled_iqr > 1e-12:
        median_shift = abs(a["median"] - b["median"]) / pooled_iqr
    else:
        median_shift = (
            0.0 if a["median"] == b["median"] else np.inf
        )

    return {
        "feature": train_series.name,
        "standardized_mean_shift": smd,
        "robust_median_shift": median_shift,
        "train_missing_pct": a["missing_rate"] * 100,
        "validation_missing_pct": b["missing_rate"] * 100,
    }


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

    if not training_files:
        raise ValueError("No training captures found.")

    print("Training captures:", len(training_files))
    print("Validation capture:", VALIDATION_FILE)
    print("Wednesday holdout: EXCLUDED")

    train = load_training_sample(training_files)
    X_train = clean_numeric(train.drop(columns=["target"]))
    y_train = train["target"].astype("int8")

    X_train = X_train.dropna(axis=1, how="all")
    constant = [
        col for col in X_train.columns
        if X_train[col].nunique(dropna=True) <= 1
    ]
    X_train = X_train.drop(columns=constant)

    feature_columns = list(X_train.columns)

    if not feature_columns:
        raise ValueError("No usable training features.")

    # Uniform random-key reservoir sampling keeps validation memory bounded.
    rng = np.random.default_rng(SEED)
    reservoirs = {
        0: pd.DataFrame(),
        1: pd.DataFrame(),
    }

    total_rows = 0
    ignored_rows = 0
    class_counts = np.zeros(2, dtype=np.int64)

    print("\nReading Tuesday capture in chunks...")

    for chunk in pd.read_csv(
        validation_path,
        chunksize=CHUNK_SIZE,
        low_memory=False,
    ):
        features, targets = prepare_features(chunk)
        total_rows += len(chunk)
        ignored_rows += len(chunk) - len(targets)

        if targets.empty:
            continue

        y = targets.to_numpy(dtype=np.int8)
        class_counts += np.bincount(y, minlength=2)

        features = clean_numeric(features.reindex(
            columns=feature_columns
        ))

        for cls in (0, 1):
            subset = features.loc[y == cls].copy()

            if subset.empty:
                continue

            subset["_key"] = rng.random(len(subset))

            if not reservoirs[cls].empty:
                subset = pd.concat(
                    [reservoirs[cls], subset],
                    ignore_index=True,
                )

            reservoirs[cls] = subset.nsmallest(
                SAMPLE_PER_CLASS, "_key"
            ).reset_index(drop=True)

    print(f"\nTuesday rows read: {total_rows:,}")
    print(f"Unlabeled rows ignored: {ignored_rows:,}")
    print(f"Class counts (BENIGN, ATTACK): {class_counts.tolist()}")

    for cls, label in ((0, "BENIGN"), (1, "ATTACK")):
        validation = reservoirs[cls].drop(columns=["_key"])

        if validation.empty:
            raise ValueError(f"No validation samples for {label}.")

        training = X_train.loc[y_train == cls]

        if training.empty:
            raise ValueError(f"No training samples for {label}.")

        print(f"\n=== {label}: feature distribution shift ===")
        print(f"Training sample rows: {len(training):,}")
        print(f"Validation sample rows: {len(validation):,}")

        results = []

        for feature in feature_columns:
            result = shift_scores(
                training[feature],
                validation[feature],
            )
            results.append(result)

        report = pd.DataFrame(results)
        report["_sort_score"] = report[
            "standardized_mean_shift"
        ].replace([np.inf, -np.inf], np.nan)

        report = report.sort_values(
            "_sort_score", ascending=False, na_position="last"
        )

        print("\nTop 15 features by standardized mean shift:")
        print(
            report.drop(columns="_sort_score")
            .head(15)
            .to_string(index=False, float_format=lambda x: f"{x:.4f}")
        )

        print("\nFeatures with largest missing-rate differences:")
        report["missing_rate_gap_pp"] = abs(
            report["train_missing_pct"]
            - report["validation_missing_pct"]
        )
        print(
            report.sort_values(
                "missing_rate_gap_pp", ascending=False
            )[
                [
                    "feature",
                    "train_missing_pct",
                    "validation_missing_pct",
                    "missing_rate_gap_pp",
                ]
            ]
            .head(10)
            .to_string(index=False, float_format=lambda x: f"{x:.4f}")
        )

    print("\nDiagnostic complete. No model or artifact saved.")
    print("Wednesday holdout was not used.")


if __name__ == "__main__":
    main()
