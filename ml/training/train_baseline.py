
from pathlib import Path
import json

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "ml/data/raw/MachineLearningCSV/MachineLearningCVE"
MODEL_DIR = ROOT / "ml/models"

SEED = 42
CHUNK_SIZE = 100_000
PER_FILE_CLASS_LIMIT = 10_000
TOTAL_CLASS_LIMIT = 50_000

# Keep this entire capture separate from training.
TEST_FILE_NAME = "Wednesday-workingHours.pcap_ISCX.csv"


def prepare_features(
    chunk: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.Series]:
    """Clean features and map BENIGN to 0 and attacks to 1."""
    chunk = chunk.copy()
    chunk.columns = chunk.columns.str.strip()

    if "Label" not in chunk.columns:
        raise ValueError("Dataset chunk does not contain a Label column.")

    labels = chunk.pop("Label").astype("string").str.strip()
    valid_labels = labels.notna() & labels.ne("")

    features = chunk.apply(pd.to_numeric, errors="coerce")
    features = features.replace([np.inf, -np.inf], np.nan)

    # Missing labels are filtered out below, not treated as attacks.
    targets = labels.ne("BENIGN").fillna(False).astype("int8")

    features = features.loc[valid_labels].reset_index(drop=True)
    targets = targets.loc[valid_labels].reset_index(drop=True)

    return features, targets


def sample_csv_by_class(
    file_path: Path,
    per_class_limit: int,
    rng: np.random.Generator,
) -> pd.DataFrame:
    """
    Read a CSV in chunks and retain a bounded random-priority
    sample for each binary class.
    """
    reservoirs = {
        0: pd.DataFrame(),
        1: pd.DataFrame(),
    }

    for chunk in pd.read_csv(
        file_path,
        chunksize=CHUNK_SIZE,
        low_memory=False,
    ):
        features, targets = prepare_features(chunk)

        for target in (0, 1):
            candidates = features.loc[targets.eq(target)].copy()

            if candidates.empty:
                continue

            candidates["__sample_key"] = rng.random(len(candidates))

            combined = pd.concat(
                [reservoirs[target], candidates],
                ignore_index=True,
            )

            reservoirs[target] = (
                combined.nsmallest(
                    per_class_limit,
                    columns="__sample_key",
                )
                .reset_index(drop=True)
            )

    sampled_parts = []

    for target, reservoir in reservoirs.items():
        if reservoir.empty:
            continue

        part = reservoir.drop(columns=["__sample_key"]).copy()
        part["target"] = target
        sampled_parts.append(part)

    if not sampled_parts:
        return pd.DataFrame()

    return pd.concat(sampled_parts, ignore_index=True)


def cap_training_classes(data: pd.DataFrame) -> pd.DataFrame:
    """Apply a reproducible sample cap to each training class."""
    parts = []

    for target in (0, 1):
        class_data = data.loc[data["target"] == target]

        if class_data.empty:
            raise ValueError(
                f"Training data has no samples for class {target}."
            )

        sample_size = min(TOTAL_CLASS_LIMIT, len(class_data))

        parts.append(
            class_data.sample(
                n=sample_size,
                random_state=SEED,
            )
        )

    return (
        pd.concat(parts, ignore_index=True)
        .sample(frac=1, random_state=SEED)
        .reset_index(drop=True)
    )


def load_training_sample(files: list[Path]) -> pd.DataFrame:
    """Collect bounded samples exclusively from training files."""
    rng = np.random.default_rng(SEED)
    samples = []

    for file_path in files:
        print(f"Sampling training file: {file_path.name}")

        sample = sample_csv_by_class(
            file_path=file_path,
            per_class_limit=PER_FILE_CLASS_LIMIT,
            rng=rng,
        )

        if not sample.empty:
            samples.append(sample)

    if not samples:
        raise ValueError("No usable training samples found.")

    return cap_training_classes(
        pd.concat(samples, ignore_index=True)
    )


def evaluate_full_capture(
    model,
    test_file: Path,
    feature_columns: pd.Index,
) -> dict:
    """
    Evaluate all rows with valid labels in the held-out capture.
    Do not balance or resample the test classes.
    """
    total_matrix = np.zeros((2, 2), dtype=np.int64)
    class_counts = np.zeros(2, dtype=np.int64)
    evaluated_rows = 0
    ignored_unlabeled_rows = 0
    extra_columns_reported = False

    print("\nEvaluating the complete held-out capture...")
    print(f"Test file: {test_file.name}")

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            test_file,
            chunksize=CHUNK_SIZE,
            low_memory=False,
        ),
        start=1,
    ):
        original_rows = len(chunk)
        X_chunk, y_chunk = prepare_features(chunk)

        ignored_unlabeled_rows += original_rows - len(y_chunk)

        if y_chunk.empty:
            continue

        missing = sorted(
            set(feature_columns) - set(X_chunk.columns)
        )

        if missing:
            raise ValueError(
                "Training features missing from test chunk "
                f"{chunk_number}: {missing}"
            )

        unexpected = sorted(
            set(X_chunk.columns) - set(feature_columns)
        )

        if unexpected and not extra_columns_reported:
            print(f"Ignoring test-only features: {unexpected}")
            extra_columns_reported = True

        # Preserve the exact training feature order.
        X_chunk = X_chunk.loc[:, feature_columns]

        predictions = model.predict(X_chunk)

        total_matrix += confusion_matrix(
            y_chunk,
            predictions,
            labels=[0, 1],
        )

        class_counts += np.bincount(
            y_chunk.to_numpy(dtype=np.int8),
            minlength=2,
        )

        evaluated_rows += len(y_chunk)

        print(
            f"\rProcessed {evaluated_rows:,} labeled rows...",
            end="",
            flush=True,
        )

    print()

    if evaluated_rows == 0:
        raise ValueError("No labeled rows available for evaluation.")

    if np.any(class_counts == 0):
        raise ValueError(
            "Expected both BENIGN and ATTACK in the holdout. "
            f"Observed class counts: {class_counts.tolist()}"
        )

    tn, fp, fn, tp = map(int, total_matrix.ravel())

    def ratio(numerator: int, denominator: int) -> float:
        return numerator / denominator if denominator else 0.0

    benign_precision = ratio(tn, tn + fn)
    benign_recall = ratio(tn, tn + fp)
    attack_precision = ratio(tp, tp + fp)
    attack_recall = ratio(tp, tp + fn)

    def f1(precision: float, recall: float) -> float:
        if precision + recall == 0:
            return 0.0
        return 2 * precision * recall / (precision + recall)

    benign_f1 = f1(benign_precision, benign_recall)
    attack_f1 = f1(attack_precision, attack_recall)

    metrics = {
        "accuracy": ratio(tn + tp, evaluated_rows),
        "precision": attack_precision,
        "recall": attack_recall,
        "macro_f1": (benign_f1 + attack_f1) / 2,
    }

    class_metrics = {
        "BENIGN": {
            "precision": benign_precision,
            "recall": benign_recall,
            "f1_score": benign_f1,
            "support": int(class_counts[0]),
        },
        "ATTACK": {
            "precision": attack_precision,
            "recall": attack_recall,
            "f1_score": attack_f1,
            "support": int(class_counts[1]),
        },
    }

    return {
        "metrics": metrics,
        "class_metrics": class_metrics,
        "confusion_matrix": total_matrix.tolist(),
        "test_class_counts": {
            "0": int(class_counts[0]),
            "1": int(class_counts[1]),
        },
        "test_rows": evaluated_rows,
        "ignored_unlabeled_rows": ignored_unlabeled_rows,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "true_positives": tp,
    }


def main():
    if not DATA_DIR.is_dir():
        raise FileNotFoundError(
            f"Dataset directory not found: {DATA_DIR}"
        )

    files = sorted(DATA_DIR.glob("*.csv"))

    if not files:
        raise FileNotFoundError(
            f"No CSV files found in {DATA_DIR}"
        )

    test_files = [
        path for path in files
        if path.name == TEST_FILE_NAME
    ]

    if len(test_files) != 1:
        raise ValueError(
            f"Expected exactly one holdout file named "
            f"{TEST_FILE_NAME!r}; found {len(test_files)}."
        )

    test_file = test_files[0]
    train_files = [
        path for path in files
        if path.name != TEST_FILE_NAME
    ]

    if not train_files:
        raise ValueError("No training files remain after holdout.")

    print("Evaluation strategy: full held-out capture")
    print(f"Test file: {test_file.name}")
    print("Training files:")

    for path in train_files:
        print(f"  - {path.name}")

    print("\nSampling training data...")
    train_data = load_training_sample(train_files)

    X_train = train_data.drop(columns=["target"])
    y_train = train_data["target"].astype("int8")

    # Select usable features using training data only.
    usable_columns = X_train.columns[
        X_train.nunique(dropna=True) > 1
    ]
    X_train = X_train.loc[:, usable_columns]
    X_train = X_train.dropna(axis=1, how="all")

    if X_train.shape[1] == 0:
        raise ValueError("No usable training features remain.")

    print(f"\nTraining rows: {len(X_train):,}")
    print(f"Feature count: {X_train.shape[1]}")

    print("\nTraining class counts (0=BENIGN, 1=ATTACK):")
    print(y_train.value_counts().sort_index().to_string())

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

    evaluation = evaluate_full_capture(
        model=model,
        test_file=test_file,
        feature_columns=X_train.columns,
    )

    metrics = evaluation["metrics"]
    matrix = np.asarray(evaluation["confusion_matrix"])

    print("\n=== Full Held-out Capture Evaluation ===")
    print(f"Evaluated rows: {evaluation['test_rows']:,}")
    print(f"BENIGN rows: {evaluation['test_class_counts']['0']:,}")
    print(f"ATTACK rows: {evaluation['test_class_counts']['1']:,}")
    print(
        "Unlabeled rows ignored: "
        f"{evaluation['ignored_unlabeled_rows']:,}"
    )

    for name, value in metrics.items():
        print(f"{name}: {value:.4f}")

    print("\nConfusion matrix [BENIGN, ATTACK]:")
    print(matrix)

    print("\nClass-wise metrics:")
    for class_name, values in evaluation["class_metrics"].items():
        print(
            f"{class_name}: "
            f"precision={values['precision']:.4f}, "
            f"recall={values['recall']:.4f}, "
            f"f1={values['f1_score']:.4f}, "
            f"support={values['support']:,}"
        )

    print(f"\nFalse positives: {evaluation['false_positives']:,}")
    print(f"False negatives: {evaluation['false_negatives']:,}")

    metadata = {
        "model": "LogisticRegression",
        "task": "binary_classification",
        "classes": {"0": "BENIGN", "1": "ATTACK"},
        "random_state": SEED,
        "train_files": [path.name for path in train_files],
        "test_file": test_file.name,
        "train_sample_rows": int(len(X_train)),
        "test_rows": evaluation["test_rows"],
        "ignored_unlabeled_rows": evaluation["ignored_unlabeled_rows"],
        "train_class_counts": {
            str(int(key)): int(value)
            for key, value in y_train.value_counts().items()
        },
        "test_class_counts": evaluation["test_class_counts"],
        "feature_count": int(X_train.shape[1]),
        "features": X_train.columns.tolist(),
        "metrics": metrics,
        "class_metrics": evaluation["class_metrics"],
        "confusion_matrix_labels": ["BENIGN", "ATTACK"],
        "confusion_matrix": evaluation["confusion_matrix"],
        "false_positives": evaluation["false_positives"],
        "false_negatives": evaluation["false_negatives"],
        "true_negatives": evaluation["true_negatives"],
        "true_positives": evaluation["true_positives"],
        "evaluation_note": (
            "All rows with valid labels from the held-out Wednesday "
            "capture were evaluated in chunks without class balancing "
            "or resampling. The holdout was excluded from model fitting "
            "and feature selection. Test-only columns were ignored to "
            "match the training feature schema. This is capture-file "
            "holdout evaluation, not multi-day temporal forecasting "
            "or a World Model."
        ),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    model_path = MODEL_DIR / "baseline_logistic_regression.joblib"
    metrics_path = (
        MODEL_DIR / "baseline_logistic_regression_metrics.json"
    )

    # Save artifacts only after training and evaluation succeed.
    dump(model, model_path)
    metrics_path.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    print(f"\nModel saved: {model_path}")
    print(f"Metrics saved: {metrics_path}")


if __name__ == "__main__":
    main()
