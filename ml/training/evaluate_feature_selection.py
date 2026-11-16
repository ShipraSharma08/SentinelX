"""Compare logistic-regression feature subsets without touching the final holdout."""

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from ml.training.train_baseline import (
    DATA_DIR,
    SEED,
    TEST_FILE_NAME,
    load_training_sample,
    prepare_features,
)


VALIDATION_FILE_NAME = "Tuesday-WorkingHours.pcap_ISCX.csv"
FEATURE_COUNTS = [10, 20, 30, 50, "all"]
THRESHOLDS = [0.10, 0.20, 0.30, 0.40, 0.50]
CHUNK_SIZE = 100_000


def make_model():
    return make_pipeline(
        SimpleImputer(strategy="median"),
        StandardScaler(),
        LogisticRegression(
            class_weight="balanced",
            max_iter=1000,
            random_state=SEED,
        ),
    )


def main():
    if not DATA_DIR.is_dir():
        raise FileNotFoundError(f"Dataset directory not found: {DATA_DIR}")

    files = sorted(DATA_DIR.glob("*.csv"))
    excluded = {TEST_FILE_NAME, VALIDATION_FILE_NAME}
    training_files = [path for path in files if path.name not in excluded]
    validation_file = DATA_DIR / VALIDATION_FILE_NAME

    if not training_files:
        raise ValueError("No training captures remain after exclusions.")

    if not validation_file.is_file():
        raise FileNotFoundError(
            f"Tuesday validation capture not found: {validation_file}"
        )

    print("Training captures:")
    for path in training_files:
        print(f"  {path.name}")
    print(f"Validation capture: {validation_file.name}")
    print(f"Final holdout excluded: {TEST_FILE_NAME}")

    data = load_training_sample(training_files)
    X_train = data.drop(columns=["target"])
    y_train = data["target"].astype("int8")

    # Remove features unusable for training or constant in the training sample.
    X_train = X_train.loc[:, X_train.notna().any(axis=0)]
    non_constant = X_train.nunique(dropna=True) > 1
    X_train = X_train.loc[:, non_constant]

    if X_train.empty:
        raise ValueError("No usable non-constant training features remain.")

    print(f"\nTraining rows: {len(X_train):,}")
    print(f"Training features after filtering: {X_train.shape[1]}")
    print(f"Training class counts: {y_train.value_counts().sort_index().to_dict()}")

    # Rank features using coefficients learned exclusively from training data.
    ranking_model = make_model()
    ranking_model.fit(X_train, y_train)

    coefficients = np.abs(ranking_model[-1].coef_[0])
    ranking = (
        pd.Series(coefficients, index=X_train.columns)
        .sort_values(ascending=False)
    )

    print("\nTop 15 features by absolute standardized logistic coefficient:")
    for feature, importance in ranking.head(15).items():
        print(f"  {feature}: {importance:.6f}")

    subsets = {}
    for count in FEATURE_COUNTS:
        k = len(ranking) if count == "all" else min(count, len(ranking))
        selected = ranking.index[:k].tolist()
        subsets[f"top_{k}"] = selected

    # Fit a separate model for each selected feature subset.
    models = {}
    for name, columns in subsets.items():
        model = make_model()
        model.fit(X_train[columns], y_train)
        models[name] = (model, columns)
        print(f"Fitted {name}: {len(columns)} features")

    # Stream through Tuesday; never load or evaluate the Wednesday holdout.
    confusion = {
        (name, threshold): np.zeros((2, 2), dtype=np.int64)
        for name in models
        for threshold in THRESHOLDS
    }
    class_counts = np.zeros(2, dtype=np.int64)
    evaluated_rows = 0
    ignored_rows = 0

    for chunk in pd.read_csv(
        validation_file,
        chunksize=CHUNK_SIZE,
        low_memory=False,
    ):
        X_chunk, y_chunk = prepare_features(chunk)

        valid_index = y_chunk.index
        ignored_rows += len(chunk) - len(y_chunk)

        # Align the validation features to the training schema.
        X_chunk = X_chunk.reindex(columns=X_train.columns)
        y_values = y_chunk.to_numpy(dtype=np.int8)

        if len(y_values) == 0:
            continue

        evaluated_rows += len(y_values)
        class_counts += np.bincount(y_values, minlength=2)[:2]

        for name, (model, columns) in models.items():
            probabilities = model.predict_proba(X_chunk[columns])[:, 1]

            for threshold in THRESHOLDS:
                predictions = (probabilities >= threshold).astype(np.int8)
                matrix = confusion_matrix(
                    y_values,
                    predictions,
                    labels=[0, 1],
                )
                confusion[(name, threshold)] += matrix

    print(f"\nTuesday evaluated rows: {evaluated_rows:,}")
    print(f"Tuesday class counts (0=BENIGN, 1=ATTACK): {class_counts.tolist()}")
    print(f"Rows with missing/blank labels ignored: {ignored_rows:,}")

    print(
        "\nRESULTS"
        "\nfeatures  threshold  precision  recall  macro_f1  false_positives"
        "  false_negatives  accuracy"
    )

    for name, (_, selected_columns) in models.items():
        for threshold in THRESHOLDS:
            matrix = confusion[(name, threshold)]
            tn, fp, fn, tp = matrix.ravel()
            y_true = np.array([0, 1], dtype=np.int8)
            # Derive aggregate metrics directly from the summed confusion matrix.
            precision = precision_score(
                [0] * (tn + fp) + [1] * (fn + tp),
                [0] * tn + [1] * fp + [0] * fn + [1] * tp,
                zero_division=0,
            ) if False else tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            accuracy = (tn + tp) / matrix.sum() if matrix.sum() else 0.0

            # Macro-F1 calculated from both class-wise precision and recall.
            benign_precision = tn / (tn + fn) if (tn + fn) else 0.0
            benign_recall = tn / (tn + fp) if (tn + fp) else 0.0
            benign_f1 = (
                2 * benign_precision * benign_recall
                / (benign_precision + benign_recall)
                if benign_precision + benign_recall
                else 0.0
            )
            attack_f1 = (
                2 * precision * recall / (precision + recall)
                if precision + recall
                else 0.0
            )
            macro_f1 = (benign_f1 + attack_f1) / 2

            print(
                f"{len(selected_columns):8d}  {threshold:9.2f}"
                f"  {precision:9.4f}  {recall:6.4f}"
                f"  {macro_f1:8.4f}  {fp:15,d}"
                f"  {fn:15,d}  {accuracy:8.4f}"
            )

    print("\nDiagnostic complete. No model or metrics artifact was saved.")


if __name__ == "__main__":
    main()
