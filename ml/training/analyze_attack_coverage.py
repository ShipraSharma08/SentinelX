from collections import Counter

import pandas as pd

from ml.training.train_baseline import DATA_DIR, TEST_FILE_NAME

VALIDATION_FILE = "Tuesday-WorkingHours.pcap_ISCX.csv"
CHUNK_SIZE = 100_000


def find_label_column(path):
    columns = pd.read_csv(path, nrows=0, low_memory=False).columns

    for column in columns:
        normalized = str(column).replace("\ufeff", "").strip().lower()
        if normalized == "label":
            return column

    raise ValueError(f"Label column not found in {path.name}")


def count_labels(path):
    label_column = find_label_column(path)
    counts = Counter()
    rows_read = 0

    for chunk in pd.read_csv(
        path,
        usecols=[label_column],
        chunksize=CHUNK_SIZE,
        low_memory=False,
    ):
        labels = (
            chunk[label_column]
            .astype("string")
            .str.replace("\ufeff", "", regex=False)
            .str.strip()
        )

        labels = labels[labels.notna() & labels.ne("")]
        counts.update(labels.tolist())
        rows_read += len(chunk)

    return counts, rows_read


def main():
    validation_path = DATA_DIR / VALIDATION_FILE

    if not validation_path.is_file():
        raise FileNotFoundError(validation_path)

    csv_files = sorted(DATA_DIR.glob("*.csv"))

    if sum(p.name == TEST_FILE_NAME for p in csv_files) != 1:
        raise ValueError("Expected exactly one Wednesday holdout.")

    training_files = [
        path for path in csv_files
        if path.name not in {VALIDATION_FILE, TEST_FILE_NAME}
    ]

    if not training_files:
        raise ValueError("No training captures found.")

    training_attack_labels = set()
    validation_attack_labels = set()

    print("Training captures:", len(training_files))
    print("Validation capture:", VALIDATION_FILE)
    print("Wednesday final holdout: EXCLUDED")

    for path in training_files + [validation_path]:
        print(f"\nScanning labels: {path.name}")
        counts, rows_read = count_labels(path)

        benign_count = sum(
            count for label, count in counts.items()
            if label.upper() == "BENIGN"
        )
        attack_counts = {
            label: count
            for label, count in counts.items()
            if label.upper() != "BENIGN"
        }

        print(f"Rows with labels: {sum(counts.values()):,}")
        print(f"BENIGN: {benign_count:,}")
        print(f"ATTACK: {sum(attack_counts.values()):,}")
        print("Attack-label counts:")

        if attack_counts:
            for label, count in sorted(
                attack_counts.items(),
                key=lambda item: item[1],
                reverse=True,
            ):
                print(f"  {label}: {count:,}")
        else:
            print("  No attack labels")

        if path.name == VALIDATION_FILE:
            validation_attack_labels.update(attack_counts)
        else:
            training_attack_labels.update(attack_counts)

    unseen = validation_attack_labels - training_attack_labels

    print("\n=== ATTACK-LABEL COVERAGE ===")
    print("Attack types in training:", len(training_attack_labels))
    print("Attack types in Tuesday:", len(validation_attack_labels))

    print("\nTuesday attack types also present in training:")
    for label in sorted(validation_attack_labels & training_attack_labels):
        print(f"  {label}")

    print("\nTuesday attack types absent from training:")
    if unseen:
        for label in sorted(unseen):
            print(f"  {label}")
    else:
        print("  None")

    print("\nCoverage diagnostic complete.")
    print("No model or artifact saved.")
    print("Wednesday holdout was not read.")


if __name__ == "__main__":
    main()
