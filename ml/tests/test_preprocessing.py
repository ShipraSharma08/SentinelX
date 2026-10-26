import numpy as np
import pandas as pd

from ml.features.preprocessing import clean_features, normalize_labels


def test_clean_column_names_and_remove_label():
    df = pd.DataFrame({
        " Flow Duration ": [1.0, 2.0],
        " Label ": ["BENIGN", "DDoS"],
    })

    result = clean_features(df)

    assert list(result.columns) == ["Flow Duration"]
    assert result["Flow Duration"].tolist() == [1.0, 2.0]


def test_infinite_values_become_nan():
    df = pd.DataFrame({
        "Flow Duration": [1.0, np.inf, -np.inf],
    })

    result = clean_features(df)

    assert result["Flow Duration"].iloc[0] == 1.0
    assert result["Flow Duration"].iloc[1:].isna().all()


def test_normalize_binary_labels():
    labels = pd.Series([" BENIGN ", "DDoS", "Bot", "PortScan"])

    result = normalize_labels(labels)

    assert result.tolist() == [
        "BENIGN", "ATTACK", "ATTACK", "ATTACK"
    ]


def test_original_dataframe_is_not_modified():
    df = pd.DataFrame({
        " Flow Duration ": [1.0, np.inf],
        " Label ": ["BENIGN", "DDoS"],
    })
    original = df.copy(deep=True)

    clean_features(df)

    pd.testing.assert_frame_equal(df, original)