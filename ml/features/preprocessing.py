import numpy as np
import pandas as pd

LABEL_COLUMN = "Label"


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Remove whitespace around column names."""
    df = df.copy()
    df.columns = df.columns.str.strip()
    return df


def normalize_labels(labels: pd.Series) -> pd.Series:
    """Convert labels into BENIGN or ATTACK."""
    normalized = labels.astype("string").str.strip().str.upper()
    return normalized.where(normalized == "BENIGN", "ATTACK")


def clean_features(df: pd.DataFrame) -> pd.DataFrame:
    """Clean numeric features and replace infinite values."""
    df = clean_column_names(df)

    if LABEL_COLUMN in df.columns:
        df = df.drop(columns=[LABEL_COLUMN])

    df = df.apply(pd.to_numeric, errors="coerce")
    df = df.replace([np.inf, -np.inf], np.nan)

    return df
