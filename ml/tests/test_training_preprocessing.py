import pandas as pd

from ml.training.train_baseline import prepare_features


def test_prepare_features_ignores_missing_and_blank_labels():
    data = pd.DataFrame({
        " Flow Duration ": [100, 200, 300, 400, 500],
        "Label": ["BENIGN", "DDoS", "", "   ", None],
    })

    features, targets = prepare_features(data)

    assert len(features) == 2
    assert targets.tolist() == [0, 1]
    assert features["Flow Duration"].tolist() == [100, 200]
