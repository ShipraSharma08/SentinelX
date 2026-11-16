
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from collector.config import (
    ML_PREDICT_URL,
    ML_REQUEST_TIMEOUT_SECONDS,
)
from collector.features.extractor import FEATURE_NAMES


class MLInferenceError(RuntimeError):
    """Raised when the ML inference service fails or returns invalid data."""


@dataclass(frozen=True)
class MLPrediction:
    prediction: str
    attack_probability: float
    model: str


class MLInferenceClient:
    """Synchronous HTTP client for SentinelX ML inference API."""

    def __init__(
        self,
        predict_url: str = ML_PREDICT_URL,
        timeout: float = ML_REQUEST_TIMEOUT_SECONDS,
    ):
        if not isinstance(predict_url, str) or not predict_url.strip():
            raise ValueError("Prediction URL must be a non-empty string")

        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("Timeout must be positive and finite")

        self.predict_url = predict_url
        self.timeout = float(timeout)

    @staticmethod
    def _validate_features(features: dict[str, float]) -> None:
        if not isinstance(features, dict):
            raise MLInferenceError("Features must be a dictionary")

        if tuple(features.keys()) != FEATURE_NAMES:
            raise MLInferenceError(
                "Feature names or order do not match the ML model contract"
            )

        for name, value in features.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise MLInferenceError(
                    f"Feature must be numeric: {name}"
                )

            if not math.isfinite(value):
                raise MLInferenceError(
                    f"Feature must be finite: {name}"
                )

    @staticmethod
    def _parse_response(body: bytes) -> MLPrediction:
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MLInferenceError(
                "ML service returned invalid JSON"
            ) from exc

        if not isinstance(data, dict):
            raise MLInferenceError(
                "ML service returned an invalid response structure"
            )

        prediction = data.get("prediction")
        probability = data.get("attack_probability")
        model = data.get("model")

        if prediction not in {"ATTACK", "BENIGN"}:
            raise MLInferenceError(
                "ML service returned an unsupported prediction label"
            )

        if (
            isinstance(probability, bool)
            or not isinstance(probability, (int, float))
            or not math.isfinite(probability)
            or not 0.0 <= probability <= 1.0
        ):
            raise MLInferenceError(
                "ML service returned an invalid attack probability"
            )

        if not isinstance(model, str) or not model.strip():
            raise MLInferenceError(
                "ML service returned an invalid model name"
            )

        return MLPrediction(
            prediction=prediction,
            attack_probability=float(probability),
            model=model,
        )

    def predict(self, features: dict[str, float]) -> MLPrediction:
        """Submit one validated flow feature record for inference."""
        self._validate_features(features)

        payload = json.dumps(
            {"features": features},
            allow_nan=False,
        ).encode("utf-8")

        request = Request(
            self.predict_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(
                request,
                timeout=self.timeout,
            ) as response:
                status_code = response.status

                if status_code != 200:
                    raise MLInferenceError(
                        f"ML service returned HTTP {status_code}"
                    )

                body = response.read()

        except HTTPError as exc:
            raise MLInferenceError(
                f"ML service returned HTTP {exc.code}"
            ) from exc

        except (URLError, TimeoutError, OSError) as exc:
            raise MLInferenceError(
                "Unable to communicate with the ML inference service"
            ) from exc

        return self._parse_response(body)
