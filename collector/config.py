
from __future__ import annotations

import math
import os
from urllib.parse import urlparse


def _load_http_url(environment_variable: str, default: str) -> str:
    """Load and validate an HTTP or HTTPS base URL."""
    value = os.getenv(environment_variable, default).strip().rstrip("/")
    parsed = urlparse(value)

    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"Invalid {environment_variable}")

    return value


def _load_timeout(environment_variable: str, default: str) -> float:
    """Load a positive finite HTTP request timeout."""
    raw_value = os.getenv(environment_variable, default)

    try:
        timeout = float(raw_value)
    except ValueError as exc:
        raise ValueError(
            f"{environment_variable} must be numeric"
        ) from exc

    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError(
            f"{environment_variable} must be positive and finite"
        )

    return timeout


ML_API_BASE_URL = _load_http_url(
    "SENTINELX_ML_API_URL",
    "http://127.0.0.1:8000",
)

ML_PREDICT_URL = f"{ML_API_BASE_URL}/predict"

ML_REQUEST_TIMEOUT_SECONDS = _load_timeout(
    "SENTINELX_ML_REQUEST_TIMEOUT",
    "10",
)

BACKEND_API_BASE_URL = _load_http_url(
    "SENTINELX_BACKEND_API_URL",
    "http://127.0.0.1:8080",
)

BACKEND_COLLECTOR_FLOW_URL = (
    f"{BACKEND_API_BASE_URL}/api/collector/flows"
)

BACKEND_REQUEST_TIMEOUT_SECONDS = _load_timeout(
    "SENTINELX_BACKEND_REQUEST_TIMEOUT",
    "10",
)
