
from __future__ import annotations

import json
import math
import os
import uuid
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from collector.config import (
    BACKEND_COLLECTOR_FLOW_URL,
    BACKEND_REQUEST_TIMEOUT_SECONDS,
)


class BackendPersistenceError(RuntimeError):
    """Raised when the backend cannot persist a completed flow."""


@dataclass(frozen=True)
class BackendPersistenceResult:
    flow_id: int
    prediction_id: int
    source_asset_id: int
    destination_asset_id: int
    status: str


class BackendPersistenceClient:
    """HTTP client for the SentinelX collector ingestion API."""

    REQUIRED_FIELDS = (
        "event_id",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "bytes_sent",
        "bytes_received",
        "packets",
        "duration",
        "first_seen",
        "prediction",
        "attack_probability",
        "model",
    )

    def __init__(
        self,
        ingest_url: str = BACKEND_COLLECTOR_FLOW_URL,
        api_key: str | None = None,
        timeout: float = BACKEND_REQUEST_TIMEOUT_SECONDS,
    ):
        if not isinstance(ingest_url, str) or not ingest_url.strip():
            raise ValueError("Backend ingestion URL must be non-empty")

        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("Timeout must be positive and finite")

        self.ingest_url = ingest_url
        self.api_key = (
            api_key
            if api_key is not None
            else os.getenv("SENTINELX_COLLECTOR_API_KEY", "")
        )
        self.timeout = float(timeout)

    @classmethod
    def _validate_payload(cls, payload: dict) -> None:
        if not isinstance(payload, dict):
            raise BackendPersistenceError(
                "Backend payload must be a dictionary"
            )

        missing_fields = [
            field for field in cls.REQUIRED_FIELDS
            if field not in payload
        ]

        if missing_fields:
            raise BackendPersistenceError(
                "Backend payload is missing required fields: "
                + ", ".join(missing_fields)
            )

        event_id = payload["event_id"]

        if not isinstance(event_id, str) or not event_id.strip():
            raise BackendPersistenceError(
                "Invalid backend payload field: event_id"
            )

        try:
            uuid.UUID(event_id)
        except (ValueError, AttributeError, TypeError) as exc:
            raise BackendPersistenceError(
                "event_id must be a valid UUID"
            ) from exc

        for field in (
            "source_ip",
            "destination_ip",
            "protocol",
            "prediction",
            "model",
        ):
            value = payload[field]

            if not isinstance(value, str) or not value.strip():
                raise BackendPersistenceError(
                    f"Invalid backend payload field: {field}"
                )

        if payload["protocol"] not in {"TCP", "UDP", "ICMP", "OTHER"}:
            raise BackendPersistenceError("Unsupported flow protocol")

        if payload["prediction"] not in {"ATTACK", "BENIGN"}:
            raise BackendPersistenceError("Unsupported prediction label")

        for field in ("source_port", "destination_port"):
            value = payload[field]

            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= 65535
            ):
                raise BackendPersistenceError(
                    f"Invalid backend payload field: {field}"
                )

        for field in ("bytes_sent", "bytes_received", "packets"):
            value = payload[field]

            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < (1 if field == "packets" else 0)
            ):
                raise BackendPersistenceError(
                    f"Invalid backend payload field: {field}"
                )

        for field in ("duration", "first_seen", "attack_probability"):
            value = payload[field]

            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise BackendPersistenceError(
                    f"Invalid backend payload field: {field}"
                )

        if payload["duration"] < 0 or payload["first_seen"] < 0:
            raise BackendPersistenceError(
                "Flow timestamps and duration cannot be negative"
            )

        if not 0.0 <= payload["attack_probability"] <= 1.0:
            raise BackendPersistenceError(
                "Attack probability must be between 0 and 1"
            )

    @staticmethod
    def _parse_response(body: bytes) -> BackendPersistenceResult:
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BackendPersistenceError(
                "Backend returned invalid JSON"
            ) from exc

        if not isinstance(data, dict):
            raise BackendPersistenceError(
                "Backend returned an invalid response structure"
            )

        if data.get("status") != "SAVED":
            raise BackendPersistenceError(
                "Backend did not confirm flow persistence"
            )

        id_fields = (
            "flowId",
            "predictionId",
            "sourceAssetId",
            "destinationAssetId",
        )

        ids = {}

        for field in id_fields:
            value = data.get(field)

            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
            ):
                raise BackendPersistenceError(
                    f"Backend returned an invalid {field}"
                )

            ids[field] = value

        return BackendPersistenceResult(
            flow_id=ids["flowId"],
            prediction_id=ids["predictionId"],
            source_asset_id=ids["sourceAssetId"],
            destination_asset_id=ids["destinationAssetId"],
            status="SAVED",
        )

    def persist(self, payload: dict) -> BackendPersistenceResult:
        """Send a completed flow and its prediction to Spring Boot."""
        self._validate_payload(payload)

        if not isinstance(self.api_key, str) or not self.api_key.strip():
            raise BackendPersistenceError(
                "Collector API key is not configured"
            )

        body = json.dumps(
            payload,
            allow_nan=False,
        ).encode("utf-8")

        request = Request(
            self.ingest_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Collector-Key": self.api_key,
            },
            method="POST",
        )

        try:
            with urlopen(
                request,
                timeout=self.timeout,
            ) as response:
                if response.status != 201:
                    raise BackendPersistenceError(
                        f"Backend returned HTTP {response.status}"
                    )

                response_body = response.read()

        except HTTPError as exc:
            raise BackendPersistenceError(
                f"Backend returned HTTP {exc.code}"
            ) from exc

        except (URLError, TimeoutError, OSError) as exc:
            raise BackendPersistenceError(
                "Unable to communicate with the SentinelX backend"
            ) from exc

        return self._parse_response(response_body)
