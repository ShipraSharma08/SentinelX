
from __future__ import annotations

from typing import Any

from scapy.packet import Packet

from collector.backend.backend_client import (
    BackendPersistenceClient,
    BackendPersistenceError,
)
from collector.backend.ml_client import (
    MLInferenceClient,
    MLInferenceError,
)
from collector.capture.parser import parse_packet
from collector.features.extractor import extract_features
from collector.flow.aggregator import FlowAggregator


class NetworkFlowPipeline:
    """
    Connect packet parsing, flow aggregation, feature extraction,
    ML inference, and optional backend persistence.

    Live packet capture is intentionally not started by this class.
    Packets must be supplied explicitly by the caller.
    """

    def __init__(
        self,
        aggregator: FlowAggregator | None = None,
        ml_client: MLInferenceClient | None = None,
        backend_client: BackendPersistenceClient | None = None,
    ):
        self.aggregator = aggregator or FlowAggregator()
        self.ml_client = ml_client or MLInferenceClient()
        self.backend_client = backend_client

        self.packets_processed = 0
        self.packets_ignored = 0
        self.flows_completed = 0
        self.predictions_succeeded = 0
        self.predictions_failed = 0
        self.persistence_succeeded = 0
        self.persistence_failed = 0

    @staticmethod
    def _flow_summary(flow: dict[str, Any]) -> dict[str, Any]:
        """Return identifying metadata without retaining packet content."""
        return {
            "event_id": flow["event_id"],
            "source_ip": flow["source_ip"],
            "destination_ip": flow["destination_ip"],
            "source_port": flow["source_port"],
            "destination_port": flow["destination_port"],
            "protocol": flow["protocol"],
            "packets": flow["packets"],
            "forward_packets": flow["forward_packets"],
            "backward_packets": flow["backward_packets"],
            "duration": flow["duration"],
            "first_seen": flow["first_seen"],
            "last_seen": flow["last_seen"],
        }

    @staticmethod
    def _build_backend_payload(
        flow: dict[str, Any],
        prediction: Any,
    ) -> dict[str, Any]:
        """Build the exact request contract expected by Spring Boot."""
        return {
            "event_id": flow["event_id"],
            "source_ip": flow["source_ip"],
            "destination_ip": flow["destination_ip"],
            "source_port": flow["source_port"],
            "destination_port": flow["destination_port"],
            "protocol": flow["protocol"],
            "bytes_sent": flow["bytes_sent"],
            "bytes_received": flow["bytes_received"],
            "packets": flow["packets"],
            "duration": flow["duration"],
            "first_seen": flow["first_seen"],
            "prediction": prediction.prediction,
            "attack_probability": prediction.attack_probability,
            "model": prediction.model,
        }

    def _persist_completed_flow(
        self,
        flow: dict[str, Any],
        prediction: Any,
    ) -> dict[str, Any]:
        """Persist one flow and its existing ML prediction."""
        if self.backend_client is None:
            return {
                "status": "not_configured",
            }

        payload = self._build_backend_payload(flow, prediction)

        try:
            result = self.backend_client.persist(payload)

        except BackendPersistenceError as exc:
            self.persistence_failed += 1

            return {
                "status": "failed",
                "error": str(exc),
            }

        self.persistence_succeeded += 1

        return {
            "status": result.status,
            "flow_id": result.flow_id,
            "prediction_id": result.prediction_id,
            "source_asset_id": result.source_asset_id,
            "destination_asset_id": result.destination_asset_id,
        }

    def _predict_completed_flow(
        self,
        flow: dict[str, Any],
    ) -> dict[str, Any]:
        """Extract features and request inference for one completed flow."""
        self.flows_completed += 1

        summary = self._flow_summary(flow)
        features = extract_features(flow)

        try:
            prediction = self.ml_client.predict(features)

        except MLInferenceError as exc:
            self.predictions_failed += 1

            return {
                "status": "inference_failed",
                "flow": summary,
                "features": features,
                "error": str(exc),
            }

        self.predictions_succeeded += 1

        persistence = self._persist_completed_flow(
            flow,
            prediction,
        )

        return {
            "status": "success",
            "flow": summary,
            "prediction": prediction.prediction,
            "attack_probability": prediction.attack_probability,
            "model": prediction.model,
            **(
                {"features": features}
                if prediction.prediction == "ATTACK"
                else {}
            ),
            "persistence": persistence,
        }

    def _process_completed_flows(
        self,
        flows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate one result for every completed flow."""
        return [
            self._predict_completed_flow(flow)
            for flow in flows
        ]

    def process_packet(
        self,
        packet: Packet,
    ) -> list[dict[str, Any]]:
        """
        Parse and aggregate one Scapy packet.

        Any flows expired during ingestion are immediately sent
        through feature extraction and ML inference.

        Returns an empty list when no flow completes.
        """
        packet_record = parse_packet(packet)

        if packet_record is None:
            self.packets_ignored += 1
            return []

        self.packets_processed += 1

        completed_flows = self.aggregator.ingest(packet_record)

        return self._process_completed_flows(completed_flows)

    def flush_expired(
        self,
        current_time: float,
    ) -> list[dict[str, Any]]:
        """
        Finalize flows whose idle timeout has elapsed.

        current_time must use the same timestamp units as packet records.
        """
        completed_flows = self.aggregator.flush_expired(current_time)

        return self._process_completed_flows(completed_flows)

    def flush_all(self) -> list[dict[str, Any]]:
        """Finalize all remaining active flows and run ML inference."""
        completed_flows = self.aggregator.flush_all()

        return self._process_completed_flows(completed_flows)

    def get_status(self) -> dict[str, int]:
        """Return pipeline processing and persistence counters."""
        return {
            "packets_processed": self.packets_processed,
            "packets_ignored": self.packets_ignored,
            "active_flows": len(self.aggregator.active_flows),
            "flows_completed": self.flows_completed,
            "predictions_succeeded": self.predictions_succeeded,
            "predictions_failed": self.predictions_failed,
            "persistence_succeeded": self.persistence_succeeded,
            "persistence_failed": self.persistence_failed,
        }
