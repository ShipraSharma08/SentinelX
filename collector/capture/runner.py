
from __future__ import annotations

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scapy.utils import PcapReader

from collector.backend.backend_client import BackendPersistenceClient
from collector.backend.pipeline import NetworkFlowPipeline


def process_pcap(
    pcap_path: str | Path,
    pipeline: NetworkFlowPipeline | None = None,
) -> dict[str, Any]:
    path = Path(pcap_path)

    if not path.is_file():
        raise FileNotFoundError("PCAP file does not exist")

    if path.suffix.lower() not in {".pcap", ".pcapng"}:
        raise ValueError("Only .pcap and .pcapng files are supported")

    flow_pipeline = pipeline or NetworkFlowPipeline(
        backend_client=BackendPersistenceClient()
    )

    results: list[dict[str, Any]] = []
    last_timestamp: float | None = None
    packets_read = 0

    with PcapReader(str(path)) as reader:
        for packet in reader:
            packets_read += 1

            timestamp = float(packet.time)

            if not math.isfinite(timestamp) or timestamp < 0:
                raise ValueError("PCAP contains an invalid packet timestamp")

            if last_timestamp is not None and timestamp < last_timestamp:
                raise ValueError("PCAP packet timestamps are out of order")

            last_timestamp = timestamp

            results.extend(flow_pipeline.process_packet(packet))

            # Expire flows using the packet capture's timestamp.
            results.extend(flow_pipeline.flush_expired(timestamp))

    # Finalize all flows still active after reading the file.
    results.extend(flow_pipeline.flush_all())

    return {
        "source_file": path.name,
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "packets_read": packets_read,
        "pipeline_status": flow_pipeline.get_status(),
        "results": results,
    }


def save_report(
    report: dict[str, Any],
    output_path: str | Path,
) -> Path:
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    with destination.open("x", encoding="utf-8") as file:
        json.dump(report, file, indent=2, allow_nan=False)

    return destination


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Process an offline PCAP file through SentinelX"
    )

    parser.add_argument(
        "pcap",
        help="Path to a .pcap or .pcapng file",
    )

    parser.add_argument(
        "--output",
        default="collector/reports",
        help="Directory for the JSON report",
    )

    args = parser.parse_args()

    try:
        report = process_pcap(args.pcap)

        timestamp = datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )

        output_path = (
            Path(args.output)
            / f"flow_report_{timestamp}.json"
        )

        saved_path = save_report(report, output_path)

        print("SentinelX PCAP processing completed")
        print(f"Packets read: {report['packets_read']}")
        print(
            "Flows completed: "
            f"{report['pipeline_status']['flows_completed']}"
        )
        print(
            "Predictions succeeded: "
            f"{report['pipeline_status']['predictions_succeeded']}"
        )
        print(
            "Predictions failed: "
            f"{report['pipeline_status']['predictions_failed']}"
        )
        print(
            "Backend persistence succeeded: "
            f"{report['pipeline_status']['persistence_succeeded']}"
        )
        print(
            "Backend persistence failed: "
            f"{report['pipeline_status']['persistence_failed']}"
        )
        print(f"Report: {saved_path}")

    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    main()
