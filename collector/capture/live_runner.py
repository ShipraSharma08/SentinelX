
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

from scapy.all import sniff

from collector.backend.backend_client import BackendPersistenceClient
from collector.backend.pipeline import NetworkFlowPipeline


def _print_diagnostics(results: list[dict[str, Any]]) -> None:
    """Print numerical features for successful ATTACK predictions only."""
    for result in results:
        if (
            result.get("status") == "success"
            and result.get("prediction") == "ATTACK"
            and isinstance(result.get("features"), dict)
        ):
            print("\n[SENTINELX ATTACK FEATURE DIAGNOSTICS]")
            print(json.dumps(
                result["features"],
                indent=2,
                sort_keys=True,
                allow_nan=False,
            ))
            print("[END ATTACK FEATURE DIAGNOSTICS]\n")


def _print_inference_failures(results: list[dict[str, Any]]) -> None:
    """Print inference_failed results and their error messages to stderr."""
    for result in results:
        status = result.get("status")
        if status == "inference_failed":
            error = result.get("error", "Unknown inference error")
            print(
                f"Inference failed: {error}",
                file=sys.stderr,
            )
        elif status == "feature_extraction_failed":
            error = result.get("error", "Unknown feature extraction error")
            print(
                f"Feature extraction failed: {error}",
                file=sys.stderr,
            )


def process_live_capture(
    interface: str,
    pipeline: NetworkFlowPipeline | None = None,
    duration: float = 0,
    flush_interval: float = 1.0,
    diagnostics: bool = False,
) -> dict[str, Any]:
    """
    Capture live packets and process them through SentinelX.

    duration=0 means capture continues until Ctrl+C.
    Packet timestamps and flow expiration use epoch time.
    Monotonic time is used only for scheduling.
    """
    if not interface or not interface.strip():
        raise ValueError("Network interface cannot be empty")

    if duration < 0:
        raise ValueError("Duration cannot be negative")

    if flush_interval <= 0:
        raise ValueError("Flush interval must be positive")

    flow_pipeline = pipeline or NetworkFlowPipeline(
        backend_client=BackendPersistenceClient()
    )

    processing_errors = 0
    capture_started = time.monotonic()
    last_flush = capture_started
    stop_reason = "duration_reached" if duration > 0 else "stopped"

    def handle_packet(packet) -> None:
        nonlocal processing_errors

        try:
            results = flow_pipeline.process_packet(packet)
            _print_inference_failures(results)
            if diagnostics:
                _print_diagnostics(results)
        except (ValueError, RuntimeError) as exc:
            processing_errors += 1
            print(
                f"Packet processing error: {exc}",
                file=sys.stderr,
            )

    print(f"Starting SentinelX live capture on {interface}")
    print("Press Ctrl+C to stop capture.")

    try:
        while True:
            now = time.monotonic()

            if duration > 0 and now - capture_started >= duration:
                break

            sniff(
                iface=interface,
                prn=handle_packet,
                store=False,
                timeout=flush_interval,
            )

            now = time.monotonic()

            if now - last_flush >= flush_interval:
                try:
                    results = flow_pipeline.flush_expired(time.time())
                    _print_inference_failures(results)
                    if diagnostics:
                        _print_diagnostics(results)
                except (ValueError, RuntimeError) as exc:
                    processing_errors += 1
                    print(
                        f"Flow flush error: {exc}",
                        file=sys.stderr,
                    )
                last_flush = now

    except KeyboardInterrupt:
        stop_reason = "interrupted"

    finally:
        # Finalize all active flows before reporting shutdown.
        try:
            results = flow_pipeline.flush_all()
            _print_inference_failures(results)
            if diagnostics:
                _print_diagnostics(results)
        except (ValueError, RuntimeError) as exc:
            processing_errors += 1
            print(
                f"Shutdown flush error: {exc}",
                file=sys.stderr,
            )

    status = flow_pipeline.get_status()

    report = {
        "interface": interface,
        "stop_reason": stop_reason,
        "duration_seconds": round(
            time.monotonic() - capture_started, 2
        ),
        "processing_errors": processing_errors,
        "pipeline_status": status,
    }

    print("\nSentinelX live capture stopped")
    print(f"Interface: {interface}")
    print(f"Stop reason: {stop_reason}")
    print(f"Packets processed: {status['packets_processed']}")
    print(f"Packets ignored: {status['packets_ignored']}")
    print(f"Flows completed: {status['flows_completed']}")
    print(f"Predictions succeeded: {status['predictions_succeeded']}")
    print(f"Predictions failed: {status['predictions_failed']}")
    print(f"Persistence succeeded: {status['persistence_succeeded']}")
    print(f"Persistence failed: {status['persistence_failed']}")
    print(f"Processing errors: {processing_errors}")

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SentinelX live network traffic capture"
    )

    parser.add_argument(
        "--interface",
        default=os.getenv("SENTINELX_CAPTURE_INTERFACE", "eth0"),
        help="Network interface to capture from (default: eth0)",
    )

    parser.add_argument(
        "--duration",
        type=float,
        default=0,
        help="Capture duration in seconds; 0 means until Ctrl+C",
    )

    parser.add_argument(
        "--flush-interval",
        type=float,
        default=1.0,
        help="Flow expiration check interval in seconds",
    )

    parser.add_argument(
        "--diagnostics",
        action="store_true",
        help="Print numerical features for successful ATTACK predictions",
    )

    args = parser.parse_args()

    try:
        process_live_capture(
            interface=args.interface,
            duration=args.duration,
            flush_interval=args.flush_interval,
            diagnostics=args.diagnostics,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"Live capture failed: {exc}\n")


if __name__ == "__main__":
    main()
