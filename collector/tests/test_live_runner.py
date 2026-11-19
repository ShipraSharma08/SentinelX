
import pytest

from collector.capture import live_runner


class FakePipeline:
    def __init__(self):
        self.packets = []
        self.expired_flushes = []
        self.final_flush_count = 0

    def process_packet(self, packet):
        self.packets.append(packet)
        return []

    def flush_expired(self, current_time):
        self.expired_flushes.append(current_time)
        return []

    def flush_all(self):
        self.final_flush_count += 1
        return []

    def get_status(self):
        return {
            "packets_processed": len(self.packets),
            "packets_ignored": 0,
            "flows_completed": 0,
            "predictions_succeeded": 0,
            "predictions_failed": 0,
            "persistence_succeeded": 0,
            "persistence_failed": 0,
            "active_flows": 0,
        }


def test_live_capture_processes_packets_and_handles_shutdown(monkeypatch):
    pipeline = FakePipeline()
    captured_packet = object()

    def fake_sniff(**kwargs):
        kwargs["prn"](captured_packet)
        raise KeyboardInterrupt

    monkeypatch.setattr(live_runner, "sniff", fake_sniff)

    report = live_runner.process_live_capture(
        interface="eth0",
        pipeline=pipeline,
    )

    assert pipeline.packets == [captured_packet]
    assert pipeline.final_flush_count == 1
    assert report["stop_reason"] == "interrupted"
    assert report["pipeline_status"]["packets_processed"] == 1


def test_live_capture_uses_configured_interface(monkeypatch):
    pipeline = FakePipeline()
    captured_interfaces = []

    def fake_sniff(**kwargs):
        captured_interfaces.append(kwargs["iface"])
        raise KeyboardInterrupt

    monkeypatch.setattr(live_runner, "sniff", fake_sniff)

    live_runner.process_live_capture(
        interface="eth0",
        pipeline=pipeline,
    )

    assert captured_interfaces == ["eth0"]


@pytest.mark.parametrize(
    "interface",
    ["", "   "],
)
def test_live_capture_rejects_empty_interface(interface):
    with pytest.raises(ValueError, match="interface cannot be empty"):
        live_runner.process_live_capture(interface=interface)


def test_live_capture_rejects_negative_duration():
    with pytest.raises(ValueError, match="Duration cannot be negative"):
        live_runner.process_live_capture(
            interface="eth0",
            duration=-1,
        )


def test_live_capture_rejects_invalid_flush_interval():
    with pytest.raises(ValueError, match="Flush interval must be positive"):
        live_runner.process_live_capture(
            interface="eth0",
            flush_interval=0,
        )


def test_diagnostics_prints_features_for_attack_only(capsys):
    attack_features = {"feature_1": 12.5, "feature_2": 30.0}

    live_runner._print_diagnostics([
        {
            "status": "success",
            "prediction": "ATTACK",
            "features": attack_features,
        },
        {
            "status": "success",
            "prediction": "BENIGN",
        },
    ])

    output = capsys.readouterr().out

    assert "[SENTINELX ATTACK FEATURE DIAGNOSTICS]" in output
    assert '"feature_1": 12.5' in output
    assert '"feature_2": 30.0' in output
    assert output.count("[SENTINELX ATTACK FEATURE DIAGNOSTICS]") == 1


def test_diagnostics_ignores_failed_predictions(capsys):
    live_runner._print_diagnostics([
        {
            "status": "inference_failed",
            "prediction": "ATTACK",
            "features": {"feature_1": 12.5},
        },
    ])

    assert capsys.readouterr().out == ""


def test_inference_failures_are_logged_to_stderr(capsys):
    live_runner._print_inference_failures([
        {
            "status": "inference_failed",
            "error": "Unable to communicate with the ML inference service",
        },
        {
            "status": "success",
            "prediction": "BENIGN",
        },
    ])

    captured = capsys.readouterr()
    assert "Inference failed: Unable to communicate with the ML inference service" in captured.err
    assert captured.out == ""


def test_live_capture_logs_inference_failures_to_stderr(monkeypatch, capsys):
    class FailingPipeline(FakePipeline):
        def process_packet(self, packet):
            return [{
                "status": "inference_failed",
                "error": "ML service returned HTTP 500",
            }]

    pipeline = FailingPipeline()

    def fake_sniff(**kwargs):
        kwargs["prn"](object())
        raise KeyboardInterrupt

    monkeypatch.setattr(live_runner, "sniff", fake_sniff)

    live_runner.process_live_capture(
        interface="eth0",
        pipeline=pipeline,
    )

    captured = capsys.readouterr()
    assert "Inference failed: ML service returned HTTP 500" in captured.err
