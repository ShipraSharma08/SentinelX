
import json

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import PcapWriter

from collector.backend.ml_client import MLPrediction
from collector.backend.pipeline import NetworkFlowPipeline
from collector.capture.runner import process_pcap, save_report


class FakeMLClient:
    def predict(self, features):
        assert len(features) == 70

        return MLPrediction(
            prediction="BENIGN",
            attack_probability=0.02,
            model="test-model",
        )


def create_test_pcap(path):
    packets = [
        (
            IP(src="192.168.1.10", dst="192.168.1.20")
            / TCP(sport=50000, dport=80, flags="S", window=64240)
            / Raw(load=b"hello")
        ),
        (
            IP(src="192.168.1.20", dst="192.168.1.10")
            / TCP(sport=80, dport=50000, flags="PA", window=64240)
            / Raw(load=b"world")
        ),
    ]

    packets[0].time = 1.0
    packets[1].time = 1.5

    writer = PcapWriter(str(path), append=False, sync=True)

    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()


def test_process_pcap_reads_packets_and_predicts(tmp_path):
    pcap_path = tmp_path / "test_traffic.pcap"
    create_test_pcap(pcap_path)

    pipeline = NetworkFlowPipeline(
        ml_client=FakeMLClient()
    )

    report = process_pcap(pcap_path, pipeline)

    assert report["packets_read"] == 2
    assert report["pipeline_status"]["packets_processed"] == 2
    assert report["pipeline_status"]["flows_completed"] == 1
    assert report["pipeline_status"]["predictions_succeeded"] == 1
    assert report["pipeline_status"]["predictions_failed"] == 0

    assert len(report["results"]) == 1
    assert report["results"][0]["status"] == "success"
    assert report["results"][0]["prediction"] == "BENIGN"


def test_process_pcap_returns_source_filename(tmp_path):
    pcap_path = tmp_path / "sample.pcap"
    create_test_pcap(pcap_path)

    report = process_pcap(
        pcap_path,
        NetworkFlowPipeline(ml_client=FakeMLClient()),
    )

    assert report["source_file"] == "sample.pcap"
    assert report["processed_at"]


def test_process_pcap_rejects_missing_file(tmp_path):
    missing_path = tmp_path / "missing.pcap"

    with pytest.raises(FileNotFoundError):
        process_pcap(missing_path)


def test_process_pcap_rejects_unsupported_extension(tmp_path):
    unsupported_path = tmp_path / "traffic.txt"
    unsupported_path.write_text("not a packet capture")

    with pytest.raises(ValueError, match="Only .pcap and .pcapng"):
        process_pcap(unsupported_path)


def test_process_pcap_rejects_out_of_order_timestamps(tmp_path):
    pcap_path = tmp_path / "out_of_order.pcap"

    packets = [
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=80, flags="S"),
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=80, flags="A"),
    ]

    packets[0].time = 2.0
    packets[1].time = 1.0

    writer = PcapWriter(str(pcap_path), append=False, sync=True)

    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()

    with pytest.raises(ValueError, match="timestamps are out of order"):
        process_pcap(
            pcap_path,
            NetworkFlowPipeline(ml_client=FakeMLClient()),
        )


def test_save_report_creates_json_file(tmp_path):
    report = {
        "source_file": "test.pcap",
        "packets_read": 2,
        "results": [],
    }

    output_path = tmp_path / "reports" / "report.json"

    saved_path = save_report(report, output_path)

    assert saved_path == output_path
    assert saved_path.is_file()

    with saved_path.open(encoding="utf-8") as file:
        saved_report = json.load(file)

    assert saved_report == report


def test_save_report_does_not_overwrite_existing_file(tmp_path):
    output_path = tmp_path / "report.json"
    output_path.write_text('{"original": true}', encoding="utf-8")

    with pytest.raises(FileExistsError):
        save_report({"changed": True}, output_path)

    assert json.loads(output_path.read_text()) == {"original": True}
