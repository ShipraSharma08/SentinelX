import json
import os
import sys
import time
import uuid
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from collector.backend.backend_client import BackendPersistenceClient, BackendPersistenceError

BASE_URL = "http://127.0.0.1:8080"
API_KEY = os.getenv("SENTINELX_COLLECTOR_API_KEY")

if not API_KEY:
    raise RuntimeError(
        "SENTINELX_COLLECTOR_API_KEY is not set. "
        "Load it from your environment before running this integration test."
    )


def run_tests():
    print("=== SentinelX Backend Integration Audit & Validation ===")

    # 1. Test Collector Auth: missing key
    print("\n[1] Testing collector authentication: missing key...")
    req = urllib.request.Request(
        f"{BASE_URL}/api/collector/flows",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        urllib.request.urlopen(req)
        print("FAIL: Expected 401 Unauthorized for missing key")
        sys.exit(1)
    except urllib.error.HTTPError as e:
        assert e.code == 401, f"Expected 401, got {e.code}"
        print(f"PASS: Missing key returned HTTP {e.code}")

    # 2. Test Collector Auth: invalid key
    print("\n[2] Testing collector authentication: invalid key...")
    req = urllib.request.Request(
        f"{BASE_URL}/api/collector/flows",
        data=b"{}",
        headers={
            "Content-Type": "application/json",
            "X-Collector-Key": "wrong_key_123",
        },
        method="POST",
    )

    try:
        urllib.request.urlopen(req)
        print("FAIL: Expected 401 Unauthorized for invalid key")
        sys.exit(1)
    except urllib.error.HTTPError as e:
        assert e.code == 401, f"Expected 401, got {e.code}"
        print(f"PASS: Invalid key returned HTTP {e.code}")

    # 3. Test Ingest BENIGN flow via BackendPersistenceClient
    print("\n[3] Testing BENIGN flow ingestion via BackendPersistenceClient...")

    client = BackendPersistenceClient(
        ingest_url=f"{BASE_URL}/api/collector/flows",
        api_key=API_KEY,
    )

    benign_event_id = str(uuid.uuid4())

    benign_payload = {
        "event_id": benign_event_id,
        "source_ip": "10.0.0.42",
        "destination_ip": "10.0.0.1",
        "source_port": 49152,
        "destination_port": 443,
        "protocol": "TCP",
        "bytes_sent": 1500,
        "bytes_received": 3000,
        "packets": 12,
        "duration": 0.45,
        "first_seen": time.time(),
        "prediction": "BENIGN",
        "attack_probability": 0.02,
        "model": "web_coverage_candidate.joblib",
    }

    res1 = client.persist(benign_payload)

    print(
        f"PASS: Flow ingested successfully: "
        f"flow_id={res1.flow_id}, "
        f"prediction_id={res1.prediction_id}, "
        f"status={res1.status}"
    )

    assert res1.flow_id > 0
    assert res1.prediction_id > 0
    assert res1.status == "SAVED"

    # 4. Test Idempotency: exact replay of BENIGN flow
    print("\n[4] Testing idempotency replay of same flow...")

    res1_replay = client.persist(benign_payload)

    print(
        f"PASS: Replayed flow returned existing record: "
        f"flow_id={res1_replay.flow_id}, "
        f"prediction_id={res1_replay.prediction_id}"
    )

    assert res1_replay.flow_id == res1.flow_id
    assert res1_replay.prediction_id == res1.prediction_id

    # 5. Test Conflict: replay same event_id with altered data
    print("\n[5] Testing conflict on altered flow with same event_id...")

    conflicting_payload = dict(benign_payload)
    conflicting_payload["destination_port"] = 8080

    try:
        client.persist(conflicting_payload)
        print("FAIL: Expected conflict HTTP 409")
        sys.exit(1)
    except BackendPersistenceError as e:
        assert "409" in str(e), f"Expected 409 error, got {e}"
        print(f"PASS: Conflicting payload correctly returned HTTP 409: {e}")

    # 6. Test Ingest ATTACK flow
    print("\n[6] Testing ATTACK flow ingestion (triggers SecurityEvent and Alert)...")

    attack_event_id = str(uuid.uuid4())

    attack_payload = {
        "event_id": attack_event_id,
        "source_ip": "10.0.0.99",
        "destination_ip": "10.0.0.1",
        "source_port": 55555,
        "destination_port": 80,
        "protocol": "TCP",
        "bytes_sent": 50000,
        "bytes_received": 200,
        "packets": 500,
        "duration": 1.25,
        "first_seen": time.time(),
        "prediction": "ATTACK",
        "attack_probability": 0.96,
        "model": "web_coverage_candidate.joblib",
    }

    res2 = client.persist(attack_payload)

    print(
        f"PASS: Attack flow ingested: "
        f"flow_id={res2.flow_id}, "
        f"prediction_id={res2.prediction_id}, "
        f"status={res2.status}"
    )

    # 7. Test Frontend auth and API endpoints
    print("\n[7] Testing frontend auth and API endpoints...")

    # Load credentials or register test user
    cred_file = ROOT / ".sentinelx-test-credentials.json"

    if not cred_file.exists():
        import secrets

        suffix = secrets.token_hex(5)

        credentials = {
            "username": f"sentinelx_test_{suffix}",
            "email": f"sentinelx.test.{suffix}@example.com",
            "password": secrets.token_urlsafe(32),
        }

        reg_req = urllib.request.Request(
            f"{BASE_URL}/api/auth/register",
            data=json.dumps(credentials).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(reg_req) as resp:
            pass

        cred_file.write_text(json.dumps(credentials))

    else:
        credentials = json.loads(cred_file.read_text())

    login_req = urllib.request.Request(
        f"{BASE_URL}/api/auth/login",
        data=json.dumps({
            "usernameOrEmail": credentials["username"],
            "password": credentials["password"],
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(login_req) as resp:
        login_data = json.loads(resp.read())
        assert resp.status == 200, f"Login failed: status={resp.status}"

    token = login_data["accessToken"]

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    # Overview
    req = urllib.request.Request(
        f"{BASE_URL}/api/dashboard/overview",
        headers=headers,
    )

    with urllib.request.urlopen(req) as resp:
        overview = json.loads(resp.read())

        print(
            f"PASS: Dashboard overview: "
            f"totalNetworkFlows={overview['totalNetworkFlows']}, "
            f"totalPredictions={overview['totalPredictions']}, "
            f"totalAlerts={overview['totalAlerts']}, "
            f"openAlerts={overview['openAlerts']}, "
            f"criticalAlerts={overview['criticalAlerts']}"
        )

        assert overview["totalNetworkFlows"] >= 2
        assert overview["totalAlerts"] >= 1

    # Recent alerts
    req = urllib.request.Request(
        f"{BASE_URL}/api/dashboard/recent-alerts",
        headers=headers,
    )

    with urllib.request.urlopen(req) as resp:
        recent_alerts = json.loads(resp.read())

        print(f"PASS: Recent alerts count: {len(recent_alerts)}")

        matching_alerts = [
            a for a in recent_alerts
            if a.get("mlPredictionId") == res2.prediction_id
        ]

        assert len(matching_alerts) == 1, (
            "Alert for ATTACK prediction not found in recent alerts"
        )

        alert = matching_alerts[0]
        alert_id = alert["id"]

        print(
            f"PASS: Found alert for attack: "
            f"id={alert_id}, "
            f"severity={alert['severity']}, "
            f"status={alert['status']}, "
            f"riskScore={alert['riskScore']}"
        )

        assert alert["severity"] == "CRITICAL"
        assert alert["status"] == "OPEN"

    # Alert lifecycle: acknowledge and resolve
    print("\n[8] Testing Alert RBAC and acknowledge/resolve lifecycle...")

    # 8a: Register a viewer to verify RBAC 403 Forbidden
    import secrets

    viewer_name = f"viewer_{secrets.token_hex(4)}"

    viewer_payload = {
        "username": viewer_name,
        "email": f"{viewer_name}@example.com",
        "password": secrets.token_urlsafe(20),
    }

    viewer_reg = urllib.request.Request(
        f"{BASE_URL}/api/auth/register",
        data=json.dumps(viewer_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(viewer_reg) as resp:
        viewer_token = json.loads(resp.read())["accessToken"]

    viewer_headers = {
        "Authorization": f"Bearer {viewer_token}",
        "Accept": "application/json",
    }

    ack_req = urllib.request.Request(
        f"{BASE_URL}/api/alerts/{alert_id}/acknowledge",
        headers=viewer_headers,
        method="PATCH",
    )

    try:
        urllib.request.urlopen(ack_req)
        print("FAIL: Expected 403 Forbidden for VIEWER role on alert acknowledge")
        sys.exit(1)

    except urllib.error.HTTPError as e:
        assert e.code == 403, (
            f"Expected 403 Forbidden for VIEWER, got {e.code}"
        )

        print(
            f"PASS: VIEWER correctly received HTTP 403 Forbidden "
            f"on alert acknowledge: {e.code}"
        )

    # 8b: Now acknowledge with SOC_ANALYST user
    ack_req2 = urllib.request.Request(
        f"{BASE_URL}/api/alerts/{alert_id}/acknowledge",
        headers=headers,
        method="PATCH",
    )

    with urllib.request.urlopen(ack_req2) as resp:
        ack_data = json.loads(resp.read())

        print(
            f"PASS: SOC_ANALYST acknowledged alert: "
            f"id={ack_data['id']}, "
            f"status={ack_data['status']}, "
            f"acknowledgedAt={ack_data['acknowledgedAt']}"
        )

        assert ack_data["status"] == "ACKNOWLEDGED"
        assert ack_data["acknowledgedAt"] is not None

    # 8c: Resolve with SOC_ANALYST user
    resolve_req = urllib.request.Request(
        f"{BASE_URL}/api/alerts/{alert_id}/resolve",
        headers=headers,
        method="PATCH",
    )

    with urllib.request.urlopen(resolve_req) as resp:
        resolve_data = json.loads(resp.read())

        print(
            f"PASS: SOC_ANALYST resolved alert: "
            f"id={resolve_data['id']}, "
            f"status={resolve_data['status']}, "
            f"resolvedAt={resolve_data['resolvedAt']}"
        )

        assert resolve_data["status"] == "RESOLVED"
        assert resolve_data["resolvedAt"] is not None

    print("\n=== ALL INTEGRATION CHECKS PASSED SUCCESSFULLY! ===")


if __name__ == "__main__":
    run_tests()
