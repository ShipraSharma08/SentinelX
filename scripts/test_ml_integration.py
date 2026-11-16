import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.inference.predict import _load_model

BASE_URL = "http://127.0.0.1:8080"
CREDENTIALS_FILE = ROOT / ".sentinelx-test-credentials.json"


def post(path, payload, token=None):
    headers = {"Content-Type": "application/json"}

    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(
        BASE_URL + path,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            return response.status, json.loads(response.read())

    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        print(f"HTTP {exc.code}: {body}")
        return exc.code, None


def create_local_test_account():
    suffix = secrets.token_hex(5)

    credentials = {
        "username": f"sentinelx_test_{suffix}",
        "email": f"sentinelx.test.{suffix}@example.com",
        "password": secrets.token_urlsafe(32),
    }

    print("Creating a dedicated SentinelX test account...")

    status, response = post("/api/auth/register", credentials)

    if status != 201:
        raise SystemExit(
            "Test account registration failed. "
            "Check the backend response above."
        )

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(CREDENTIALS_FILE, flags, 0o600)

    with os.fdopen(fd, "w") as file:
        json.dump(credentials, file)

    os.chmod(CREDENTIALS_FILE, 0o600)

    print("Test account created.")
    print("Local credentials saved with restricted permissions.")

    return credentials


def load_credentials():
    if not CREDENTIALS_FILE.exists():
        return create_local_test_account()

    if os.name == "posix":
        permissions = CREDENTIALS_FILE.stat().st_mode & 0o777
        if permissions & 0o077:
            os.chmod(CREDENTIALS_FILE, 0o600)

    try:
        credentials = json.loads(CREDENTIALS_FILE.read_text())
        for key in ("username", "email", "password"):
            if not credentials.get(key):
                raise ValueError(f"Missing {key}")
        return credentials

    except (ValueError, OSError, json.JSONDecodeError):
        raise SystemExit(
            "Local test credentials file is invalid. "
            "No credentials were printed or overwritten."
        )


def main():
    print("\n=== SentinelX ML Integration Test ===\n")

    credentials = load_credentials()

    # Authenticate automatically; JWT stays in memory.
    status, login_data = post(
        "/api/auth/login",
        {
            "usernameOrEmail": credentials["username"],
            "password": credentials["password"],
        },
    )

    if status != 200 or not login_data:
        raise SystemExit(
            "Login failed. Check whether the local test account "
            "still exists and is enabled."
        )

    token = login_data.get("accessToken")

    if not token:
        raise SystemExit("Login response did not contain an access token.")

    print("\nPASS: Automatic authentication successful.")

    # Generate synthetic model-compatible features.
    _, feature_names = _load_model()
    features = {name: 0.0 for name in feature_names}
    features["Destination Port"] = 80.0

    # Send authenticated prediction request.
    status, result = post(
        "/api/ml/predict",
        {"features": features},
        token,
    )

    if status != 201 or not result:
        raise SystemExit("Backend prediction request failed.")

    print("\nPASS: Backend prediction request successful.")
    print("HTTP Status:", status)

    # Display response without exposing authentication data.
    safe_fields = (
        "id",
        "prediction",
        "model",
        "modelVersion",
        "confidence",
        "riskScore",
        "predictedAt",
    )

    safe_result = {
        key: result[key]
        for key in safe_fields
        if key in result
    }

    print(json.dumps(safe_result, indent=2))
    print("\nJWT was neither displayed nor saved.")
    print("Test credentials remain in the ignored local file.")


if __name__ == "__main__":
    main()
