"""End-to-end API tests. Skipped automatically if the web dependencies are missing."""
import os
from unittest.mock import patch

import pytest

for module in ("fastapi", "httpx", "jose", "passlib", "multipart"):
    pytest.importorskip(module)

os.environ["APP_ENV"] = "development"
os.environ["DEMO_USERNAME"] = "tester"
os.environ["DEMO_PASSWORD"] = "test-password"
os.environ.pop("VT_API_KEY", None)  # never call the network from tests

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402

client = TestClient(main.app)

PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"


def auth_header():
    resp = client.post("/token", data={"username": "tester", "password": "test-password"})
    assert resp.status_code == 200
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def upload(name, content, headers=None):
    return client.post("/analyze", files={"file": (name, content)}, headers=headers or auth_header())


def test_ping():
    assert client.get("/ping").json() == {"message": "pong"}


def test_wrong_password_is_rejected():
    resp = client.post("/token", data={"username": "tester", "password": "nope"})
    assert resp.status_code == 401


def test_analyze_requires_login():
    resp = client.post("/analyze", files={"file": ("a.pdf", PDF)})
    assert resp.status_code == 401


def test_clean_pdf_is_analyzed():
    resp = upload("report.pdf", PDF)
    assert resp.status_code == 200
    body = resp.json()
    assert body["file_type"] == "pdf"
    assert body["risk"]["band"] == "Low"
    assert len(body["hashes"]["sha256"]) == 64


def test_disguised_file_is_rejected():
    resp = upload("invoice.exe", PDF)
    assert resp.status_code == 400
    assert "does not look like" in resp.json()["detail"]


def test_unsupported_extension_is_rejected():
    assert upload("notes.txt", b"hello").status_code == 400


def test_oversized_file_is_rejected():
    with patch.object(main, "MAX_FILE_SIZE", 10):
        assert upload("big.pdf", PDF).status_code == 413


def test_malformed_exe_is_scored_not_crashed():
    resp = upload("broken.exe", b"MZ" + b"\x90" * 100)
    assert resp.status_code == 200
    assert resp.json()["risk"]["score"] >= 20
