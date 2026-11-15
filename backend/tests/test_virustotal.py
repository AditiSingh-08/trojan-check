from unittest.mock import MagicMock, patch

import requests

import virustotal

HASH = "a" * 64


def fake_response(status, payload=None):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload or {}
    return resp


def test_returns_none_without_api_key():
    with patch.object(virustotal.config, "VT_API_KEY", None):
        assert virustotal.lookup_hash(HASH) is None


def test_found_returns_detection_counts_and_link():
    payload = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 7, "suspicious": 1, "harmless": 0, "undetected": 50}}}}
    with patch("virustotal.requests.get", return_value=fake_response(200, payload)) as get:
        result = virustotal.lookup_hash(HASH, api_key="key")
    assert result["status"] == "found"
    assert result["malicious"] == 7
    assert HASH in result["link"]
    assert get.call_args.kwargs["headers"] == {"x-apikey": "key"}


def test_404_means_hash_not_found():
    with patch("virustotal.requests.get", return_value=fake_response(404)):
        assert virustotal.lookup_hash(HASH, api_key="key") == {"status": "not_found"}


def test_rate_limit_is_reported():
    with patch("virustotal.requests.get", return_value=fake_response(429)):
        assert virustotal.lookup_hash(HASH, api_key="key")["status"] == "unavailable"


def test_network_failure_does_not_raise():
    with patch("virustotal.requests.get", side_effect=requests.ConnectionError("boom")):
        result = virustotal.lookup_hash(HASH, api_key="key")
    assert result["status"] == "unavailable"
