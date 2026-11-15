"""Optional VirusTotal lookup. Only the file's SHA-256 is sent, never the file."""
import logging

import requests

import config

logger = logging.getLogger(__name__)

_URL = "https://www.virustotal.com/api/v3/files/{}"
_GUI = "https://www.virustotal.com/gui/file/{}"


def lookup_hash(sha256: str, api_key=None):
    """Return None if no API key is configured, otherwise a status dict."""
    api_key = api_key or config.VT_API_KEY
    if not api_key:
        return None
    try:
        resp = requests.get(
            _URL.format(sha256),
            headers={"x-apikey": api_key},
            timeout=config.VT_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        logger.warning("VirusTotal request failed: %s", exc)
        return {"status": "unavailable", "reason": "VirusTotal could not be reached."}

    if resp.status_code == 404:
        return {"status": "not_found"}
    if resp.status_code == 429:
        return {"status": "unavailable", "reason": "VirusTotal rate limit reached."}
    if resp.status_code != 200:
        return {"status": "unavailable", "reason": f"VirusTotal returned HTTP {resp.status_code}."}

    try:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, ValueError):
        return {"status": "unavailable", "reason": "Unexpected VirusTotal response."}

    return {
        "status": "found",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "link": _GUI.format(sha256),
    }
