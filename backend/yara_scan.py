"""Run the YARA rules in backend/rules/ against file contents."""
import logging
import os
from functools import lru_cache

try:
    import yara
except ImportError:  # keep the API usable without yara-python installed
    yara = None

logger = logging.getLogger(__name__)

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


@lru_cache(maxsize=1)
def _load_rules():
    if yara is None:
        return None
    files = {
        os.path.splitext(name)[0]: os.path.join(RULES_DIR, name)
        for name in sorted(os.listdir(RULES_DIR))
        if name.endswith((".yar", ".yara"))
    }
    if not files:
        return None
    return yara.compile(filepaths=files)


def scan(data: bytes) -> dict:
    """Return {"available": bool, "matches": [{"rule", "description", "severity"}]}."""
    try:
        rules = _load_rules()
    except Exception:
        logger.exception("Could not compile YARA rules")
        return {"available": False, "matches": []}
    if rules is None:
        return {"available": False, "matches": []}
    try:
        found = rules.match(data=data, timeout=10)
    except Exception:
        logger.exception("YARA scan failed")
        return {"available": False, "matches": []}
    return {
        "available": True,
        "matches": [
            {
                "rule": m.rule,
                "description": m.meta.get("description", ""),
                "severity": m.meta.get("severity", "low"),
            }
            for m in found
        ],
    }
