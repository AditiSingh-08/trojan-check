"""Static analysis of Windows PE files (EXE/DLL) using pefile."""
import datetime
import logging

import pefile
from pefile import PEFormatError

from entropy import shannon_entropy
from pe_constants import (
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_WRITE,
    SUSPICIOUS_APIS,
)

logger = logging.getLogger(__name__)

def _clean_name(raw: bytes) -> str:
    return raw.rstrip(b"\x00").decode("utf-8", errors="ignore").strip()


def analyze_pe(data: bytes) -> dict:
    """Parse `data` as a PE file. Returns a dict, or {"error": "..."} on failure."""
    try:
        pe = pefile.PE(data=data)
    except PEFormatError as exc:
        logger.info("PEFormatError: %s", exc)
        return {"error": "Not a valid or complete PE file."}
    except Exception:
        logger.exception("Unexpected error while parsing PE file")
        return {"error": "Could not parse this file as a PE executable."}

    try:
        sections = []
        for s in pe.sections:
            raw = s.get_data()
            sections.append({
                "name": _clean_name(s.Name),
                "entropy": round(shannon_entropy(raw), 2),
                "raw_size": s.SizeOfRawData,
                "virtual_size": s.Misc_VirtualSize,
                "executable": bool(s.Characteristics & IMAGE_SCN_MEM_EXECUTE),
                "writable": bool(s.Characteristics & IMAGE_SCN_MEM_WRITE),
            })

        dlls, function_names = [], set()
        function_count = 0
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dlls.append(entry.dll.decode("utf-8", errors="ignore"))
            for imp in entry.imports:
                function_count += 1
                if imp.name:
                    function_names.add(imp.name.decode("utf-8", errors="ignore"))

        suspicious = {
            category: sorted(function_names & apis)
            for category, apis in SUSPICIOUS_APIS.items()
            if function_names & apis
        }

        timestamp = pe.FILE_HEADER.TimeDateStamp
        compile_time, timestamp_note = None, None
        if timestamp == 0:
            timestamp_note = "unset"
        else:
            compile_time = datetime.datetime.fromtimestamp(
                timestamp, datetime.timezone.utc
            ).isoformat()
            if timestamp > datetime.datetime.now(datetime.timezone.utc).timestamp() + 86400:
                timestamp_note = "in the future"

        return {
            "is_dll": pe.is_dll(),
            "compile_time": compile_time,
            "timestamp_note": timestamp_note,
            "sections": sections,
            "imports": dlls,
            "import_function_count": function_count,
            "suspicious_imports": suspicious,
        }
    except Exception:
        logger.exception("Error while reading PE structure")
        return {"error": "The PE file is malformed and could not be fully read."}
    finally:
        pe.close()
