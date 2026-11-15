"""Detect the real file type from the first bytes, not from the filename."""
import io
import zipfile
from typing import Optional

OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")  # legacy Office (.doc, .xls, ...)

# Which detected types are acceptable for each allowed extension.
_EXTENSION_TO_TYPES = {
    ".exe": {"exe"},
    ".pdf": {"pdf"},
    ".docx": {"docx"},
    ".doc": {"doc", "docx"},  # some ".doc" files are really OOXML
}

ALLOWED_EXTENSIONS = set(_EXTENSION_TO_TYPES)


def detect_file_type(data: bytes) -> Optional[str]:
    """Return 'exe', 'pdf', 'docx', 'doc' or None if unrecognised."""
    if data[:2] == b"MZ":
        return "exe"
    if b"%PDF-" in data[:1024]:
        return "pdf"
    if data[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                if "word/document.xml" in zf.namelist():
                    return "docx"
        except zipfile.BadZipFile:
            return None
        return None
    if data[:8] == OLE_MAGIC:
        return "doc"
    return None


def extension_matches(extension: str, detected: Optional[str]) -> bool:
    return detected in _EXTENSION_TO_TYPES.get(extension.lower(), set())
