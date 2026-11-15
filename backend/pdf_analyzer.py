"""PDF triage: look for risky features (JavaScript, auto-run actions, embedded files)."""
import io
import logging
import re

logger = logging.getLogger(__name__)

RISKY_KEYWORDS = [
    "JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile",
    "RichMedia", "XFA", "URI", "SubmitForm", "GoToR", "Encrypt",
]

# A PDF name ends at whitespace or a delimiter, so "/JS" must not match "/JSON".
_PATTERN = re.compile(
    rb"/(" + b"|".join(k.encode() for k in RISKY_KEYWORDS) + rb")(?=[\s/<>\[\]()%{}]|$)"
)
_HEX_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")


def _count(data: bytes) -> dict:
    counts = {}
    for match in _PATTERN.finditer(data):
        key = match.group(1).decode()
        counts[key] = counts.get(key, 0) + 1
    return counts


def _decode_hex_names(data: bytes) -> bytes:
    """PDF allows /J#61vaScript to mean /JavaScript. Malware uses this to hide keywords."""
    return _HEX_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), data)


def _read_with_pypdf(data: bytes) -> dict:
    try:
        import PyPDF2
    except ImportError:
        return {"parse_note": "PyPDF2 is not installed; page and text details skipped."}
    try:
        reader = PyPDF2.PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            return {"page_count": None, "metadata": {}, "text_sample": ""}
        metadata = {str(k): str(v) for k, v in (reader.metadata or {}).items()}
        text = ""
        if len(reader.pages) > 0:
            text = (reader.pages[0].extract_text() or "")[:200]
        return {"page_count": len(reader.pages), "metadata": metadata, "text_sample": text}
    except Exception as exc:
        logger.info("PyPDF2 could not read the PDF: %s", exc)
        return {"parse_error": "The PDF structure could not be fully parsed (it may be damaged or deliberately malformed)."}


def analyze_pdf(data: bytes) -> dict:
    raw_counts = _count(data)
    decoded_counts = _count(_decode_hex_names(data))
    obfuscated = sorted(k for k, n in decoded_counts.items() if n > raw_counts.get(k, 0))

    info = {
        "keywords": decoded_counts,
        "obfuscated_keywords": obfuscated,
        "encrypted": "Encrypt" in decoded_counts,
        "scan_note": "Keywords inside compressed object streams are not visible to this scan.",
    }
    info.update(_read_with_pypdf(data))
    return info
