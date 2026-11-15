"""Word document triage (.docx and legacy .doc) without executing or rendering anything.

XML is read with regular expressions on purpose: untrusted XML parsers can be
abused (entity expansion), and we only need a few attributes.
"""
import io
import logging
import re
import zipfile

logger = logging.getLogger(__name__)

MAX_ENTRIES = 5000
MAX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_RELS_BYTES = 1024 * 1024

_REL_TAG = re.compile(rb"<Relationship\b[^>]*>")
_TARGET = re.compile(rb'Target="([^"]*)"')
_TYPE = re.compile(rb'Type="([^"]*)"')


def _external_relationships(zf: zipfile.ZipFile) -> list:
    """External links other than ordinary hyperlinks (e.g. remote template injection)."""
    found = []
    for name in zf.namelist():
        if not name.endswith(".rels"):
            continue
        try:
            content = zf.read(name)[:MAX_RELS_BYTES]
        except Exception:
            continue
        for tag in _REL_TAG.findall(content):
            if b'TargetMode="External"' not in tag:
                continue
            rel_type = _TYPE.search(tag)
            kind = rel_type.group(1).decode(errors="ignore").rsplit("/", 1)[-1] if rel_type else "unknown"
            if kind == "hyperlink":
                continue
            target = _TARGET.search(tag)
            found.append({
                "type": kind,
                "target": (target.group(1).decode(errors="ignore") if target else "")[:200],
            })
    return found


def analyze_docx(data: bytes) -> dict:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return {"format": "docx", "error": "The file is not a valid DOCX archive."}

    with zf:
        infos = zf.infolist()
        total = sum(i.file_size for i in infos)
        ratio = total / max(len(data), 1)
        if len(infos) > MAX_ENTRIES or total > MAX_UNCOMPRESSED_BYTES or ratio > MAX_COMPRESSION_RATIO:
            return {
                "format": "docx",
                "suspicious_archive": True,
                "archive_note": (
                    f"{len(infos)} entries, {total // 1024} KB uncompressed "
                    f"(ratio {ratio:.0f}:1). Contents were not opened."
                ),
            }

        names = zf.namelist()
        info = {
            "format": "docx",
            "suspicious_archive": False,
            "has_macros": any(n.lower().endswith("vbaproject.bin") for n in names),
            "embedded_objects": [
                n for n in names if n.startswith(("word/embeddings/", "word/activeX/"))
            ][:20],
            "external_relationships": _external_relationships(zf),
        }

    try:
        import docx  # python-docx

        document = docx.Document(io.BytesIO(data))
        text = "\n".join(p.text for p in document.paragraphs)
        info["word_count"] = len(text.split())
        info["text_sample"] = text[:200]
    except Exception as exc:
        logger.info("python-docx could not read the document: %s", exc)
        info["text_note"] = "Text could not be extracted."
    return info


def analyze_doc(data: bytes) -> dict:
    """Legacy binary Word files: heuristic byte scan. Use oletools for deep macro analysis."""
    def has(text: str) -> bool:
        return text.encode("utf-16le") in data or text.encode("ascii") in data

    autoexec = [m for m in ("AutoOpen", "AutoExec", "AutoClose", "Document_Open") if has(m)]
    return {
        "format": "doc",
        "has_macros": "_VBA_PROJECT".encode("utf-16le") in data,
        "autoexec_indicators": autoexec,
        "embedded_objects": ["Ole10Native"] if "Ole10Native".encode("utf-16le") in data else [],
        "note": "Legacy .doc files get a heuristic byte scan. Use oletools for full macro analysis.",
    }


def analyze_office(data: bytes, detected_type: str) -> dict:
    return analyze_docx(data) if detected_type == "docx" else analyze_doc(data)
