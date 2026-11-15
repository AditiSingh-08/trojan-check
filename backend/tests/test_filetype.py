import io
import zipfile

from filetype import detect_file_type, extension_matches


def make_zip(names):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            zf.writestr(name, "<x/>")
    return buf.getvalue()


def test_detects_exe_by_mz_header():
    assert detect_file_type(b"MZ" + b"\x00" * 100) == "exe"


def test_detects_pdf_header():
    assert detect_file_type(b"%PDF-1.7\n...") == "pdf"


def test_detects_docx_zip():
    assert detect_file_type(make_zip(["word/document.xml", "[Content_Types].xml"])) == "docx"


def test_plain_zip_is_not_docx():
    assert detect_file_type(make_zip(["readme.txt"])) is None


def test_detects_legacy_doc():
    assert detect_file_type(bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 50) == "doc"


def test_unknown_content_returns_none():
    assert detect_file_type(b"just some text") is None


def test_extension_must_match_content():
    assert extension_matches(".exe", "exe")
    assert not extension_matches(".exe", "pdf")
    assert not extension_matches(".pdf", None)


def test_doc_extension_accepts_ooxml_content():
    assert extension_matches(".doc", "docx")
    assert extension_matches(".doc", "doc")
