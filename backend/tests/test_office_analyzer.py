import io
import zipfile

from office_analyzer import analyze_doc, analyze_docx


def make_docx(files, compression=zipfile.ZIP_STORED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        zf.writestr("word/document.xml", "<w:document/>")
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_clean_docx_has_no_findings():
    info = analyze_docx(make_docx({}))
    assert info["has_macros"] is False
    assert info["external_relationships"] == []
    assert info["embedded_objects"] == []


def test_detects_vba_project_inside_docx():
    info = analyze_docx(make_docx({"word/vbaProject.bin": b"\x00\x01"}))
    assert info["has_macros"] is True


def test_detects_remote_template_but_ignores_hyperlinks():
    rels = (
        '<Relationships>'
        '<Relationship Id="1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
        'Target="http://evil.example/t.dotm" TargetMode="External"/>'
        '<Relationship Id="2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
        'Target="https://example.com" TargetMode="External"/>'
        '</Relationships>'
    )
    info = analyze_docx(make_docx({"word/_rels/document.xml.rels": rels}))
    assert info["external_relationships"] == [
        {"type": "attachedTemplate", "target": "http://evil.example/t.dotm"}
    ]


def test_detects_embedded_objects():
    info = analyze_docx(make_docx({"word/embeddings/oleObject1.bin": b"x"}))
    assert info["embedded_objects"] == ["word/embeddings/oleObject1.bin"]


def test_highly_compressed_archive_is_not_opened():
    bomb = make_docx({"word/bigfile.bin": b"\x00" * (10 * 1024 * 1024)}, zipfile.ZIP_DEFLATED)
    info = analyze_docx(bomb)
    assert info["suspicious_archive"] is True
    assert "has_macros" not in info


def test_invalid_zip_returns_error():
    assert "error" in analyze_docx(b"PK\x03\x04 not really a zip")


def test_legacy_doc_macro_marker():
    data = bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 20 + "_VBA_PROJECT".encode("utf-16le")
    assert analyze_doc(data)["has_macros"] is True


def test_legacy_doc_without_macros():
    data = bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 200
    info = analyze_doc(data)
    assert info["has_macros"] is False
    assert info["autoexec_indicators"] == []
