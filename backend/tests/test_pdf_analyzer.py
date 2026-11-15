from pdf_analyzer import analyze_pdf

CLEAN = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF"


def test_clean_pdf_has_no_risky_keywords():
    info = analyze_pdf(CLEAN)
    assert info["keywords"] == {}
    assert info["obfuscated_keywords"] == []


def test_detects_javascript_and_open_action():
    data = b"%PDF-1.4\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\n%%EOF"
    kw = analyze_pdf(data)["keywords"]
    assert kw["OpenAction"] == 1
    assert kw["JavaScript"] == 1
    assert kw["JS"] == 1


def test_js_keyword_does_not_match_longer_names():
    data = b"%PDF-1.4\n<< /JSON 1 /JSX 2 >>\n%%EOF"
    assert "JS" not in analyze_pdf(data)["keywords"]


def test_hex_escaped_name_is_decoded_and_flagged():
    data = b"%PDF-1.4\n<< /S /J#61vaScript /JS (x) >>\n%%EOF"
    info = analyze_pdf(data)
    assert info["keywords"]["JavaScript"] == 1
    assert "JavaScript" in info["obfuscated_keywords"]


def test_encrypted_flag():
    data = b"%PDF-1.4\ntrailer << /Encrypt 5 0 R >>\n%%EOF"
    assert analyze_pdf(data)["encrypted"] is True
