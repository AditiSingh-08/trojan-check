import scoring


def clean_pe(**overrides):
    pe = {
        "is_dll": False,
        "compile_time": "2020-01-01T00:00:00+00:00",
        "timestamp_note": None,
        "sections": [
            {"name": ".text", "entropy": 6.1, "raw_size": 4096, "virtual_size": 4000, "executable": True, "writable": False},
            {"name": ".data", "entropy": 3.0, "raw_size": 512, "virtual_size": 500, "executable": False, "writable": True},
        ],
        "imports": ["KERNEL32.dll"],
        "import_function_count": 40,
        "suspicious_imports": {},
    }
    pe.update(overrides)
    return pe


NO_YARA = {"available": True, "matches": []}


def titles(risk):
    return [f["title"] for f in risk["findings"]]


def test_band_thresholds():
    assert scoring.band_for(0) == "Low"
    assert scoring.band_for(19) == "Low"
    assert scoring.band_for(20) == "Medium"
    assert scoring.band_for(49) == "Medium"
    assert scoring.band_for(50) == "High"


def test_clean_exe_scores_zero_and_explains_itself():
    risk = scoring.score_exe(clean_pe(), NO_YARA)
    assert risk["score"] == 0
    assert risk["band"] == "Low"
    assert "No suspicious indicators found" in titles(risk)


def test_packer_section_and_high_entropy_is_medium():
    pe = clean_pe(sections=[
        {"name": "UPX0", "entropy": 7.8, "raw_size": 0, "virtual_size": 9000, "executable": True, "writable": True},
    ])
    risk = scoring.score_exe(pe, NO_YARA)
    # packer 25 + entropy 20 + writable/executable 15
    assert risk["score"] == 60
    assert risk["band"] == "High"


def test_one_injection_api_is_not_enough():
    pe = clean_pe(suspicious_imports={"process_injection": ["WriteProcessMemory"]})
    assert scoring.score_exe(pe, NO_YARA)["score"] == 0


def test_two_injection_apis_add_points():
    pe = clean_pe(suspicious_imports={"process_injection": ["VirtualAllocEx", "WriteProcessMemory"]})
    assert scoring.score_exe(pe, NO_YARA)["score"] == 25


def test_debugger_check_alone_is_ignored_but_three_count():
    one = clean_pe(suspicious_imports={"anti_debugging": ["IsDebuggerPresent"]})
    three = clean_pe(suspicious_imports={"anti_debugging": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"]})
    assert scoring.score_exe(one, NO_YARA)["score"] == 0
    assert scoring.score_exe(three, NO_YARA)["score"] == 10


def test_almost_no_imports_is_flagged_for_exe_but_not_dll():
    assert scoring.score_exe(clean_pe(import_function_count=1), NO_YARA)["score"] == 15
    assert scoring.score_exe(clean_pe(import_function_count=1, is_dll=True), NO_YARA)["score"] == 0


def test_unparseable_pe_adds_points():
    risk = scoring.score_exe({"error": "Not a valid or complete PE file."}, NO_YARA)
    assert risk["score"] == 20


def test_yara_matches_use_severity_points():
    yara_result = {"available": True, "matches": [
        {"rule": "A", "description": "d", "severity": "high"},
        {"rule": "B", "description": "d", "severity": "low"},
    ]}
    assert scoring.score_exe(clean_pe(), yara_result)["score"] == 35


def test_score_is_capped_at_100():
    yara_result = {"available": True, "matches": [{"rule": str(i), "description": "", "severity": "high"} for i in range(5)]}
    assert scoring.score_exe(clean_pe(), yara_result)["score"] == 100


def test_virustotal_many_detections_dominates():
    vt = {"status": "found", "malicious": 40, "suspicious": 0, "harmless": 0, "undetected": 20}
    risk = scoring.score_exe(clean_pe(), NO_YARA, vt)
    assert risk["score"] == 60
    assert risk["band"] == "High"


def test_virustotal_unknown_hash_adds_nothing():
    assert scoring.score_exe(clean_pe(), NO_YARA, {"status": "not_found"})["score"] == 0


def test_pdf_with_auto_run_javascript_is_high():
    risk = scoring.score_pdf({"keywords": {"JavaScript": 1, "OpenAction": 1}})
    assert risk["score"] == 55
    assert risk["band"] == "High"


def test_pdf_launch_is_medium_alone_and_high_with_embedded_file():
    assert scoring.score_pdf({"keywords": {"Launch": 1}})["band"] == "Medium"  # 40 points
    assert scoring.score_pdf({"keywords": {"Launch": 1, "EmbeddedFile": 1}})["band"] == "High"


def test_clean_pdf_is_low():
    assert scoring.score_pdf({"keywords": {"URI": 3}})["score"] == 0


def test_pdf_obfuscation_is_flagged():
    risk = scoring.score_pdf({"keywords": {"JavaScript": 1}, "obfuscated_keywords": ["JavaScript"]})
    assert risk["score"] == 45


def test_docx_with_macros_is_flagged():
    assert scoring.score_office({"format": "docx", "has_macros": True})["score"] == 35


def test_external_template_is_flagged():
    info = {"format": "docx", "external_relationships": [{"type": "attachedTemplate", "target": "http://evil.example/t.dotm"}]}
    assert scoring.score_office(info)["score"] == 25


def test_every_point_has_a_matching_finding():
    pe = clean_pe(import_function_count=1)
    risk = scoring.score_exe(pe, NO_YARA)
    assert sum(f["points"] for f in risk["findings"]) == risk["score"]
