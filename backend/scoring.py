"""Turn analyzer output into a 0-100 score, a risk band and explained findings.

Every point added to the score comes with a finding that says why, so the
number is never a black box. This is a heuristic triage score, not a verdict.
"""
from pe_constants import PACKER_SECTIONS, STANDARD_SECTIONS

YARA_POINTS = {"high": 30, "medium": 15, "low": 5}

# category -> (distinct API hits needed, points, explanation)
API_RULES = {
    "process_injection": (2, 25, "Imports several APIs used to inject code into other processes"),
    "keylogging": (2, 15, "Imports APIs commonly used to capture keystrokes"),
    "anti_debugging": (3, 10, "Imports several APIs used to detect debuggers"),
    "downloader": (1, 10, "Imports APIs that download files from the internet"),
}

LOW_MAX = 19
MEDIUM_MAX = 49


def band_for(score: int) -> str:
    if score <= LOW_MAX:
        return "Low"
    if score <= MEDIUM_MAX:
        return "Medium"
    return "High"


def _finding(title: str, detail: str, points: int) -> dict:
    if points >= 25:
        severity = "high"
    elif points >= 10:
        severity = "medium"
    elif points > 0:
        severity = "low"
    else:
        severity = "info"
    return {"severity": severity, "title": title, "detail": detail, "points": points}


def build_risk(findings: list) -> dict:
    score = min(100, sum(f["points"] for f in findings))
    findings = sorted(findings, key=lambda f: f["points"], reverse=True)
    if not any(f["points"] > 0 for f in findings):
        findings.append(_finding(
            "No suspicious indicators found",
            "None of the checks flagged this file. That does not prove it is safe.",
            0,
        ))
    return {"score": score, "band": band_for(score), "findings": findings}


def _virustotal_findings(vt) -> list:
    if not vt:
        return []
    status = vt.get("status")
    if status == "found":
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        if malicious >= 5:
            return [_finding(f"{malicious} antivirus engines on VirusTotal flag this file as malicious",
                             "Strong signal: many independent engines agree.", 60)]
        if malicious >= 1:
            return [_finding(f"{malicious} antivirus engine(s) on VirusTotal flag this file",
                             "A few detections can be false positives; check which engines flagged it.", 25)]
        return [_finding("No VirusTotal engine flagged this file",
                         f"{suspicious} engine(s) marked it suspicious." if suspicious else
                         "The hash is known and no engine reported it as malicious.", 0)]
    if status == "not_found":
        return [_finding("Hash is unknown to VirusTotal",
                         "New or rare files are often unknown. This is not evidence either way.", 0)]
    return [_finding("VirusTotal lookup unavailable", vt.get("reason", "Unknown error."), 0)]


def score_exe(pe: dict, yara_result: dict, vt=None) -> dict:
    findings = []

    if "error" in pe:
        findings.append(_finding(
            "File could not be parsed as a valid PE executable",
            pe["error"] + " Corrupt or deliberately malformed headers are sometimes used to evade tools.",
            20,
        ))
    else:
        sections = pe.get("sections", [])

        packers = [s["name"] for s in sections if s["name"].lower() in PACKER_SECTIONS]
        if packers:
            findings.append(_finding(
                "Section names match a known packer",
                f"Found: {', '.join(packers)}. Packers hide the real code; they are used by both software vendors and malware.",
                25,
            ))

        hot = [s for s in sections if s["executable"] and s["entropy"] >= 7.0]
        if hot:
            listing = ", ".join(f"{s['name']} ({s['entropy']})" for s in hot)
            findings.append(_finding(
                "Executable section has very high entropy",
                f"{listing}. Entropy near 8 suggests packed or encrypted code (normal code is about 5-6.5).",
                20,
            ))

        writable_exec = [s["name"] for s in sections if s["executable"] and s["writable"]]
        if writable_exec:
            findings.append(_finding(
                "Section is both writable and executable",
                f"{', '.join(writable_exec)}. Self-modifying or unpacking code often needs this.",
                15,
            ))

        unusual = [s["name"] for s in sections
                   if s["name"].lower() not in STANDARD_SECTIONS | PACKER_SECTIONS]
        if unusual:
            findings.append(_finding(
                f"{len(unusual)} unusual section name(s)",
                f"Found: {', '.join(unusual)}. Some compilers use custom names, so this is a weak signal.",
                min(5 * len(unusual), 15),
            ))

        for category, hits in pe.get("suspicious_imports", {}).items():
            needed, points, label = API_RULES[category]
            if len(hits) >= needed:
                findings.append(_finding(label, f"Imported: {', '.join(hits)}.", points))

        if not pe.get("is_dll") and pe.get("import_function_count", 0) < 5:
            findings.append(_finding(
                "Almost no imported functions",
                "Packed programs often hide their imports and rebuild them while running.",
                15,
            ))

        if pe.get("timestamp_note") == "in the future":
            findings.append(_finding(
                "Compile timestamp is in the future",
                "The header timestamp was probably forged.",
                5,
            ))

    if yara_result.get("available"):
        for match in yara_result["matches"]:
            findings.append(_finding(
                f"YARA rule matched: {match['rule']}",
                match["description"],
                YARA_POINTS.get(match["severity"], 5),
            ))
    else:
        findings.append(_finding("YARA scanning unavailable",
                                 "The YARA engine or rules could not be loaded on this server.", 0))

    findings += _virustotal_findings(vt)
    return build_risk(findings)


def score_pdf(info: dict, vt=None) -> dict:
    findings = []
    kw = info.get("keywords", {})
    js = kw.get("JavaScript", 0) + kw.get("JS", 0)
    auto = kw.get("OpenAction", 0) + kw.get("AA", 0)

    if js:
        findings.append(_finding("Contains JavaScript",
                                 f"{js} JavaScript marker(s). Legitimate forms use it, but it is the most common PDF attack vector.", 30))
    if auto:
        findings.append(_finding("Runs an action automatically when opened",
                                 "An OpenAction or additional-actions entry is present.", 15))
    if js and auto:
        findings.append(_finding("JavaScript is set to run automatically",
                                 "This combination is a classic pattern in malicious PDFs.", 10))
    if kw.get("Launch"):
        findings.append(_finding("Can launch external programs",
                                 "A /Launch action can ask the viewer to run a command or open a file.", 40))
    if kw.get("EmbeddedFile"):
        findings.append(_finding("Contains an embedded file",
                                 "Attached files can carry a second-stage payload.", 20))
    if kw.get("RichMedia"):
        findings.append(_finding("Contains rich media (Flash/3D)", "Rarely needed; historically abused.", 20))
    if kw.get("XFA"):
        findings.append(_finding("Contains XFA forms", "A complex format with a history of viewer vulnerabilities.", 10))
    if info.get("obfuscated_keywords"):
        findings.append(_finding("Keywords are hidden with name encoding",
                                 f"Hex-escaped names decoded to: {', '.join(info['obfuscated_keywords'])}. Hiding keywords is an evasion technique.", 15))
    if info.get("encrypted"):
        findings.append(_finding("PDF is encrypted", "Encrypted content cannot be inspected by this scan.", 5))
    if info.get("parse_error"):
        findings.append(_finding("PDF structure could not be parsed", info["parse_error"], 10))

    findings += _virustotal_findings(vt)
    return build_risk(findings)


def score_office(info: dict, vt=None) -> dict:
    findings = []

    if info.get("error"):
        findings.append(_finding("File could not be read as a valid Word document", info["error"], 20))
    if info.get("suspicious_archive"):
        findings.append(_finding("Archive looks like a decompression bomb or is abnormally large",
                                 info.get("archive_note", ""), 20))
    if info.get("has_macros"):
        points = 35 if info.get("format") == "docx" else 30
        findings.append(_finding("Contains VBA macros",
                                 "Macros can run code when the document is opened. A .docx should not contain any." if info.get("format") == "docx"
                                 else "Macros can run code when the document is opened.", points))
    if info.get("autoexec_indicators"):
        findings.append(_finding("Macro names that run on open",
                                 f"Found: {', '.join(info['autoexec_indicators'])}.", 25))
    external = info.get("external_relationships", [])
    if external:
        shown = "; ".join(f"{r['type']} -> {r['target']}" for r in external[:3])
        findings.append(_finding("Loads content from an external location",
                                 f"{shown}. Remote templates are used to pull in malicious content after delivery.", 25))
    if info.get("embedded_objects"):
        findings.append(_finding("Contains embedded objects",
                                 "Embedded OLE or ActiveX objects can hide executables.", 15))

    findings += _virustotal_findings(vt)
    return build_risk(findings)
