import logging
import os

import uvicorn
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool

import config
import scoring
import yara_scan
from auth import get_current_active_user
from auth_routes import router as auth_router
from filetype import ALLOWED_EXTENSIONS, detect_file_type, extension_matches
from hashing import compute_hashes
from office_analyzer import analyze_office
from pdf_analyzer import analyze_pdf
from pe_analyzer import analyze_pe
from virustotal import lookup_hash

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_FILE_SIZE = config.MAX_FILE_SIZE

DISCLAIMER = (
    "Static analysis only: the file was inspected but never executed. "
    "The score is a heuristic triage aid, not a malware verdict."
)

app = FastAPI(title="Trojan Check API")
app.include_router(auth_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=False,  # auth uses a bearer token header, not cookies
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


async def read_limited(file: UploadFile, limit: int) -> bytes:
    """Read the upload in chunks and stop as soon as it exceeds the limit."""
    chunks, total = [], 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise HTTPException(status_code=413, detail=f"File too large (limit {limit // (1024 * 1024)} MB).")
        chunks.append(chunk)
    return b"".join(chunks)


def run_analysis(detected: str, data: bytes, vt) -> tuple:
    """CPU-bound analysis. Runs in a worker thread so it does not block the server."""
    if detected == "exe":
        pe_info = analyze_pe(data)
        yara_result = yara_scan.scan(data)
        return scoring.score_exe(pe_info, yara_result, vt), {"pe": pe_info, "yara": yara_result}
    if detected == "pdf":
        info = analyze_pdf(data)
        return scoring.score_pdf(info, vt), {"pdf": info}
    info = analyze_office(data, detected)
    return scoring.score_office(info, vt), {"document": info}


@app.get("/ping")
def ping():
    return {"message": "pong"}


@app.post("/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    current_user=Depends(get_current_active_user),
):
    filename = os.path.basename(file.filename or "")[:255]
    ext = os.path.splitext(filename)[1].lower()
    if not filename or ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Unsupported file type. Use .exe, .pdf, .doc or .docx.")

    data = await read_limited(file, MAX_FILE_SIZE)
    if not data:
        raise HTTPException(status_code=400, detail="The file is empty.")

    detected = detect_file_type(data)
    if not extension_matches(ext, detected):
        raise HTTPException(
            status_code=400,
            detail=f"The file content does not look like a {ext} file, so it was not analyzed.",
        )

    logger.info("Analyzing %s (%s, %d bytes) for %s", filename, detected, len(data), current_user.username)

    hashes = compute_hashes(data)
    vt = await run_in_threadpool(lookup_hash, hashes["sha256"])

    try:
        risk, details = await run_in_threadpool(run_analysis, detected, data, vt)
    except Exception:
        logger.exception("Analysis failed for %s", filename)
        raise HTTPException(status_code=500, detail="Analysis failed unexpectedly. The error was logged.")

    return {
        "filename": filename,
        "file_type": detected,
        "size_bytes": len(data),
        "hashes": hashes,
        "virustotal": vt,
        "risk": risk,
        "details": details,
        "disclaimer": DISCLAIMER,
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
