from fastapi import FastAPI, File, UploadFile, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
import uvicorn  
import yara
import pefile
from pefile import PEFormatError
import tempfile
import os
import logging

# Additional libraries for PDF and DOCX analysis
import PyPDF2
import docx

# Import authentication dependency from auth.py and routes from auth_routes.py
from auth import get_current_active_user  # Assumes auth.py exists in the backend folder
from auth_routes import router as auth_router  # Your authentication routes (including /token)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Include authentication routes
app.include_router(auth_router)

# Enable CORS for local development so the React app can communicate with this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development; restrict in production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Allowed file extensions for analysis.
ALLOWED_EXTENSIONS = {'.exe', '.pdf', '.doc', '.docx'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

def is_allowed_file(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS

# Define a simple inline YARA rule (for EXE files).
yara_rule = """
rule SuspiciousFile
{
    strings:
        $mz = "MZ" ascii
    condition:
        $mz at 0
}
"""
compiled_rule = yara.compile(source=yara_rule)

def analyze_pe(file_path: str):
    """Extracts basic PE file information using pefile."""
    try:
        pe = pefile.PE(file_path)
        sections = [section.Name.decode('utf-8', errors='ignore').strip() for section in pe.sections]
        imports = [entry.dll.decode('utf-8', errors='ignore') for entry in pe.DIRECTORY_ENTRY_IMPORT] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else []
        logger.info("PE analysis successful.")
        return {"sections": sections, "imports": imports}
    except PEFormatError:
        logger.error("PEFormatError: Not a valid or complete PE file.")
        return {"error": "Not a valid or complete PE file (PEFormatError)."}
    except Exception as e:
        logger.exception("Error in analyze_pe:")
        return {"error": str(e)}

def compute_risk(yara_hit, pe_info):
    """Computes a risk factor (0-100) based on YARA match and PE analysis."""
    risk = 0
    details = {}

    if "error" in pe_info:
        details["pefile_error"] = pe_info["error"]
        risk_factor = 30  # Default risk for unparseable PE files
        details["yara"] = "Unknown (PE parse error)"
        return risk_factor, details

    if yara_hit:
        risk += 50
        details["yara"] = "YARA rule match detected."
    else:
        details["yara"] = "No YARA rule matches."

    expected_sections = {".text", ".data", ".rdata", ".rsrc", ".reloc"}
    section_risk = sum(10 for s in pe_info.get("sections", []) if s.lower() not in expected_sections)
    risk += section_risk
    details["sections_risk"] = section_risk

    import_count = len(pe_info.get("imports", []))
    import_risk = 20 if import_count > 10 else 0
    risk += import_risk
    details["import_risk"] = import_risk

    risk_factor = min(risk, 100)
    return risk_factor, details

def analyze_pdf(file_path: str):
    """Analyzes a PDF file using PyPDF2."""
    try:
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            num_pages = len(reader.pages)
            metadata = reader.metadata
            text_sample = ""
            if num_pages > 0:
                extracted_text = reader.pages[0].extract_text()
                text_sample = extracted_text[:200] if extracted_text else ""
        logger.info("PDF analysis successful.")
        return {
            "file_type": "pdf",
            "num_pages": num_pages,
            "metadata": metadata,
            "text_sample": text_sample,
        }
    except Exception as e:
        logger.exception("Error in analyze_pdf:")
        return {"error": str(e)}

def analyze_docx(file_path: str):
    """Analyzes a DOCX file using python-docx."""
    try:
        doc = docx.Document(file_path)
        full_text = [para.text for para in doc.paragraphs]
        text = "\n".join(full_text)
        logger.info("DOCX analysis successful.")
        return {
            "file_type": "docx",
            "word_count": len(text.split()),
            "text_sample": text[:200],
        }
    except Exception as e:
        logger.exception("Error in analyze_docx:")
        return {"error": str(e)}

@app.get("/ping")
def ping():
    """A simple endpoint to test if the API is running."""
    return {"message": "pong"}

@app.post("/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_active_user)
):
    logger.info(f"Received file: {file.filename} from user: {current_user.username if current_user else 'unknown'}")
    
    if not is_allowed_file(file.filename):
        raise HTTPException(status_code=400, detail="Unsupported file type.")
    
    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large.")
    
    tmp_path = None
    try:
        # Save the uploaded file temporarily with its original extension.
        ext = os.path.splitext(file.filename)[1].lower()
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
            tmp.write(contents)
            tmp_path = tmp.name
        logger.info("Temporary file saved: %s", tmp_path)

        # Route the analysis based on file extension.
        if ext == ".exe":
            logger.info("Starting EXE analysis")
            yara_matches = compiled_rule.match(tmp_path)
            yara_hit = bool(yara_matches)
            logger.info("YARA match: %s", yara_hit)
            pe_info = analyze_pe(tmp_path)
            logger.info("PE analysis result: %s", pe_info)
            risk_factor, risk_details = compute_risk(yara_hit, pe_info)
            logger.info("Computed risk factor: %s", risk_factor)
            result = {
                "filename": file.filename,
                "file_type": "exe",
                "yara_hit": yara_hit,
                "pe_info": pe_info,
                "risk_factor": risk_factor,
                "risk_details": risk_details,
            }
        elif ext == ".pdf":
            logger.info("Starting PDF analysis")
            pdf_info = analyze_pdf(tmp_path)
            result = {
                "filename": file.filename,
                "file_type": "pdf",
                "pdf_info": pdf_info,
            }
        elif ext in {".doc", ".docx"}:
            logger.info("Starting DOCX analysis")
            doc_info = analyze_docx(tmp_path)
            result = {
                "filename": file.filename,
                "file_type": "docx",
                "doc_info": doc_info,
            }
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type.")

        logger.info("Analysis complete. Returning result.")
        return result
    except Exception as e:
        logger.exception("Error during analysis:")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
            logger.info("Temporary file deleted: %s", tmp_path)

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
