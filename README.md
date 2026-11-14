# Trojan Check

A web app for static analysis of uploaded files. Users sign in, upload a file, and receive an analysis report that can be exported as a PDF.

Built for KrackHack 2.0 as a student project. This is a prototype, not a production antivirus.

## What it does

- Accepts `.exe`, `.pdf`, `.doc` and `.docx` uploads (10 MB limit, file-type allowlist).
- **EXE files:** matches a YARA rule, parses the PE structure with `pefile` (section names, imported DLLs) and returns a heuristic risk score from 0 to 100.
- **PDF files:** extracts page count, metadata and a text sample (PyPDF2).
- **DOCX files:** extracts word count and a text sample (python-docx). Legacy `.doc` files may fail to parse.
- Protects the API with JWT login (OAuth2 password flow).
- Exports the result as a PDF report from the React frontend.

## How the EXE risk score works

| Signal | Score |
|---|---|
| YARA rule match (`MZ` header at offset 0) | +50 |
| Each section not in `.text/.data/.rdata/.rsrc/.reloc` | +10 |
| More than 10 imported DLLs | +20 |
| PE file cannot be parsed | fixed 30 |

The score is capped at 100. The YARA rule only checks for a Windows executable header, so every valid `.exe` receives the +50. The score is a rough heuristic, not a malware verdict.

## Tech stack

- **Frontend:** React, Material UI, axios, jsPDF
- **Backend:** Python, FastAPI, Uvicorn, yara-python, pefile, PyPDF2, python-docx, python-jose, passlib (bcrypt)

## Run it locally

Backend:

```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows (use: source venv/bin/activate on macOS/Linux)
pip install -r requirements.txt
uvicorn main:app --reload    # runs on http://127.0.0.1:8000
```

Frontend:

```bash
cd frontend
npm install
npm start                    # runs on http://localhost:3000
```

Demo login (hard-coded in `backend/auth.py` for development): username `johndoe`, password `secret`.

## Known limitations

- Single hard-coded demo user and a JWT secret key stored in source code. Move both to environment variables and a real database before any real use.
- CORS allows all origins (development setting).
- Detection is limited to one YARA rule and PE heuristics; PDF and DOCX files are only parsed for text and metadata.

## Planned (not implemented yet)

- More YARA rules and signature sources
- Entropy analysis for packed or encrypted files
- VirusTotal lookup
- Persistent user database and a registration flow

## Project structure

```
backend/    FastAPI app (main.py, auth.py, auth_routes.py)
frontend/   React app (login, upload, report export)
```
